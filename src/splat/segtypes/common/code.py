from collections import OrderedDict
from typing import OrderedDict, List, Optional, Type

from ...util import log, options

from .group import CommonSegGroup
from ..segment import Segment, parse_segment_align


def dotless_type(type: str) -> str:
    return type[1:] if type[0] == "." else type


# code group
class CommonSegCode(CommonSegGroup):
    def __init__(
        self,
        rom_start: Optional[int],
        rom_end: Optional[int],
        type: str,
        name: str,
        vram_start: Optional[int],
        args: list,
        yaml,
    ):
        self.bss_size: int = yaml.get("bss_size", 0) if isinstance(yaml, dict) else 0

        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            args=args,
            yaml=yaml,
        )

        self.reported_file_split = False

        self.align = parse_segment_align(yaml)
        if self.align is None:
            self.align = 0x10

    @property
    def needs_symbols(self) -> bool:
        return True

    @property
    def vram_end(self) -> Optional[int]:
        if self.vram_start is not None and self.size is not None:
            return self.vram_start + self.size + self.bss_size
        else:
            return None

    # Generates a placeholder segment for the auto_all_sections option
    def _generate_segment_from_all(
        self,
        rep_type: str,
        replace_class: Type[Segment],
        base_name: str,
        base_seg: Segment,
        rom_start: Optional[int] = None,
        rom_end: Optional[int] = None,
        vram_start: Optional[int] = None,
    ) -> Segment:
        rep: Segment = replace_class(
            rom_start=rom_start,
            rom_end=rom_end,
            type=rep_type,
            name=base_name,
            vram_start=vram_start,
            args=[],
            yaml={},
        )
        rep.extract = False
        rep.given_subalign = self.given_subalign
        rep.exclusive_ram_id = self.get_exclusive_ram_id()
        rep.given_dir = self.given_dir
        rep.given_symbol_name_format = self.symbol_name_format
        rep.given_symbol_name_format_no_rom = self.symbol_name_format_no_rom
        rep.sibling = base_seg
        rep.parent = self
        rep.is_auto_all = True
        if rep.special_vram_segment:
            self.special_vram_segment = True
        rep.bss_contains_common = self.bss_contains_common
        return rep

    def _insert_all_auto_sections(
        self,
        ret: List[Segment],
        base_segments: OrderedDict[str, Segment],
    ) -> List[Segment]:
        if len(options.opts.auto_all_sections) == 0:
            return ret

        # Determine what will be the min insertion index
        last_inserted_index = len(ret)
        for sect in reversed(self.section_order):
            for i, (name, seg) in enumerate(base_segments.items()):
                if seg.get_linker_section_linksection() == sect:
                    continue
                last_inserted_index = i

        for sect in options.opts.auto_all_sections:
            for name, seg in base_segments.items():
                if seg.get_linker_section_linksection() == sect:
                    # Avoid duplicating current section
                    last_inserted_index = ret.index(seg)
                    continue

                sibling = seg.siblings.get(sect)
                if sibling is None:
                    replace_class = Segment.get_class_for_type(sect)
                    sibling = self._generate_segment_from_all(
                        sect, replace_class, seg.name, seg
                    )
                    seg.siblings[sect] = sibling
                    last_inserted_index += 1
                    ret.insert(last_inserted_index, sibling)

                last_inserted_index = ret.index(sibling)

        return ret

    def parse_subsegments(self, segment_yaml) -> List[Segment]:
        if "subsegments" not in segment_yaml:
            if not self.parent:
                raise Exception(
                    f"No subsegments provided in top-level code segment {self.name}"
                )
            return []

        base_segments: OrderedDict[str, Segment] = OrderedDict()
        ret: List[Segment] = []
        prev_start: Optional[int] = -1
        prev_vram: Optional[int] = -1

        last_rom_end = None

        for i, subsegment_yaml in enumerate(segment_yaml["subsegments"]):
            # endpos marker
            if isinstance(subsegment_yaml, list) and len(subsegment_yaml) == 1:
                continue

            typ = Segment.parse_segment_type(subsegment_yaml)
            start = Segment.parse_segment_start(subsegment_yaml)

            segment_class = Segment.get_class_for_type(typ)

            if start is None:
                # Attempt to infer the start address
                if i == 0:
                    # The start address of this segment is the start address of the group
                    start = self.rom_start
                else:
                    # The start address is the end address of the previous segment
                    start = last_rom_end

            # First, try to get the end address from the next segment's start address
            # Second, try to get the end address from the estimated size of this segment
            # Third, try to get the end address from the next segment with a start address
            end: Optional[int] = None
            if i < len(segment_yaml["subsegments"]) - 1:
                end = Segment.parse_segment_start(segment_yaml["subsegments"][i + 1])
            if start is not None and end is None:
                est_size = segment_class.estimate_size(subsegment_yaml)
                if est_size is not None:
                    end = start + est_size
            if end is None:
                end = self.get_next_seg_start(i, segment_yaml["subsegments"])

            if start is not None and prev_start is not None and start < prev_start:
                log.error(
                    f"Error: Group segment '{self.name}' contains subsegments which are out of ascending rom order (0x{prev_start:X} followed by 0x{start:X})"
                )

            vram = None
            if start is not None:
                assert isinstance(start, int)
                vram = self.get_most_parent().rom_to_ram(start)

            if segment_class.is_noload():
                # Pretend bss's rom address is after the last actual rom segment
                start = last_rom_end
                # and it has a rom size of zero
                end = last_rom_end

            segment: Segment = Segment.from_yaml(
                segment_class, subsegment_yaml, start, end, vram
            )

            if (
                segment.vram_start is not None
                and prev_vram is not None
                and segment.vram_start < prev_vram
            ):
                log.error(
                    f"Error: Group segment '{self.name}' contains subsegments which are out of ascending vram order (0x{prev_vram:X} followed by 0x{segment.vram_start:X}).\n"
                    + f"Detected when processing file '{segment.name}' of type '{segment.type}'"
                )

            segment.sibling = base_segments.get(segment.name, None)

            if segment.sibling is not None:
                # Make siblings reference between them
                segment.siblings[segment.sibling.get_linker_section_linksection()] = (
                    segment.sibling
                )
                segment.sibling.siblings[segment.get_linker_section_linksection()] = (
                    segment
                )

            segment.parent = self
            if segment.special_vram_segment:
                self.special_vram_segment = True

            segment.bss_contains_common = self.bss_contains_common
            ret.append(segment)

            if segment.is_text():
                base_segments[segment.name] = segment

            if self.section_order.index(".rodata") < self.section_order.index(".text"):
                if segment.is_rodata() and segment.sibling is None:
                    base_segments[segment.name] = segment

            prev_start = start
            prev_vram = segment.vram_start
            if end is not None:
                last_rom_end = end

        ret = self._insert_all_auto_sections(ret, base_segments)

        return ret

    def scan(self, rom_bytes):
        # Always scan code first
        for sub in self.subsegments:
            if sub.is_text() and sub.should_scan():
                sub.scan(rom_bytes)

        # Scan everyone else
        for sub in self.subsegments:
            if not sub.is_text() and sub.should_scan():
                sub.scan(rom_bytes)
