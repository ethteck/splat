from collections import OrderedDict
from typing import Dict, List, Optional, Tuple, Set, Type

from ...util import log, options
from ...util.range import Range
from ...util.symbols import Symbol

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
        self.jtbl_glabels_to_add: Set[int] = set()
        self.jumptables: Dict[int, Tuple[int, int]] = {}
        self.rodata_syms: Dict[int, List[Symbol]] = {}

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

    def check_rodata_sym_impl(self, func_addr: int, sym: Symbol, rodata_section: Range):
        if rodata_section.is_complete():
            assert rodata_section.start is not None
            assert rodata_section.end is not None

            rodata_start: int = rodata_section.start
            rodata_end: int = rodata_section.end
            if rodata_start <= sym.vram_start < rodata_end:
                if func_addr not in self.rodata_syms:
                    self.rodata_syms[func_addr] = []
                self.rodata_syms[func_addr].append(sym)

    # Prepare symbol for migration to the function
    def check_rodata_sym(self, func_addr: int, sym: Symbol):
        rodata_section = self.section_boundaries.get(".rodata")
        if rodata_section is not None:
            self.check_rodata_sym_impl(func_addr, sym, rodata_section)
        rodata_section = self.section_boundaries.get(".rdata")
        if rodata_section is not None:
            self.check_rodata_sym_impl(func_addr, sym, rodata_section)

    # Generates a placeholder segment for the auto_all_sections option
    def _generate_segment_from_all(
        self,
        rep_type: str,
        replace_class: Type[Segment],
        rom_start: Optional[int],
        rom_end: Optional[int],
        vram_start: Optional[int],
        base_name: str,
        base_seg: Segment,
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
        if rep.special_vram_segment:
            self.special_vram_segment = True
        return rep

    def _insert_auto_section(
        self,
        rep_type: str,
        base_seg: Segment,
        ret: List[Segment],
        last_inserted_indices: Dict[str, int],
        sections_start_indices: Dict[str, int],
    ) -> Segment:
        replace_class = Segment.get_class_for_type(rep_type)
        rep = self._generate_segment_from_all(
            rep_type, replace_class, None, None, None, base_seg.name, base_seg
        )

        # Get where to insert this segment
        index_to_insert = last_inserted_indices.get(rep_type, -1)

        if index_to_insert < 0:
            # We haven't inserted anything of this type yet, so just insert it at the beginning of this section
            index_to_insert = sections_start_indices.get(rep_type, -1)
        if index_to_insert < 0:
            # There aren't any subsegments of this type, so search in previous sections
            for other_section in self.section_order[
                self.section_order.index(rep_type) - 1 :: -1
            ]:
                index_to_insert = last_inserted_indices.get(other_section, -1)
                if index_to_insert >= 0:
                    break
                index_to_insert = sections_start_indices.get(other_section, -1)
                if index_to_insert >= 0:
                    break

        assert index_to_insert >= 0, base_seg.name
        index_to_insert += 1
        ret.insert(index_to_insert, rep)

        # Update all other indices
        for s, idx in sections_start_indices.items():
            if idx >= index_to_insert:
                sections_start_indices[s] += 1
        for s, idx in last_inserted_indices.items():
            if idx >= index_to_insert:
                last_inserted_indices[s] += 1

        # Update this section
        last_inserted_indices[rep_type] = index_to_insert
        return rep

    def _insert_all_auto_sections(
        self,
        ret: List[Segment],
        base_segments: OrderedDict[str, Segment],
        sections_start_indices: Dict[str, int],
    ):
        if len(options.opts.auto_all_sections) == 0:
            return

        # Track the index where we last inserted something per section type
        last_inserted_indices = {x: -1 for x in options.opts.section_order}

        for name, seg in base_segments.items():
            for sect in options.opts.auto_all_sections:
                if seg.get_linker_section_linksection() == sect:
                    # Avoid duplicating current section
                    continue

                sibling = seg.siblings.get(sect)
                if sibling is None:
                    # If there's no sibling for this section type then we generate and insert it
                    seg.siblings[sect] = self._insert_auto_section(
                        sect, seg, ret, last_inserted_indices, sections_start_indices
                    )
                else:
                    # Preserve order
                    last_inserted_indices[sect] = ret.index(sibling)

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

        self.section_boundaries = OrderedDict(
            (s_name, Range()) for s_name in options.opts.section_order
        )

        sections_start_indices: Dict[str, int] = dict()
        for section_name in options.opts.auto_all_sections:
            sections_start_indices[section_name] = -1

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
                if self.section_order.index(".text") < self.section_order.index(
                    ".rodata"
                ):
                    if segment.is_rodata():
                        assert (
                            segment.sibling.rodata_sibling is None
                        ), segment.sibling.name
                        segment.sibling.rodata_sibling = segment
                else:
                    if segment.is_text() and segment.sibling.is_rodata():
                        assert segment.rodata_sibling is None, segment.name
                        segment.rodata_sibling = segment.sibling
                        segment.sibling.sibling = segment

                if self.section_order.index(".text") < self.section_order.index(
                    ".data"
                ):
                    if segment.is_data():
                        assert (
                            segment.sibling.data_sibling is None
                        ), segment.sibling.name
                        segment.sibling.data_sibling = segment
                else:
                    if segment.is_text() and segment.sibling.is_data():
                        assert segment.data_sibling is None, segment.name
                        segment.data_sibling = segment.sibling
                        segment.sibling.sibling = segment

                if self.section_order.index(".text") < self.section_order.index(".bss"):
                    if segment.is_noload():
                        assert segment.sibling.bss_sibling is None, segment.sibling.name
                        segment.sibling.bss_sibling = segment
                else:
                    if segment.is_text() and segment.sibling.is_noload():
                        assert segment.bss_sibling is None, segment.name
                        segment.bss_sibling = segment.sibling
                        segment.sibling.sibling = segment

                segment.siblings[
                    segment.sibling.get_linker_section_linksection()
                ] = segment.sibling
                segment.sibling.siblings[
                    segment.get_linker_section_linksection()
                ] = segment

            segment.parent = self
            if segment.special_vram_segment:
                self.special_vram_segment = True

            for i, section in enumerate(self.section_order):
                if not self.section_boundaries[section].has_start() and dotless_type(
                    section
                ) == dotless_type(segment.type):
                    if i > 0:
                        prev_section = self.section_order[i - 1]
                        self.section_boundaries[prev_section].end = segment.vram_start
                    self.section_boundaries[section].start = segment.vram_start

            segment.bss_contains_common = self.bss_contains_common
            ret.append(segment)

            if segment.is_text():
                base_segments[segment.name] = segment

            if self.section_order.index(".rodata") < self.section_order.index(".text"):
                if segment.is_rodata() and segment.sibling is None:
                    base_segments[segment.name] = segment

            section_type = segment.get_linker_section_linksection()
            if sections_start_indices.get(section_type, -1) < 0:
                sections_start_indices[section_type] = i

            prev_start = start
            prev_vram = segment.vram_start
            if end is not None:
                last_rom_end = end

        self._insert_all_auto_sections(ret, base_segments, sections_start_indices)

        # TODO why is this necessary?
        rodata_section = self.section_boundaries.get(
            ".rodata"
        ) or self.section_boundaries.get(".rdata")
        if (
            rodata_section is not None
            and rodata_section.has_start()
            and not rodata_section.has_end()
        ):
            assert self.vram_end is not None
            rodata_section.end = self.vram_end

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
