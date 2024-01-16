import typing
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple, Set

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

    def _generate_segment_from_all(self, rep_type: str, replace_class: type[Segment], rom_start: Optional[int], rom_end: Optional[int], vram_start: Optional[int], base_name: str, base_seg: Segment) -> Segment:
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

    def _insert_auto_all_segment(self, rep_type: str, base_seg: Segment, ret: list[Segment], last_inserted_indices: Dict[str, int], sections_start_indices: Dict[str, int]) -> Segment:
        replace_class = Segment.get_class_for_type(rep_type)
        rep = self._generate_segment_from_all(rep_type, replace_class, None,None, None, base_seg.name, base_seg)

        if base_seg.name == "boot/dmadata":
            toph = 1

        if base_seg.name == "boot/util":
            toph = 1

        # Get where to insert this segment
        index_to_insert = last_inserted_indices[rep_type]

        if index_to_insert < 0:
            # We haven't inserted anything of this type yet, so just insert it at the beginning of this section
            index_to_insert = sections_start_indices[rep_type]
        if index_to_insert < 0:
            # There aren't any subsegments of this type, so search in previous sections
            for other_section in self.section_order[self.section_order.index(rep_type)-1::-1]:
                index_to_insert = last_inserted_indices[other_section]
                if index_to_insert >= 0:
                    break
                index_to_insert = sections_start_indices[other_section]
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

        last_inserted_indices[rep_type] = index_to_insert
        return rep


    def handle_alls(self, segs: List[Segment], base_segs: OrderedDict[str, Segment]) -> bool:
        print(self.name)
        print("  segs:")
        for x in segs:
            print(f"    {x.name}: {x.type}")
        print("  base segs:")
        for k, v in base_segs.items():
            print(f"    {k}")
        for i, elem in enumerate(segs):
            if elem.type.startswith("all_"):
                alls = []

                rep_type = f"{elem.type[4:]}"
                replace_class = Segment.get_class_for_type(rep_type)

                for base in base_segs.items():
                    if isinstance(elem.rom_start, int) and isinstance(
                        self.rom_start, int
                    ):
                        # Shoddy rom to ram
                        assert self.vram_start is not None, self.vram_start
                        vram_start = elem.rom_start - self.rom_start + self.vram_start
                    else:
                        vram_start = None
                    """
                    rep: Segment = replace_class(
                        rom_start=elem.rom_start,
                        rom_end=elem.rom_end,
                        type=rep_type,
                        name=base[0],
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
                    rep.sibling = base[1]
                    rep.parent = self
                    if rep.special_vram_segment:
                        self.special_vram_segment = True
                    """
                    rep = self._generate_segment_from_all(rep_type, replace_class, elem.rom_start, elem.rom_end, vram_start, base[0], base[1])
                    alls.append(rep)

                # Insert alls into segs at i
                del segs[i]
                segs[i:i] = alls
                return True
        return False

    # Find places we should automatically add "all_data" / "all_rodata" / "all_bss"
    def find_inserts(
        self, found_sections: typing.OrderedDict[str, Range]
    ) -> "OrderedDict[str, int]":
        inserts: OrderedDict[str, int] = OrderedDict()

        section_order = self.section_order.copy()
        section_order.remove(".text")

        for i, section in enumerate(section_order):
            if section not in options.opts.auto_all_sections:
                continue

            if not found_sections[section].has_start():
                search_done = False
                for j in range(i - 1, -1, -1):
                    end = found_sections[section_order[j]].end
                    if end is not None:
                        inserts[section] = end
                        search_done = True
                        break
                if not search_done:
                    inserts[section] = -1
                    pass

        return inserts

    def parse_subsegments(self, segment_yaml) -> List[Segment]:
        if "subsegments" not in segment_yaml:
            if not self.parent:
                raise Exception(
                    f"No subsegments provided in top-level code segment {self.name}"
                )
            return []
        
        print()

        base_segments: OrderedDict[str, Segment] = OrderedDict()
        ret: List[Segment] = []
        prev_start: Optional[int] = -1
        prev_vram: Optional[int] = -1
        inserts: OrderedDict[
            str, int
        ] = (
            OrderedDict()
        )  # Used to manually add "all_" types for sections not otherwise defined in the yaml

        self.section_boundaries = OrderedDict(
            (s_name, Range()) for s_name in options.opts.section_order
        )
        """
        found_sections = OrderedDict(
            (s_name, Range()) for s_name in self.section_boundaries
        )  # Stores yaml index where a section was first found
        found_sections.pop(".text")

        # Mark any manually added dot types
        cur_section = None

        for i, subsegment_yaml in enumerate(segment_yaml["subsegments"]):
            # endpos marker
            if isinstance(subsegment_yaml, list) and len(subsegment_yaml) == 1:
                continue

            typ = Segment.parse_segment_type(subsegment_yaml)
            if typ.startswith("all_"):
                typ = typ[4:]
            if not typ.startswith("."):
                typ = f".{typ}"

            if typ in found_sections:
                if cur_section is None:
                    # Starting point
                    found_sections[typ].start = i
                    cur_section = typ
                else:
                    if cur_section != typ:
                        # We're changing sections

                        if options.opts.check_consecutive_segment_types:
                            if found_sections[cur_section].has_end():
                                log.error(
                                    f"Section {cur_section} end encountered but was already ended earlier!"
                                )
                            if found_sections[typ].has_start():
                                log.error(
                                    f"Section {typ} start encounted but has already started earlier!"
                                )

                        # End the current section
                        found_sections[cur_section].end = i

                        # Start the next section
                        found_sections[typ].start = i
                        cur_section = typ

        if cur_section is not None:
            found_sections[cur_section].end = -1

        inserts = self.find_inserts(found_sections)
        inserts = OrderedDict()
        """

        auto_sections_list: OrderedDict[str, List[Segment]] = OrderedDict()
        sections_start_indices: dict[str, int] = dict()
        sections_end_indices: dict[str, int] = dict()
        for section_name in options.opts.auto_all_sections:
            auto_sections_list[section_name] = []
            sections_start_indices[section_name] = -1
            sections_end_indices[section_name] = -1

        last_rom_end = None

        for i, subsegment_yaml in enumerate(segment_yaml["subsegments"]):
            # endpos marker
            if isinstance(subsegment_yaml, list) and len(subsegment_yaml) == 1:
                continue

            typ = Segment.parse_segment_type(subsegment_yaml)
            start = Segment.parse_segment_start(subsegment_yaml)

            # Add dummy segments to be expanded later
            if typ.startswith("all_"):
                dummy_seg = Segment(
                    rom_start=start,
                    rom_end=None,
                    type=typ,
                    name="",
                    vram_start=None,
                    args=[],
                    yaml={},
                )
                dummy_seg.given_subalign = self.given_subalign
                dummy_seg.exclusive_ram_id = self.exclusive_ram_id
                dummy_seg.given_dir = self.given_dir
                dummy_seg.given_symbol_name_format = self.symbol_name_format
                dummy_seg.given_symbol_name_format_no_rom = (
                    self.symbol_name_format_no_rom
                )
                ret.append(dummy_seg)
                continue

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
                        segment.sibling.rodata_sibling = segment
                else:
                    if segment.is_text() and segment.sibling.is_rodata():
                        segment.rodata_sibling = segment.sibling
                        segment.sibling.sibling = segment

                if self.section_order.index(".text") < self.section_order.index(
                    ".data"
                ):
                    if segment.is_data():
                        segment.sibling.data_sibling = segment
                else:
                    if segment.is_text() and segment.sibling.is_data():
                        segment.data_sibling = segment.sibling
                        segment.sibling.sibling = segment

                if self.section_order.index(".text") < self.section_order.index(
                    ".bss"
                ):
                    if segment.is_noload():
                        segment.sibling.bss_sibling = segment
                else:
                    if segment.is_text() and segment.sibling.is_noload():
                        segment.bss_sibling = segment.sibling
                        segment.sibling.sibling = segment

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

            if segment.is_text():
                if sections_start_indices.get(".text", -1) < 0:
                    sections_start_indices[".text"] = i
            elif segment.is_data():
                if sections_start_indices.get(".data", -1) < 0:
                    sections_start_indices[".data"] = i
                if ".data" in auto_sections_list:
                    auto_sections_list[".data"].append(segment)
                    sections_end_indices[".data"] = i
            elif segment.is_rodata():
                if sections_start_indices.get(".rodata", -1) < 0:
                    sections_start_indices[".rodata"] = i
                if ".rodata" in auto_sections_list:
                    auto_sections_list[".rodata"].append(segment)
                    sections_end_indices[".rodata"] = i
            elif segment.is_noload():
                if sections_start_indices.get(".bss", -1) < 0:
                    sections_start_indices[".bss"] = i
                if ".bss" in auto_sections_list:
                    auto_sections_list[".bss"].append(segment)
                    sections_end_indices[".bss"] = i

            prev_start = start
            prev_vram = segment.vram_start
            if end is not None:
                last_rom_end = end

        if len(auto_sections_list) > 0:
            last_inserted_name: Optional[str] = None


            last_inserted_indices = {x: -1 for x in options.opts.auto_all_sections}

            if self.name == "boot":
                toph = 1
            

            for name, seg in base_segments.items():
                """
                for sect_type, seg_list in auto_sections_list.items():
                    found_other_seg = False
                    for other_seg in seg_list:
                        if other_seg.name == seg.name:
                            found_other_seg = True
                            break
                    if found_other_seg:
                        # Already has this section listed in the yaml, skip
                        continue

                    # There's no subsegment for this section type
                    for idx, other_seg in enumerate(ret):
                        pass
                """

                if seg.data_sibling is None:
                    if ".data" in options.opts.auto_all_sections:
                        rep_type = ".data"
                        seg.data_sibling = self._insert_auto_all_segment(rep_type, seg, ret, last_inserted_indices, sections_start_indices)
                else:
                    # Preserve order
                    last_inserted_indices[".data"] = ret.index(seg.data_sibling)

                if seg.rodata_sibling is None:
                    if ".rodata" in options.opts.auto_all_sections:
                        rep_type = ".rodata"
                        seg.rodata_sibling = self._insert_auto_all_segment(rep_type, seg, ret, last_inserted_indices, sections_start_indices)
                else:
                    # Preserve order
                    last_inserted_indices[".rodata"] = ret.index(seg.rodata_sibling)

                if seg.bss_sibling is None:
                    if ".bss" in options.opts.auto_all_sections:
                        rep_type = ".bss"
                        seg.bss_sibling = self._insert_auto_all_segment(rep_type, seg, ret, last_inserted_indices, sections_start_indices)
                else:
                    # Preserve order
                    last_inserted_indices[".bss"] = ret.index(seg.bss_sibling)

                last_inserted_name = seg.name

        """
        print(inserts)
        # Add the automatic all_ sections
        orig_len = len(ret)
        for section in reversed(inserts):
            idx = inserts[section]

            if idx == -1:
                idx = orig_len

            # bss hack TODO maybe rethink
            if (
                section == "bss"
                and self.vram_start is not None
                and self.rom_end is not None
                and self.rom_start is not None
            ):
                rom_start = self.rom_end
                vram_start = self.vram_start + self.rom_end - self.rom_start
            else:
                rom_start = None
                vram_start = None

            new_seg = Segment(
                rom_start=rom_start,
                rom_end=None,
                type="all_" + section,
                name="",
                vram_start=vram_start,
                args=[],
                yaml={},
            )
            new_seg.given_subalign = self.given_subalign
            new_seg.exclusive_ram_id = self.exclusive_ram_id
            new_seg.given_dir = self.given_dir
            new_seg.given_symbol_name_format = self.symbol_name_format
            new_seg.given_symbol_name_format_no_rom = self.symbol_name_format_no_rom
            ret.insert(idx, new_seg)
        """

        check = True
        while check:
            check = self.handle_alls(ret, base_segments)

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

        print()
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
