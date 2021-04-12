from segtypes.n64.data import N64SegData
from segtypes.n64.bss import N64SegBss
from segtypes.n64.rodata import N64SegRodata
from typing import List, Dict, Optional
import sys
from segtypes.n64.segment import N64Segment
from segtypes.segment import RomAddr, Segment
from util.symbols import Symbol

class N64SegGroup(N64Segment):
    def __init__(self, segment, rom_start, rom_end):
        super().__init__(segment, rom_start, rom_end)

        self.rodata_syms: Dict[int, List[Symbol]] = {}

        # TODO Note: These start/end vram options don't really do anything yet
        self.data_vram_start: Optional[int] = segment.get("data_vram_start")
        self.data_vram_end: Optional[int] = segment.get("data_vram_end")
        self.rodata_vram_start: Optional[int] = segment.get("rodata_vram_start")
        self.rodata_vram_end: Optional[int] = segment.get("rodata_vram_end")
        self.bss_vram_start: Optional[int] = segment.get("bss_vram_start")
        self.bss_vram_end: Optional[int] = segment.get("bss_vram_end")

        self.subsegments = self.parse_subsegments(segment)

    @property
    def needs_symbols(self) -> bool:
        for seg in self.subsegments:
            if seg.needs_symbols:
                return True
        return False

    def parse_subsegments(self, segment_yaml) -> List[Segment]:
        base_segments: Dict[str, Segment] = {}
        ret = []
        prev_start: RomAddr = -1

        if "subsegments" not in segment_yaml:
            print(f"Error: Group segment {self.name} is missing a 'subsegments' field")
            sys.exit(2)

        for i, subsection_yaml in enumerate(segment_yaml["subsegments"]):
            typ = Segment.parse_segment_type(subsection_yaml)

            segment_class = Segment.get_class_for_type(typ)

            start = Segment.parse_segment_start(subsection_yaml)
            end = self.rom_end if i == len(segment_yaml["subsegments"]) - 1 else Segment.parse_segment_start(segment_yaml["subsegments"][i + 1])
            
            if isinstance(start, int) and isinstance(prev_start, int) and start < prev_start:
                print(f"Error: Code segment {self.name} contains subsegments which are out of ascending rom order (0x{prev_start:X} followed by 0x{start:X})")
                sys.exit(1)

            segment: Segment = segment_class(subsection_yaml, start, end)
            segment.sibling = base_segments.get(segment.name, None)
            segment.parent = self
            
            if segment.rom_start != "auto":
                segment.vram_start = self.rom_to_ram(segment.rom_start)

            # TODO: assumes section order - generalize and stuff
            if self.data_vram_start == None and isinstance(segment, N64SegData):
                self.data_vram_start = segment.vram_start
            if self.rodata_vram_start == None and isinstance(segment, N64SegRodata):
                self.data_vram_end = segment.vram_start
                self.rodata_vram_start = segment.vram_start
            if self.rodata_vram_end == None and isinstance(segment, N64SegBss):
                self.rodata_vram_end = segment.vram_start
                self.bss_vram_start = segment.vram_start

            ret.append(segment)

            # todo change
            if typ in ["c", "asm", "hasm"]:
                base_segments[segment.name] = segment

            prev_start = start

        if self.rodata_vram_start != None and self.rodata_vram_end == None:
            assert self.vram_end is not None
            self.rodata_vram_end = self.vram_end

        return ret

    def get_linker_entries(self):
        return [sub.get_linker_entry() for sub in self.subsegments]

    def scan(self, rom_bytes):
        for sub in self.subsegments:
            sub.scan(rom_bytes)

    def split(self, rom_bytes):
        for sub in self.subsegments:
            sub.split(rom_bytes)
