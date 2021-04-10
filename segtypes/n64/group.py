from typing import List, Dict, Optional
import sys
from segtypes.n64.segment import N64Segment
from segtypes.segment import RomAddr, Segment

    # def get_out_subdir(self) -> Path:
    #     if self.type.startswith("."):
    #         if self.c_sibling:
    #             return self.c_sibling.get_out_subdir()
    #         else:
    #             return options.get_src_path()
    #     elif self.type in ["c"]:
    #         return options.get_src_path()
    #     elif self.type in ["asm", "hasm"]:
    #         return options.get_asm_path()
    #     elif self.type in ["rodata"]:
    #         return options.get_asm_path() / "data"

    #     return options.get_asset_path()

    # def get_ld_obj_type(self):
    #     if self.type in ["c", "asm", "hasm"]:
    #         return ".text"
    #     elif self.type in [".rodata", "rodata"]:
    #         return ".rodata"

    # def get_ext(self):
    #     if self.type.startswith("."):
    #         if self.c_sibling:
    #             return self.c_sibling.get_ext()
    #         else:
    #             return "c"
    #     elif self.type in ["c"]:
    #         return "c"
    #     elif self.type in ["asm", "hasm"]:
    #         return "s"
    #     elif self.type in ["rodata"]:
    #         return self.type + ".s"
    #     return self.type
        
class N64SegGroup(N64Segment):
    def __init__(self, segment, rom_start, rom_end):
        super().__init__(segment, rom_start, rom_end)
        self.subsegments = self.parse_subsegments(segment)

        # TODO Note: These start/end vram options don't really do anything yet
        self.data_vram_start: Optional[int] = segment.get("data_vram_start")
        self.data_vram_end: Optional[int] = segment.get("data_vram_end")
        self.rodata_vram_start: Optional[int] = segment.get("rodata_vram_start")
        self.rodata_vram_end: Optional[int] = segment.get("rodata_vram_end")
        self.bss_vram_start: Optional[int] = segment.get("bss_vram_start")
        self.bss_vram_end: Optional[int] = segment.get("bss_vram_end")

    def parse_subsegments(self, segment_yaml) -> List[Segment]:
        base_segments: Dict[str, Segment] = {}
        ret = []
        prev_start: RomAddr = -1

        if "subsegments" not in segment_yaml:
            print(f"Error: Code segment {self.name} is missing a 'subsegments' field")
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
            segment.c_sibling = base_segments.get(segment.name, None)
            segment.parent = self

            if self.rodata_vram_start == -1 and "rodata" in typ:
                self.rodata_vram_start = segment.vram_start
            if self.rodata_vram_end == -1 and "bss" in typ:
                self.rodata_vram_end = segment.vram_start

            ret.append(segment)

            if typ in ["c", "asm", "hasm"]:
                base_segments[segment.name] = segment

            prev_start = start

        if self.rodata_vram_start != -1 and self.rodata_vram_end == -1:
            assert self.vram_end is not None
            self.rodata_vram_end = self.vram_end

        return ret

    def get_linker_entries(self):
        return [sub.get_linker_entry() for sub in self.subsegments]

    def get_subsection_for_ram(self, addr):
        for sub in self.subsegments:
            if sub.contains_vram(addr):
                return sub
        return None

    def split(self, rom_bytes):
        for sub in self.subsegments:
            sub.scan(self, rom_bytes)

        for sub in self.subsegments:
            sub.split(self, rom_bytes)
