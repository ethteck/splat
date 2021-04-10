from typing import List, Dict, Optional
import sys
from pathlib import Path

from segtypes.n64.palette import N64SegPalette
from segtypes.n64.segment import N64Segment
from segtypes.segment import RomAddr, Segment
from util import options

class Subsegment():
    def __init__(self, parent: 'Segment', start: RomAddr, end: RomAddr, name, type, vram: int, args, c_sibling: 'Optional[Subsegment]'):
        self.rom_start: RomAddr = start
        self.rom_end: RomAddr = end


        self.size: RomAddr = "auto"
        if isinstance(self.rom_start, int) and isinstance(self.rom_end, int):
            self.size = self.rom_end - self.rom_start

        self.name = name
        
        self.vram_start = vram

        self.vram_end = vram
        if isinstance(self.size, int) and isinstance(vram, int):
            self.vram_end = vram + self.size

        self.type = type
        self.args = args
        self.parent = parent
        self.dir = parent.dir
        self.c_sibling = c_sibling

        self.subalign = parent.subalign

    def contains_vram(self, addr):
        return self.vram_start <= addr < self.vram_end

    def get_out_subdir(self) -> Path:
        if self.type.startswith("."):
            if self.c_sibling:
                return self.c_sibling.get_out_subdir()
            else:
                return options.get_src_path()
        elif self.type in ["c", ".data", ".rodata", ".bss"]:
            return options.get_src_path()
        elif self.type in ["asm", "hasm"]:
            return options.get_asm_path()
        elif self.type in ["data", "rodata"]:
            return options.get_asm_path() / "data"

        return options.get_asset_path()

    def get_ld_obj_type(self):
        if self.type in ["c", "asm", "hasm"]:
            return ".text"
        elif self.type in [".rodata", "rodata"]:
            return ".rodata"
        elif self.type in [".bss", "bss"]:
            return ".bss"

    def get_ext(self):
        if self.type.startswith("."):
            if self.c_sibling:
                return self.c_sibling.get_ext()
            else:
                return "c"
        elif self.type in ["c"]:
            return "c"
        elif self.type in ["asm", "hasm", "header"]:
            return "s"
        elif self.type in ["data", "rodata"]:
            return self.type + ".s"
        return self.type

    def get_linker_entry(self):
        from segtypes.linker_entry import LinkerEntry

        return LinkerEntry(
            self,
            [self.get_generic_out_path()],
            self.get_generic_out_path(),
            self.get_ld_obj_type()
        )

    def get_generic_out_path(self):
        return self.get_out_subdir() / self.parent.dir / f"{self.name}.{self.get_ext()}"

class DataSubsegment(Subsegment):
    def scan_inner(self, segment, rom_bytes):
        if not self.type.startswith(".") or self.type == ".rodata":
            self.file_text = segment.disassemble_data(self, rom_bytes)

    def split_inner(self, segment, rom_bytes):
        if not self.type.startswith("."):
            asm_out_dir = options.get_asm_path() / "data" / self.parent.dir
            asm_out_dir.mkdir(parents=True, exist_ok=True)

            outpath = asm_out_dir / f"{self.name}.{self.type}.s"

            if self.file_text:
                with open(outpath, "w", newline="\n") as f:
                    f.write(self.file_text)

class BssSubsegment(DataSubsegment):
    def __init__(self, parent, start, end, name, type, vram, args, c_sibling):
        super().__init__(parent, start, end, name, type, vram, args, c_sibling)
        #self.rom_start = 0
        self.rom_end = 0
        if type == "bss":
            self.size = self.args[0]
            self.vram_end = self.vram_start + self.size
        
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

        if "subsections" not in segment_yaml:
            print(f"Error: Code segment {self.name} is missing a 'subsections' field")
            sys.exit(2)

        for i, subsection_yaml in enumerate(segment_yaml["subsections"]):
            typ = Segment.parse_segment_type(subsection_yaml)

            segment_class = Segment.get_class_for_type(typ)

            start = Segment.parse_segment_start(subsection_yaml)
            end = self.rom_end if i == len(segment_yaml["subsections"]) - 1 else Segment.parse_segment_start(segment_yaml["subsections"][i + 1])
            
            if isinstance(start, int) and isinstance(prev_start, int) and start < prev_start:
                print(f"Error: Code segment {self.name} contains subsections which are out of ascending rom order (0x{prev_start:X} followed by 0x{start:X})")
                sys.exit(1)

            segment: Segment = segment_class(subsection_yaml, start, end)
            segment.c_sibling = base_segments.get(segment.name, None)
            segment.parent = self
            segment.is_overlay = self.is_overlay

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
