from segtypes.segment import N64Segment
import os
from pathlib import Path
import re

class N64SegC(N64Segment):
    def split(self, rom_bytes, base_path):
        pass


    def get_ld_section(self):
        section_name = ".text{:X}_{}".format(self.ram_addr, self.name)

        lines = []
        lines.append("    /* 0x{:X} {:X}-{:X} [{:X}] */".format(self.ram_addr, self.rom_start, self.rom_end, self.rom_end - self.rom_start))
        lines.append("    {} 0x{:X} : AT(0x{:X}) ".format(section_name, self.ram_addr, self.rom_start) + "{")
        lines.append("        build/src/{}.o(.text);".format(self.name))
        lines.append("    }")
        lines.append("")
        lines.append("")
        return "\n".join(lines)


    @staticmethod
    def create_makefile_target():
        return ""