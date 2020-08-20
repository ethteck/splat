import os
from segtypes.segment import N64Segment
from pathlib import Path

class N64SegBin(N64Segment):
    def split(self, rom_bytes, base_path, options):
        out_dir = self.create_split_dir(base_path, "bin")

        with open(os.path.join(out_dir,  self.name + ".bin"), "wb") as f:
            f.write(rom_bytes[self.rom_start : self.rom_end])


    def get_ld_section(self):
        section_name = ".data_{}".format(self.name)

        lines = []
        lines.append("    /* 0x00000000 {:X}-{:X} [{:X}] */".format(self.rom_start, self.rom_end, self.rom_end - self.rom_start))
        lines.append("    {} 0x{:X} : AT(0x{:X}) ".format(section_name, self.rom_start, self.rom_start) + "{")
        lines.append("        build/bin/{}.o(.data);".format(self.name))
        lines.append("    }")
        lines.append("")
        lines.append("")
        return "\n".join(lines)


    @staticmethod
    def create_makefile_target():
        return ""