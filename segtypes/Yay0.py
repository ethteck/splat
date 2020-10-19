import os
from segtypes.segment import N64Segment
from pathlib import Path
from util import Yay0decompress

class N64SegYay0(N64Segment):
    def split(self, rom_bytes, base_path):
        if self.type in self.options["modes"] or "all" in self.options["modes"]:
            out_dir = self.create_parent_dir(base_path, self.name)

            path = os.path.join(out_dir, os.path.basename(self.name) + ".bin")
            with open(path, "wb") as f:
                print(f"Decompressing {self.name}...")
                compressed_bytes = rom_bytes[self.rom_start : self.rom_end]
                decompressed_bytes = Yay0decompress.decompress_yay0(compressed_bytes)
                f.write(decompressed_bytes)
            print(f"Wrote {self.name} to {path}")


    def get_ld_section(self):
        section_name = ".data_{}".format(self.rom_start)

        lines = []
        lines.append("    /* 0x00000000 {:X}-{:X} [{:X}] */".format(self.rom_start, self.rom_end, self.rom_end - self.rom_start))
        lines.append("    {} 0x{:X} : AT(0x{:X}) ".format(section_name, self.rom_start, self.rom_start) + "{")
        lines.append("        build/{}.Yay0(.data);".format(self.name))
        lines.append("    }")
        lines.append("")
        lines.append("")
        return "\n".join(lines)


    @staticmethod
    def create_makefile_target():
        return ""

    @staticmethod
    def get_default_name(addr):
        return "bin/Yay0/{:X}".format(addr)
