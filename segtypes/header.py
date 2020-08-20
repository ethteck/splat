import os
from segtypes.segment import N64Segment
from pathlib import Path

class N64SegAsm(N64Segment):
    def split(self, rom_bytes, base_path, options):
        out_dir = self.create_split_dir(base_path, "asm")

        with open(os.path.join(out_dir,  self.name + ".s"), "w", newline="\n") as f:
            f.write(".section .header, \"a\"\n")
            f.write("")


    @staticmethod
    def create_makefile_target():
        return ""