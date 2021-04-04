import os
from segtypes.n64.segment import N64Segment
from util.n64 import Yay0decompress
from util import options
from segtypes.linker_entry import LinkerEntry

class N64SegYay0(N64Segment):
    def split(self, rom_bytes, base_path):
        out_dir = options.get_asset_path / self.dir
        out_dir.mkdir(parents=True, exist_ok=True)

        out_path = out_dir / self.name / ".bin"
        with open(out_path, "wb") as f:
            self.log(f"Decompressing {self.name}...")
            compressed_bytes = rom_bytes[self.rom_start : self.rom_end]
            decompressed_bytes = Yay0decompress.decompress_yay0(compressed_bytes)
            f.write(decompressed_bytes)
        self.log(f"Wrote {self.name} to {out_path}")


    def get_linker_entries(self):
        return [LinkerEntry(self, options.get_asset_dir() / self.dir / "{self.name}.Yay0")]

    @staticmethod
    def get_default_name(addr):
        return "Yay0/{:X}".format(addr)
