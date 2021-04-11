from segtypes.n64.segment import N64Segment
from util.n64 import Yay0decompress
from util import options

class N64SegYay0(N64Segment):
    def split(self, rom_bytes):
        out_dir = options.get_asset_path() / self.dir
        out_dir.mkdir(parents=True, exist_ok=True)

        out_path = out_dir / f"{self.name}.bin"
        with open(out_path, "wb") as f:
            self.log(f"Decompressing {self.name}...")
            compressed_bytes = rom_bytes[self.rom_start : self.rom_end]
            decompressed_bytes = Yay0decompress.decompress_yay0(compressed_bytes)
            f.write(decompressed_bytes)
        self.log(f"Wrote {self.name} to {out_path}")


    def get_linker_entries(self):
        from segtypes.linker_entry import LinkerEntry

        return [LinkerEntry(
            self,
            [options.get_asset_path() / self.dir / f"{self.name}.bin"],
            options.get_asset_path() / self.dir / f"{self.name}.Yay0",
            self.get_linker_section()
        )]
