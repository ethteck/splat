from pathlib import Path
from segtypes.n64.segment import N64Segment
from util import options

class N64SegBin(N64Segment):
    def split(self, rom_bytes):
        out_dir = options.get_asset_path() / self.dir
        out_dir.mkdir(parents=True, exist_ok=True)

        bin_path = out_dir / f"{self.name}.bin"
        with open(bin_path, "wb") as f:
            f.write(rom_bytes[self.rom_start : self.rom_end])
        self.log(f"Wrote {self.name} to {bin_path}")

    def get_linker_entries(self):
        from segtypes.linker_entry import LinkerEntry

        path = options.get_asset_path() / self.dir / f"{self.name}.bin"

        return [LinkerEntry(
            self,
            [path],
            path,
            ".data",
        )]

    @staticmethod
    def get_default_name(addr):
        return "bin_{:X}".format(addr)
