from pathlib import Path
from typing import Optional
from segtypes.n64.segment import N64Segment
from util import options

class N64SegBin(N64Segment):
    def out_path(self) -> Optional[Path]:
        return options.get_asset_path() / self.dir / f"{self.name}.bin"
        
    def split(self, rom_bytes):
        path = self.out_path()
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "wb") as f:
            f.write(rom_bytes[self.rom_start : self.rom_end])
        self.log(f"Wrote {self.name} to {path}")

    @staticmethod
    def get_default_name(addr):
        return "bin_{:X}".format(addr)
