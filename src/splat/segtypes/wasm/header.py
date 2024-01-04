from pathlib import Path
from typing import Optional

from ...util import options

from ..common.bin import CommonSegBin

from wasm_tob import ModuleHeader


class WasmSegHeader(CommonSegBin):
    @staticmethod
    def is_text() -> bool:
        return True

    def out_path(self) -> Optional[Path]:
        return options.opts.asm_path / self.dir / f"{self.name}.wat"

    def split(self, rom_bytes: bytes):
        raw = rom_bytes[self.rom_start : self.rom_end]

        out_path = self.out_path()
        if out_path:
            out_path.parent.mkdir(parents=True, exist_ok=True)

            hdr = ModuleHeader()
            hdr_len, hdr_data, _ = hdr.from_raw(None, raw)

            with open(out_path, "w") as f:
                f.write(f"(module ;; version: {hdr_data.version}")
