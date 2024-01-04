from pathlib import Path
from typing import Optional

from ...util import options

from ..common.bin import CommonSegBin

from wasm_tob import Section


class WasmSegTypes(CommonSegBin):
    @staticmethod
    def is_text() -> bool:
        return True

    def out_path(self) -> Optional[Path]:
        return options.opts.asm_path / self.dir / f"{self.name}.types.wat"

    def split(self, rom_bytes: bytes):
        raw = rom_bytes[self.rom_start : self.rom_end]

        out_path = self.out_path()
        if out_path:
            out_path.parent.mkdir(parents=True, exist_ok=True)

            sec = Section()
            sec_len, sec_data, _ = sec.from_raw(None, raw)

            print(f"{sec_len} {sec_data}")

            with open(out_path, "wb") as f:
                f.write(raw)  # syke
