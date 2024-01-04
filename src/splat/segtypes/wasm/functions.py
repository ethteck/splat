from pathlib import Path
from typing import Optional

from ...util import options

from ..common.bin import CommonSegBin

from wasm_tob import Section, SEC_FUNCTION, FunctionSection, FuncType
from ...platforms.wasm import function_section_to_wat


class WasmSegFunctions(CommonSegBin):
    @staticmethod
    def is_text() -> bool:
        return True

    def out_path(self) -> Optional[Path]:
        return options.opts.asm_path / self.dir / f"{self.name}.functions.wat"

    def split(self, rom_bytes: bytes):
        raw = rom_bytes[self.rom_start : self.rom_end]

        out_path = self.out_path()
        if out_path:
            out_path.parent.mkdir(parents=True, exist_ok=True)

            sec = Section()
            sec_len, sec_data, _ = sec.from_raw(None, raw)

            if sec_data.id != SEC_FUNCTION:
                # TODO: handle invalidly assigned sections.
                pass

            function_section: FunctionSection = sec_data.payload
            with open(out_path, "w") as f:
                f.write(function_section_to_wat(function_section))
