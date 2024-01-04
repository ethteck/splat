from pathlib import Path
from typing import Optional

from wasm_tob import (
    decode_bytecode,
    format_instruction,
    INSN_ENTER_BLOCK,
    INSN_LEAVE_BLOCK,
    Section,
    SEC_TYPE,
    SEC_IMPORT,
    SEC_FUNCTION,
    SEC_EXPORT
)

from ...util import options

from ..common.bin import CommonSegBin
from ...platforms.wasm import (
    type_section_to_wat, 
    import_section_to_wat,
    function_section_to_wat,
    export_section_to_wat,
)


class WasmSegAsm(CommonSegBin):
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

            sec = Section()
            sec_len, sec_data, _ = sec.from_raw(None, raw)

            SECTION_TO_WAT = {
                SEC_TYPE: type_section_to_wat,
                SEC_IMPORT: import_section_to_wat,
                SEC_FUNCTION: function_section_to_wat,
                SEC_EXPORT: export_section_to_wat,
            }

            with open(out_path, "w") as f:
                f.write(SECTION_TO_WAT[sec_data.id](sec_data.payload))
