from pathlib import Path
from typing import Optional

from wasm_tob import (
    decode_bytecode,
    format_instruction,
    INSN_ENTER_BLOCK,
    INSN_LEAVE_BLOCK,
    Section,
    SEC_UNK,
    SEC_TYPE,
    SEC_IMPORT,
    SEC_FUNCTION,
    SEC_TABLE,
    SEC_MEMORY,
    SEC_GLOBAL,
    SEC_EXPORT,
    SEC_START,
    SEC_ELEMENT,
    SEC_CODE,
    SEC_DATA,
)

from ...util import options, log

from ..common.bin import CommonSegBin
from ...platforms.wasm import (
    type_section_to_wat,
    import_section_to_wat,
    function_section_to_wat,
    export_section_to_wat,
    data_section_to_wat,
    code_section_to_wat,
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
                SEC_DATA: data_section_to_wat,
                SEC_CODE: code_section_to_wat,
            }

            SECTION_TO_STR = {
                SEC_UNK: "custom",
                SEC_TYPE: "type",
                SEC_IMPORT: "import",
                SEC_FUNCTION: "function",
                SEC_TABLE: "table",
                SEC_MEMORY: "memory",
                SEC_GLOBAL: "global",
                SEC_EXPORT: "export",
                SEC_START: "start",
                SEC_ELEMENT: "element",
                SEC_CODE: "code",
                SEC_DATA: "data",
            }

            if sec_data.id not in SECTION_TO_WAT:
                log.write(
                    f"error: parsing for {SECTION_TO_STR[sec_data.id]} section is not done yet.",
                    status="error",
                )
            else:
                with open(out_path, "w") as f:
                    f.write(SECTION_TO_WAT[sec_data.id](sec_data.payload))
