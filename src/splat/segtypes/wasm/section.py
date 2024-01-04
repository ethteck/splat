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

from ..common.segment import CommonSegment
from ...platforms.wasm import (
    type_section_to_wat,
    import_section_to_wat,
    function_section_to_wat,
    export_section_to_wat,
    data_section_to_wat,
    code_section_to_wat,
)


SECTION_TO_WAT = {
    SEC_TYPE: lambda mod: type_section_to_wat(mod.type_section),
    SEC_IMPORT: lambda mod: import_section_to_wat(mod.import_section),
    SEC_FUNCTION: lambda mod: function_section_to_wat(mod.function_section),
    SEC_EXPORT: lambda mod: export_section_to_wat(mod.export_section),
    SEC_DATA: lambda mod: data_section_to_wat(mod.data_section),
    SEC_CODE: lambda mod: code_section_to_wat(mod.code_section, mod.function_section, mod.type_section),
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

class WasmSegSection(CommonSegment):
    def __init__(
        self,
        rom_start: Optional[int],
        rom_end: Optional[int],
        type: str,
        name: str,
        vram_start: Optional[int],
        args: list,
        yaml,
    ):
        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            args=args,
            yaml=yaml,
        )
        self.section = None
        
    @staticmethod
    def is_text() -> bool:
        return True

    def out_path(self) -> Optional[Path]:
        return options.opts.asm_path / self.dir / f"{self.name}.wat"

    def scan(self, rom_bytes: bytes):
        raw = rom_bytes[self.rom_start : self.rom_end]

        sec = Section()
        sec_len, self.section, _ = sec.from_raw(None, raw)

        if self.section.id not in SECTION_TO_WAT:
            log.write(
                f"warning: parsing for {SECTION_TO_STR[self.section.id]} section is not done yet.",
                status="warn",
            )
        else:
            self.parent.sections[self.section.id] = self.section
        
        pass

    def split(self, rom_bytes: bytes):
        if self.section.id not in SECTION_TO_WAT:
            return

        out_path = self.out_path()
        if out_path:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(out_path, "w") as f:
                f.write(SECTION_TO_WAT[self.section.id](self.parent))
