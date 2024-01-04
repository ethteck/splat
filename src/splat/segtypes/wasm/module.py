from pathlib import Path
from typing import Optional, Dict

from ...util import options

from ..common.group import CommonSegGroup

from wasm_tob import (
    ModuleHeader,
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


class WasmSegModule(CommonSegGroup):
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
        self.sections: Dict[int, Section] = {}

    @staticmethod
    def is_text() -> bool:
        return True

    def out_path(self) -> Optional[Path]:
        return options.opts.asm_path / self.dir / f"{self.name}.wat"

    def scan(self, rom_bytes: bytes):
        raw = rom_bytes[self.rom_start : self.rom_end]

        hdr = ModuleHeader()
        hdr_len, hdr_data, _ = hdr.from_raw(None, raw)

        print(f"(module ;; version: {hdr_data.version}")

        super().scan(rom_bytes)

    def get_section_payload(self, id: int):
        return self.sections[id].payload

    @property
    def type_section(self):
        return self.get_section_payload(SEC_TYPE)

    @property
    def import_section(self):
        return self.get_section_payload(SEC_IMPORT)

    @property
    def function_section(self):
        return self.get_section_payload(SEC_FUNCTION)

    @property
    def export_section(self):
        return self.get_section_payload(SEC_EXPORT)

    @property
    def data_section(self):
        return self.get_section_payload(SEC_DATA)

    @property
    def code_section(self):
        return self.get_section_payload(SEC_CODE)
