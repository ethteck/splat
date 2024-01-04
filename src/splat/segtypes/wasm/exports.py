from pathlib import Path
from typing import Optional

from ...util import options

from ..common.bin import CommonSegBin

from wasm_tob import Section, SEC_EXPORT, ExportSection
from ...platforms.wasm import export_section_to_wat


class WasmSegExports(CommonSegBin):
    @staticmethod
    def is_text() -> bool:
        return True

    def out_path(self) -> Optional[Path]:
        return options.opts.asm_path / self.dir / f"{self.name}.exports.wat"

    def split(self, rom_bytes: bytes):
        raw = rom_bytes[self.rom_start : self.rom_end]

        out_path = self.out_path()
        if out_path:
            out_path.parent.mkdir(parents=True, exist_ok=True)

            sec = Section()
            sec_len, sec_data, _ = sec.from_raw(None, raw)

            if sec_data.id != SEC_EXPORT:
                # TODO: handle invalidly assigned sections.
                pass

            export_section: ExportSection = sec_data.payload
            with open(out_path, "w") as f:
                f.write(export_section_to_wat(export_section))
