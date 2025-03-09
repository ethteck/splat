from pathlib import Path
from typing import Optional, List

from ...util import options

from .codesubsegment import CommonSegCodeSubsegment


class CommonSegAsm(CommonSegCodeSubsegment):
    @staticmethod
    def is_text() -> bool:
        return True

    def get_section_flags(self) -> Optional[str]:
        return "ax"

    def scan(self, rom_bytes: bytes):
        if (
            self.rom_start is not None
            and self.rom_end is not None
            and self.rom_start != self.rom_end
        ):
            self.scan_code(rom_bytes)

    def split(self, rom_bytes: bytes):
        if self.rom_start == self.rom_end:
            return

        self.split_as_asm_file(self.out_path())
