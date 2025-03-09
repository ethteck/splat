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

    def get_asm_file_extra_directives(self) -> List[str]:
        ret = []

        ret.append(".set noat")  # allow manual use of $at
        ret.append(".set noreorder")  # don't insert nops after branches
        if options.opts.add_set_gp_64:
            ret.append(".set gp=64")  # allow use of 64-bit general purpose registers
        ret.append("")

        return ret

    def split(self, rom_bytes: bytes):
        if self.rom_start == self.rom_end:
            return

        self.split_as_asm_file(self.out_path())
