from typing import Optional

import spimdisasm

from ..common.data import CommonSegData
from ...disassembler.disassembler_section import DisassemblerSection


class PS2SegCtor(CommonSegData):
    """Segment that only contains a pointer to C++ global data initialization functions"""

    def get_linker_section(self) -> str:
        return ".ctor"

    def get_section_flags(self) -> Optional[str]:
        return "a"

    def configure_disassembler_section(self, disassembler_section: DisassemblerSection) -> None:
        "Allows to configure the section before running the analysis on it"

        super().configure_disassembler_section(disassembler_section)

        section = disassembler_section.get_section()
        assert isinstance(section, spimdisasm.mips.sections.SectionBase)

        section.enableStringGuessing = False
        section.typeForOwnedSymbols = "s32"
        section.sizeForOwnedSymbols = 4
