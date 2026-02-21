from __future__ import annotations

from ..common.data import CommonSegData
from ...disassembler.disassembler_section import DisassemblerSection


class Ps2SegCtor(CommonSegData):
    """Segment that contains pointers to C++ global data initialization functions"""

    def get_linker_section(self) -> str:
        return ".ctor"

    def get_section_flags(self) -> str | None:
        return "a"

    def configure_disassembler_section(
        self, disassembler_section: DisassemblerSection
    ) -> None:
        "Allows to configure the section before running the analysis on it"

        super().configure_disassembler_section(disassembler_section)

        section = disassembler_section.get_section()
        assert section is not None

        # We use s32 to make sure spimdisasm disassembles the data from this section as words/references to other symbols
        section.enableStringGuessing = False
        section.typeForOwnedSymbols = "s32"
        section.sizeForOwnedSymbols = 4
