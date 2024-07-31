from typing import Optional

from .data import CommonSegData
from ...disassembler.disassembler_section import DisassemblerSection


class CommonSegEh_frame(CommonSegData):
    """Segment containing an Error Handler Frame, used for C++ exceptions"""

    def get_linker_section(self) -> str:
        return ".eh_frame"

    def get_section_flags(self) -> Optional[str]:
        return "aw"

    def configure_disassembler_section(
        self, disassembler_section: DisassemblerSection
    ) -> None:
        "Allows to configure the section before running the analysis on it"

        super().configure_disassembler_section(disassembler_section)

        section = disassembler_section.get_section()

        # We use s32 to make sure spimdisasm disassembles the data from this section as words/references to other symbols
        section.enableStringGuessing = False
        section.typeForOwnedSymbols = "s32"
