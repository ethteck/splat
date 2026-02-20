from typing import Optional

from ..common.data import CommonSegData
from ...disassembler.disassembler_section import DisassemblerSection


class Ps2SegLit8(CommonSegData):
    """Segment that only contains double-precision floats"""

    def get_linker_section(self) -> str:
        return ".lit8"

    def get_section_flags(self) -> Optional[str]:
        return "wa"

    def configure_disassembler_section(
        self, disassembler_section: DisassemblerSection
    ) -> None:
        "Allows to configure the section before running the analysis on it"

        super().configure_disassembler_section(disassembler_section)

        section = disassembler_section.get_section()

        # Tell spimdisasm this section only contains doubles
        section.enableStringGuessing = False
        section.typeForOwnedSymbols = "f64"
        section.sizeForOwnedSymbols = 8
