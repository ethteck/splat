import spimdisasm
from util import symbols

from segtypes.common.data import CommonSegData


class CommonSegBss(CommonSegData):
    def get_linker_section(self) -> str:
        return ".bss"

    def disassemble_data(self, rom_bytes: bytes):
        assert isinstance(self.vram_start, int), f"{self.vram_start} {self.name}"
        assert isinstance(self.vrom_end, int)

        segment_vrom_start = self.get_most_parent().vrom_start

        next_subsegment = self.parent.get_next_subsegment_for_ram(self.vram_start)
        if next_subsegment is None:
            bss_end = self.get_most_parent().vram_end
            assert isinstance(bss_end, int)
        else:
            bss_end = next_subsegment.vram_start

        self.spim_section = spimdisasm.mips.sections.SectionBss(
            symbols.spim_context,
            self.vrom_start,
            self.vrom_end,
            self.vram_start,
            bss_end,
            self.name,
            segment_vrom_start,
            self.get_exclusive_ram_id(),
        )

        self.spim_section.analyze()
        self.spim_section.setCommentOffset(self.vrom_start)

        for spim_sym in self.spim_section.symbolList:
            symbols.create_symbol_from_spim_symbol(
                self.get_most_parent(), spim_sym.contextSym
            )
