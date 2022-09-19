import spimdisasm
from typing import List

from segtypes.common.data import CommonSegData
from segtypes.linker_entry import LinkerEntry
from util import options, symbols


class CommonSegBss(CommonSegData):
    def get_linker_section(self) -> str:
        return ".bss"

    def disassemble_data(self, rom_bytes: bytes):
        assert isinstance(self.rom_start, int)
        assert isinstance(self.rom_end, int)

        segment_rom_start = self.get_most_parent().rom_start
        assert isinstance(segment_rom_start, int)

        bss_end = self.get_most_parent().vram_end
        assert isinstance(bss_end, int)

        self.spim_section = spimdisasm.mips.sections.SectionBss(
            symbols.spim_context,
            self.rom_start,
            self.rom_end,
            self.vram_start,
            bss_end,
            self.name,
            segment_rom_start,
            self.get_exclusive_ram_id(),
        )

        for symbol_list in self.seg_symbols.values():
            symbols.add_symbol_to_spim_section(self.spim_section, symbol_list[0])

        for sym in symbols.all_symbols:
            if sym.user_declared:
                symbols.add_symbol_to_spim_section(self.spim_section, sym)

        self.spim_section.analyze()
        self.spim_section.setCommentOffset(self.rom_start)

        for spim_sym in self.spim_section.symbolList:
            symbols.create_symbol_from_spim_symbol(
                self.get_most_parent(), spim_sym.contextSym
            )

    def get_linker_entries(self) -> "List[LinkerEntry]":
        if self.sibling:
            path = self.sibling.out_path()
        else:
            path = self.out_path()

        if path:
            return [LinkerEntry(self, [path], path, self.get_linker_section())]
        else:
            return []
