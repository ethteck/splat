import spimdisasm
from typing import List

from segtypes.common.data import CommonSegData
from segtypes.linker_entry import LinkerEntry
from util import options, symbols


class CommonSegBss(CommonSegData):
    def get_linker_section(self) -> str:
        return ".bss"

    def scan(self, rom_bytes: bytes):
        assert isinstance(self.rom_start, int)
        assert isinstance(self.rom_end, int)

        segment_rom_start = self.get_most_parent().rom_start
        assert isinstance(segment_rom_start, int)

        bss_end = self.get_most_parent().vram_end
        assert isinstance(bss_end, int)

        self.bss_section = spimdisasm.mips.sections.SectionBss(
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
            symbols.add_symbol_to_spim_section(self.bss_section, symbol_list[0])

        for sym in symbols.all_symbols:
            if sym.user_declared:
                symbols.add_symbol_to_spim_section(self.bss_section, sym)

        self.bss_section.analyze()
        self.bss_section.setCommentOffset(self.rom_start)

        for spim_sym in self.bss_section.symbolList:
            symbols.create_symbol_from_spim_symbol(
                self.get_most_parent(), spim_sym.contextSym
            )

    def split(self, rom_bytes: bytes):
        if not self.rom_start == self.rom_end:
            out_path = self.out_path()
            if out_path:
                out_path.parent.mkdir(parents=True, exist_ok=True)

                with open(out_path, "w", newline="\n") as f:
                    f.write('.include "macro.inc"\n\n')
                    f.write(f'.section {self.get_linker_section()}\n\n')

                    f.write(self.bss_section.disassemble())

    def get_linker_entries(self) -> "List[LinkerEntry]":

        if self.sibling:
            path = self.sibling.out_path()
        else:
            path = self.out_path()

        if path:
            return [LinkerEntry(self, [path], path, self.get_linker_section())]
        else:
            return []
