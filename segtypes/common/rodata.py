import spimdisasm

from segtypes.common.data import CommonSegData
from util import symbols


class CommonSegRodata(CommonSegData):
    def get_linker_section(self) -> str:
        return ".rodata"

    def disassemble_data(self, rom_bytes):
        assert isinstance(self.rom_start, int)
        assert isinstance(self.rom_end, int)

        segment_rom_start = self.get_most_parent().rom_start
        assert isinstance(segment_rom_start, int)

        self.rodata_section = spimdisasm.mips.sections.SectionRodata(
            symbols.spim_context,
            self.rom_start,
            self.rom_end,
            self.vram_start,
            self.name,
            rom_bytes,
            segment_rom_start,
            self.get_exclusive_ram_id(),
        )

        for symbol_list in self.seg_symbols.values():
            symbols.add_symbol_to_spim_section(self.rodata_section, symbol_list[0])

        for sym in symbols.all_symbols:
            if sym.user_declared:
                symbols.add_symbol_to_spim_section(self.rodata_section, sym)

        self.rodata_section.analyze()
        self.rodata_section.setCommentOffset(self.rom_start)

        for symbol in self.rodata_section.symbolList:
            symbols.create_symbol_from_spim_symbol(
                self.get_most_parent(), symbol.contextSym
            )

        return None


    def split(self, rom_bytes: bytes):
        super().split(rom_bytes)

        if not self.type.startswith("."):
            path = self.out_path()

            if path:
                path.parent.mkdir(parents=True, exist_ok=True)

                self.print_file_boundaries()

                with open(path, "w", newline="\n") as f:
                    f.write(self.rodata_section.disassemble())


    def print_file_boundaries(self):
        # TODO
        pass
