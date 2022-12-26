import spimdisasm
from util import log, options, symbols

from segtypes.common.data import CommonSegData


class CommonSegRodata(CommonSegData):
    def get_linker_section(self) -> str:
        return ".rodata"

    def disassemble_data(self, rom_bytes):
        if not isinstance(self.rom_start, int):
            log.error(
                f"Segment '{self.name}' (type '{self.type}') requires a rom_start. Got '{self.rom_start}'"
            )

        # Supposedly logic error, not user error
        assert isinstance(self.rom_end, int), self.rom_end

        # Supposedly logic error, not user error
        segment_rom_start = self.get_most_parent().rom_start
        assert isinstance(segment_rom_start, int), segment_rom_start

        if not isinstance(self.vram_start, int):
            log.error(
                f"Segment '{self.name}' (type '{self.type}') requires a vram address. Got '{self.vram_start}'"
            )

        self.spim_section = spimdisasm.mips.sections.SectionRodata(
            symbols.spim_context,
            self.rom_start,
            self.rom_end,
            self.vram_start,
            self.name,
            rom_bytes,
            segment_rom_start,
            self.get_exclusive_ram_id(),
        )

        # Set rodata string encoding
        # First check the global configuration
        if options.opts.string_encoding is not None:
            self.spim_section.stringEncoding = options.opts.string_encoding

        # Then check the per-segment configuration in case we want to override the global one
        if self.str_encoding is not None:
            self.spim_section.stringEncoding = self.str_encoding

        self.spim_section.analyze()
        self.spim_section.setCommentOffset(self.rom_start)

        for symbol in self.spim_section.symbolList:
            symbols.create_symbol_from_spim_symbol(
                self.get_most_parent(), symbol.contextSym
            )

    def split(self, rom_bytes: bytes):
        # Disassemble the file itself
        super().split(rom_bytes)

        if options.opts.migrate_rodata_to_functions:
            if self.spim_section is not None and self.partial_migration:
                path_folder = options.opts.nonmatchings_path / self.dir / self.name
                path_folder.mkdir(parents=True, exist_ok=True)

                for rodataSym in self.spim_section.symbolList:
                    if rodataSym.shouldMigrate():
                        continue

                    path = path_folder / f"{rodataSym.getName()}.s"
                    with open(path, "w", newline="\n") as f:
                        if options.opts.include_macro_inc:
                            f.write('.include "macro.inc"\n\n')
                        preamble = options.opts.generated_s_preamble
                        if preamble:
                            f.write(preamble + "\n")
                        f.write(f".section {self.get_linker_section()}\n\n")
                        f.write(rodataSym.disassemble())
