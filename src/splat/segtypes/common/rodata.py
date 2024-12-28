from typing import Optional, Set, Tuple, List
import spimdisasm
from ..segment import Segment
from ...util import log, options, symbols

from .data import CommonSegData

from ...disassembler.disassembler_section import (
    DisassemblerSection,
    make_rodata_section,
)


class CommonSegRodata(CommonSegData):
    def get_linker_section(self) -> str:
        return ".rodata"

    def get_section_flags(self) -> Optional[str]:
        return "a"

    @staticmethod
    def is_data() -> bool:
        return False

    @staticmethod
    def is_rodata() -> bool:
        return True

    def get_possible_text_subsegment_for_symbol(
        self, rodata_sym: spimdisasm.mips.symbols.SymbolBase
    ) -> Optional[Tuple[Segment, spimdisasm.common.ContextSymbol]]:
        # Check if this rodata segment does not have a corresponding code file, try to look for one

        if self.sibling is not None or not options.opts.pair_rodata_to_text:
            return None

        if not rodata_sym.shouldMigrate():
            return None

        if len(rodata_sym.contextSym.referenceFunctions) != 1:
            return None

        func = list(rodata_sym.contextSym.referenceFunctions)[0]
        text_segment = self.parent.get_subsegment_for_ram(func.vram)

        if text_segment is None or not text_segment.is_text():
            return None
        return text_segment, func

    def configure_disassembler_section(
        self, disassembler_section: DisassemblerSection
    ) -> None:
        "Allows to configure the section before running the analysis on it"

        section = disassembler_section.get_section()

        # Set rodata string encoding
        # First check the global configuration
        if options.opts.string_encoding is not None:
            section.stringEncoding = options.opts.string_encoding

        # Then check the per-segment configuration in case we want to override the global one
        if self.str_encoding is not None:
            section.stringEncoding = self.str_encoding

    def disassemble_data(self, rom_bytes):
        if self.is_auto_segment:
            return

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

        self.spim_section = make_rodata_section(
            self.rom_start,
            self.rom_end,
            self.vram_start,
            self.name,
            rom_bytes,
            segment_rom_start,
            self.get_exclusive_ram_id(),
        )

        assert self.spim_section is not None

        self.configure_disassembler_section(self.spim_section)

        self.spim_section.analyze()
        self.spim_section.set_comment_offset(self.rom_start)

        possible_text_segments: Set[Segment] = set()

        last_jumptable_addr_remainder = 0
        misaligned_jumptable_offsets: List[int] = []

        for symbol in self.spim_section.get_section().symbolList:
            generated_symbol = symbols.create_symbol_from_spim_symbol(
                self.get_most_parent(), symbol.contextSym
            )
            generated_symbol.linker_section = self.get_linker_section_linksection()

            # Gather symbols found by spimdisasm and create those symbols in splat's side
            for referenced_vram in symbol.referencedVrams:
                context_sym = self.spim_section.get_section().getSymbol(
                    referenced_vram, tryPlusOffset=False
                )
                if context_sym is not None:
                    symbols.create_symbol_from_spim_symbol(
                        self.get_most_parent(), context_sym
                    )

            possible_text = self.get_possible_text_subsegment_for_symbol(symbol)
            if possible_text is not None:
                text_segment, refenceeFunction = possible_text
                if text_segment not in possible_text_segments:
                    print(
                        f"\nRodata segment '{self.name}' may belong to the text segment '{text_segment.name}'"
                    )
                    print(
                        f"    Based on the usage from the function {refenceeFunction.getName()} to the symbol {symbol.getName()}"
                    )
                    possible_text_segments.add(text_segment)

            if options.opts.platform in ("psx", "ps2"):
                if generated_symbol.type == "jtbl":
                    # GCC aligns jumptables to 8, but it doesn't impose alignment restrictions for sections themselves on PSX/PS2.
                    # This means a jumptable may be aligned file-wise, but it may not end up 8-aligned binary-wise.
                    # We can use this as a way to find file splits on PSX/PS2
                    vram_diff = generated_symbol.vram_start - self.vram_start
                    if vram_diff % 8 != last_jumptable_addr_remainder:
                        # Each time the this remainder changes means there's a new file split
                        last_jumptable_addr_remainder = vram_diff % 8

                        misaligned_jumptable_offsets.append(self.rom_start + vram_diff)

        if len(misaligned_jumptable_offsets) > 0:
            print(
                f"\nThe rodata segment '{self.name}' has jumptables that are not aligned properly file-wise, indicating one or more likely file split."
            )
            print(
                "File split suggestions for this segment will follow in config yaml format:"
            )
            for offset in misaligned_jumptable_offsets:
                print(f"      - [0x{offset:X}, {self.type}]")
            print()
