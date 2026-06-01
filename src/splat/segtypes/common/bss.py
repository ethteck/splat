from typing import Optional, Union

from ...util import options, symbols, log

from .data import CommonSegData

from ...disassembler.disassembler_section import DisassemblerSection, make_bss_section

# If `options.opts.ld_bss_is_noload` is False, then this segment behaves like a `CommonSegData`


class CommonSegBss(CommonSegData):
    def __init__(
        self,
        rom_start: Optional[int],
        rom_end: Optional[int],
        type: str,
        name: str,
        vram_start: Optional[int],
        args: list,
        yaml: Union[dict, list],
        bss_size: Optional[int] = None,
    ):
        parsed_bss_size = self.parse_bss_size(yaml)
        if bss_size is not None:
            if parsed_bss_size is not None:
                log.error(
                    f"Error: Passing bss_size attribute to bss section {self.name} (0x{vram_start:08X}) is not allowed when the size of the bss section can be inferred (was inferred to 0x{bss_size:X}).\n"""
                    "  Setting this attribute is only allowed when the bss size can't be inferred."
                )
            self.bss_size = bss_size
        else:
            self.bss_size = parsed_bss_size

        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            args=args,
            yaml=yaml,
            bss_size=self.bss_size,
        )

    def get_linker_section(self) -> str:
        return ".bss"

    def get_section_flags(self) -> Optional[str]:
        return "wa"

    @staticmethod
    def is_data() -> bool:
        if not options.opts.ld_bss_is_noload:
            return True
        return False

    @staticmethod
    def is_noload() -> bool:
        if not options.opts.ld_bss_is_noload:
            return False
        return True

    def configure_disassembler_section(
        self, disassembler_section: DisassemblerSection
    ) -> None:
        "Allows to configure the section before running the analysis on it"

        pass

    def disassemble_data(self, rom_bytes: bytes):
        if not options.opts.ld_bss_is_noload:
            super().disassemble_data(rom_bytes)
            return

        if self.is_auto_segment:
            return

        if not isinstance(self.rom_start, int):
            log.error(
                f"Segment '{self.name}' (type '{self.type}') requires a rom_start. Got '{self.rom_start}'"
            )

        # Supposedly logic error, not user error
        assert isinstance(self.rom_end, int), f"{self.name} {self.rom_end}"

        # Supposedly logic error, not user error
        segment_rom_start = self.get_most_parent().rom_start
        assert isinstance(segment_rom_start, int), f"{self.name} {segment_rom_start}"

        if not isinstance(self.vram_start, int):
            log.error(
                f"Segment '{self.name}' (type '{self.type}') requires a vram address. Got '{self.vram_start}'"
            )

        # Supposedly logic error, not user error
        if self.bss_size is None:
            log.error(
                f"Unable to infer the size for segment '{self.name}' (type '{self.type}', vram 0x{self.vram_start:08X}).\n"
                "  This may happen when this segment is followed by a segment that doesn't use a vram address.\n"
                "  HINT: Try setting a vram address to the next segment in the yaml or set `bss_size=0xXXXX` for this segment."
            )

        bss_end = self.vram_start + self.bss_size

        self.spim_section = make_bss_section(
            self.rom_start,
            self.rom_end,
            self.vram_start,
            bss_end,
            self.name,
            segment_rom_start,
            self.get_exclusive_ram_id(),
        )

        assert self.spim_section is not None

        self.configure_disassembler_section(self.spim_section)

        self.spim_section.analyze()
        self.spim_section.set_comment_offset(self.rom_start)

        for spim_sym in self.spim_section.get_section().symbolList:
            symbols.create_symbol_from_spim_symbol(
                self.get_most_parent(), spim_sym.contextSym, force_in_segment=True
            )

    def should_scan(self) -> bool:
        if not options.opts.ld_bss_is_noload:
            return super().should_scan()
        return options.opts.is_mode_active("code") and self.vram_start is not None
