from __future__ import annotations

from splat.segtypes.common.data import CommonSegData
from splat.util import log

from splat.disassembler.disassembler_section import make_gcc_except_table_section


class PS2SegGcc_except_table(CommonSegData):
    def get_linker_section(self) -> str:
        return ".gcc_except_table"

    def get_section_flags(self) -> str|None:
        return "aw"

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

        self.spim_section = make_gcc_except_table_section(
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
