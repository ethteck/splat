"""
N64 Vtx struct splitter
Dumps out Vtx as a .inc.c file.

Originally written by Mark Street (https://github.com/mkst)
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import TYPE_CHECKING

from ...util import options, log

from ..common.codesubsegment import CommonSegCodeSubsegment

if TYPE_CHECKING:
    from ...util.vram_classes import SerializedSegmentData
    from ...util.symbols import Symbol


class N64SegVtx(CommonSegCodeSubsegment):
    def __init__(
        self,
        rom_start: int | None,
        rom_end: int | None,
        type: str,
        name: str,
        vram_start: int | None,
        args: list[str],
        yaml: SerializedSegmentData | list[str],
    ) -> None:
        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            args=args,
            yaml=yaml,
        )
        self.file_text: str | None = None
        self.data_only = isinstance(yaml, dict) and yaml.get("data_only", False)

    def format_sym_name(self, sym: Symbol) -> str:
        return sym.name

    def get_linker_section(self) -> str:
        return ".data"

    def out_path(self) -> Path:
        return options.opts.asset_path / self.dir / f"{self.name}.vtx.inc.c"

    def scan(self, rom_bytes: bytes) -> None:
        self.file_text = self.disassemble_data(rom_bytes)

    def disassemble_data(self, rom_bytes: bytes) -> str:
        assert isinstance(self.rom_start, int)
        assert isinstance(self.rom_end, int)
        assert isinstance(self.vram_start, int)

        vertex_data = rom_bytes[self.rom_start : self.rom_end]
        segment_length = len(vertex_data)
        if (segment_length) % 16 != 0:
            log.error(
                f"Error: Vtx segment {self.name} length ({segment_length}) is not a multiple of 16!"
            )

        lines = []
        if not self.data_only:
            lines.append(options.opts.generated_c_preamble)
            lines.append("")

        vertex_count = segment_length // 16
        sym = self.create_symbol(
            addr=self.vram_start, in_segment=True, type="data", define=True
        )

        if not self.data_only:
            lines.append(f"Vtx {self.format_sym_name(sym)}[{vertex_count}] = {{")

        for vtx in struct.iter_unpack(">hhhHhhBBBB", vertex_data):
            x, y, z, flg, t, c, r, g, b, a = vtx
            vtx_string = f"    {{{{{{ {x:5}, {y:5}, {z:5} }}, {flg}, {{ {t:5}, {c:5} }}, {{ {r:3}, {g:3}, {b:3}, {a:3} }}}}}},"
            if flg != 0:
                self.warn(f"Non-zero flag found in vertex data {self.name}!")
            lines.append(vtx_string)

        if not self.data_only:
            lines.append("};")

        # enforce newline at end of file
        lines.append("")
        return "\n".join(lines)

    def split(self, rom_bytes: bytes) -> None:
        out_path = self.out_path()
        if self.file_text and out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)

            with open(out_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(self.file_text)

    def should_scan(self) -> bool:
        return options.opts.is_mode_active("vtx")

    def should_split(self) -> bool:
        return self.extract and options.opts.is_mode_active("vtx")

    @staticmethod
    def estimate_size(yaml: SerializedSegmentData | list[str]) -> int | None:
        if isinstance(yaml, dict) and "length" in yaml:
            return yaml["length"] * 0x10
        return None
