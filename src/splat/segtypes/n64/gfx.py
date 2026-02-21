"""
N64 f3dex display list splitter
Dumps out Gfx[] as a .inc.c file.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pathlib import Path

from pygfxd import (
    gfxd_buffer_to_string,
    gfxd_cimg_callback,
    gfxd_dl_callback,
    gfxd_endian,
    gfxd_execute,
    gfxd_input_buffer,
    gfxd_light_callback,
    gfxd_lookat_callback,
    gfxd_macro_dflt,
    gfxd_macro_fn,
    gfxd_mtx_callback,
    gfxd_output_buffer,
    gfxd_printf,
    gfxd_puts,
    gfxd_target,
    gfxd_timg_callback,
    gfxd_tlut_callback,
    gfxd_vp_callback,
    gfxd_vtx_callback,
    gfxd_zimg_callback,
    GfxdEndian,
    gfxd_f3d,
    gfxd_f3db,
    gfxd_f3dex,
    gfxd_f3dexb,
    gfxd_f3dex2,
)

from ...util import log, options
from ...util.log import error

from ..common.codesubsegment import CommonSegCodeSubsegment

from ...util import symbols

if TYPE_CHECKING:
    from ...util.vram_classes import SerializedSegmentData

LIGHTS_RE = re.compile(r"\*\(Lightsn \*\)0x[0-9A-F]{8}")


class N64SegGfx(CommonSegCodeSubsegment):
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
        self.in_segment = not isinstance(yaml, dict) or yaml.get("in_segment", True)

    def format_sym_name(self, sym: symbols.Symbol) -> str:
        return sym.name

    def get_linker_section(self) -> str:
        return ".data"

    def out_path(self) -> Path:
        return options.opts.asset_path / self.dir / f"{self.name}.gfx.inc.c"

    def scan(self, rom_bytes: bytes) -> None:
        self.file_text = self.disassemble_data(rom_bytes)

    def get_gfxd_target(self) -> gfxd_f3d:
        opt = options.opts.gfx_ucode

        if opt == "f3d":
            return gfxd_f3d
        if opt == "f3db":
            return gfxd_f3db
        if opt == "f3dex":
            return gfxd_f3dex
        if opt == "f3dexb":
            return gfxd_f3dexb
        if opt == "f3dex2":
            return gfxd_f3dex2
        log.error(f"Unknown target {opt}")

    def tlut_handler(self, addr: int, idx: int, count: int) -> int:
        sym = self.create_symbol(
            addr=addr, in_segment=self.in_segment, type="data", reference=True
        )
        gfxd_printf(self.format_sym_name(sym))
        return 1

    def timg_handler(
        self, addr: int, fmt, size: int, width: int, height: int, pal
    ) -> int:
        sym = self.create_symbol(
            addr=addr, in_segment=self.in_segment, type="data", reference=True
        )
        gfxd_printf(self.format_sym_name(sym))
        return 1

    def cimg_handler(self, addr: int, fmt, size: int, width: int) -> int:
        sym = self.create_symbol(
            addr=addr, in_segment=self.in_segment, type="data", reference=True
        )
        gfxd_printf(self.format_sym_name(sym))
        return 1

    def zimg_handler(self, addr: int) -> int:
        sym = self.create_symbol(
            addr=addr, in_segment=self.in_segment, type="data", reference=True
        )
        gfxd_printf(self.format_sym_name(sym))
        return 1

    def dl_handler(self, addr: int) -> int:
        # Look for 'Gfx'-typed symbols first
        sym = self.retrieve_sym_type(symbols.all_symbols_dict, addr, "Gfx")

        if not sym:
            sym = self.create_symbol(
                addr=addr, in_segment=self.in_segment, type="data", reference=True
            )
        gfxd_printf(self.format_sym_name(sym))
        return 1

    def mtx_handler(self, addr: int) -> int:
        sym = self.create_symbol(
            addr=addr, in_segment=self.in_segment, type="data", reference=True
        )
        gfxd_printf(f"&{self.format_sym_name(sym)}")
        return 1

    def lookat_handler(self, addr: int, count: int) -> int:
        sym = self.create_symbol(
            addr=addr, in_segment=self.in_segment, type="data", reference=True
        )
        gfxd_printf(self.format_sym_name(sym))
        return 1

    def light_handler(self, addr: int, count: int) -> int:
        sym = self.create_symbol(
            addr=addr, in_segment=self.in_segment, type="data", reference=True
        )
        gfxd_printf(self.format_sym_name(sym))
        return 1

    def vtx_handler(self, addr: int, count: int) -> int:
        # Look for 'Vtx'-typed symbols first
        sym = self.retrieve_sym_type(symbols.all_symbols_dict, addr, "Vtx")

        if not sym:
            sym = self.create_symbol(
                addr=addr,
                in_segment=self.in_segment,
                type="Vtx",
                reference=True,
                search_ranges=True,
            )

        index = int((addr - sym.vram_start) / 0x10)
        gfxd_printf(f"&{self.format_sym_name(sym)}[{index}]")
        return 1

    def vp_handler(self, addr: int) -> int:
        sym = self.create_symbol(
            addr=addr, in_segment=self.in_segment, type="data", reference=True
        )
        gfxd_printf(f"&{self.format_sym_name(sym)}")
        return 1

    def macro_fn(self) -> int:
        gfxd_puts("    ")
        gfxd_macro_dflt()
        gfxd_puts(",\n")
        return 0

    def disassemble_data(self, rom_bytes: bytes) -> str:
        assert isinstance(self.rom_start, int)
        assert isinstance(self.rom_end, int)
        assert isinstance(self.vram_start, int)

        gfx_data = rom_bytes[self.rom_start : self.rom_end]
        segment_length = len(gfx_data)
        if (segment_length) % 8 != 0:
            error(
                f"Error: gfx segment {self.name} length ({segment_length}) is not a multiple of 8!"
            )

        out_str = "" if self.data_only else options.opts.generated_c_preamble + "\n\n"

        sym = self.create_symbol(
            addr=self.vram_start, in_segment=True, type="data", define=True
        )

        gfxd_input_buffer(gfx_data)

        # TODO terrible guess at the size we'll need - improve this
        outb = bytes([0] * segment_length * 100)
        outbuf = gfxd_output_buffer(outb, len(outb))

        gfxd_target(self.get_gfxd_target())
        gfxd_endian(
            GfxdEndian.big if options.opts.endianness == "big" else GfxdEndian.little, 4
        )

        # Callbacks
        gfxd_macro_fn(self.macro_fn)

        gfxd_tlut_callback(self.tlut_handler)
        gfxd_timg_callback(self.timg_handler)
        gfxd_cimg_callback(self.cimg_handler)
        gfxd_zimg_callback(self.zimg_handler)
        gfxd_dl_callback(self.dl_handler)
        gfxd_mtx_callback(self.mtx_handler)
        gfxd_lookat_callback(self.lookat_handler)
        gfxd_light_callback(self.light_handler)
        # gfxd_seg_callback ?
        gfxd_vtx_callback(self.vtx_handler)
        gfxd_vp_callback(self.vp_handler)
        # gfxd_uctext_callback ?
        # gfxd_ucdata_callback ?
        # gfxd_dram_callback ?

        gfxd_execute()

        if self.data_only:
            out_str += gfxd_buffer_to_string(outbuf)
        else:
            out_str += "Gfx " + self.format_sym_name(sym) + "[] = {\n"
            out_str += gfxd_buffer_to_string(outbuf)
            out_str += "};\n"

        # Poor man's light fix until we get my libgfxd PR merged
        def light_sub_func(match: re.Match[str]) -> str:
            light = match.group(0)
            addr = int(light[12:], 0)
            sym = self.create_symbol(
                addr=addr, in_segment=self.in_segment, type="data", reference=True
            )
            return self.format_sym_name(sym)

        out_str = re.sub(LIGHTS_RE, light_sub_func, out_str)

        return out_str

    def split(self, rom_bytes: bytes) -> None:
        out_path = self.out_path()
        if self.file_text and out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)

            with open(self.out_path(), "w", encoding="utf-8", newline="\n") as f:
                f.write(self.file_text)

    def should_scan(self) -> bool:
        return (
            options.opts.is_mode_active("gfx")
            and self.rom_start is not None
            and self.rom_end is not None
        )

    def should_split(self) -> bool:
        return self.extract and options.opts.is_mode_active("gfx")

    @staticmethod
    def estimate_size(yaml: SerializedSegmentData | list[str]) -> int | None:
        if isinstance(yaml, dict) and "length" in yaml:
            return int(yaml["length"]) * 0x10
        return None
