"""
N64 f3dex display list splitter
Dumps out Gfx[] as a .inc.c file.
"""

from pathlib import Path
from pygfxd import *
from util.log import error

from util import options
from segtypes.common.codesubsegment import CommonSegCodeSubsegment


class N64SegGfx(CommonSegCodeSubsegment):
    def __init__(
        self,
        rom_start,
        rom_end,
        type,
        name,
        vram_start,
        extract,
        given_subalign,
        exclusive_ram_id,
        bss_size: int,
        given_dir,
        symbol_name_format,
        symbol_name_format_no_rom,
        args,
        yaml,
    ):
        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            extract,
            given_subalign,
            exclusive_ram_id=exclusive_ram_id,
            bss_size=bss_size,
            given_dir=given_dir,
            symbol_name_format=symbol_name_format,
            symbol_name_format_no_rom=symbol_name_format_no_rom,
            args=args,
            yaml=yaml,
        )
        self.file_text = None

    def get_linker_section(self) -> str:
        return ".data"

    def out_path(self) -> Path:
        return options.get_asset_path() / self.dir / f"{self.name}.gfx.inc.c"

    def scan(self, rom_bytes: bytes):
        self.file_text = self.disassemble_data(rom_bytes)

    def disassemble_data(self, rom_bytes):
        def macro_fn():
            gfxd_puts("    ")
            gfxd_macro_dflt()
            gfxd_puts(",\n")
            return 0

        gfx_data = rom_bytes[self.rom_start : self.rom_end]
        segment_length = len(gfx_data)
        if (segment_length) % 8 != 0:
            error(
                f"Error: gfx segment {self.name} length ({segment_length}) is not a multiple of 8!"
            )

        out_str = options.get_generated_c_premble() + "\n\n"

        sym = self.get_most_parent().get_symbol(
            addr=self.vram_start, type="data", create=True, define=True
        )

        outb = bytes([0] * 4096)
        gfxd_input_buffer(gfx_data)
        outbuf = gfxd_output_buffer(outb, len(outb))
        gfxd_target(gfxd_f3dex2)
        gfxd_endian(
            GfxdEndian.big if options.get_endianess() == "big" else GfxdEndian.little, 4
        )

        # Callbacks
        gfxd_macro_fn(macro_fn)
        # TODO add callbacks for macros that can use symbols

        gfxd_execute()
        out_str += "Gfx " + sym.name + "[] = {\n"
        out_str += gfxd_buffer_to_string(outbuf)
        out_str += "};\n"
        return out_str

    def split(self, rom_bytes: bytes):
        if self.file_text and self.out_path():
            self.out_path().parent.mkdir(parents=True, exist_ok=True)

            with open(self.out_path(), "w", newline="\n") as f:
                f.write(self.file_text)

    def should_scan(self) -> bool:
        return (
            options.mode_active("gfx")
            and self.rom_start != "auto"
            and self.rom_end != "auto"
        )

    def should_split(self) -> bool:
        return self.extract and options.mode_active("gfx")
