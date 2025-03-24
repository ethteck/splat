from pathlib import Path

from .asm import CommonSegAsm

from ...util import options


class CommonSegHasm(CommonSegAsm):
    def asm_out_path(self) -> Path:
        if options.opts.hasm_in_src_path:
            return options.opts.src_path / self.dir / f"{self.name}.s"

        return super().asm_out_path()

    def scan(self, rom_bytes: bytes):
        if (
            self.rom_start is not None
            and self.rom_end is not None
            and self.rom_start != self.rom_end
        ):
            self.scan_code(rom_bytes, is_hasm=True)

    def split(self, rom_bytes: bytes):
        if self.rom_start == self.rom_end:
            return

        out_path = self.out_path()
        if out_path and not out_path.exists():
            self.split_as_asm_file(out_path)
