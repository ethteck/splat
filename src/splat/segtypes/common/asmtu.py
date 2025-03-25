from .asm import CommonSegAsm


class CommonSegAsmtu(CommonSegAsm):
    def split(self, rom_bytes: bytes):
        if self.rom_start == self.rom_end:
            return

        if self.spim_section is None:
            return

        out_path = self.out_path()
        assert out_path is not None, str(self)

        self.split_as_asmtu_file(out_path)
