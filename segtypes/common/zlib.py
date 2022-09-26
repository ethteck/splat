import zlib

from segtypes.common.code import CommonSegCode


class CommonSegZlib(CommonSegCode):
    @staticmethod
    def decompressZlib(data: bytes) -> bytearray:
        decomp = zlib.decompressobj(-zlib.MAX_WBITS)
        output = bytearray()
        output.extend(decomp.decompress(data))
        while decomp.unconsumed_tail:
            output.extend(decomp.decompress(decomp.unconsumed_tail))
        output.extend(decomp.flush())
        return output

    def scan(self, rom_bytes: bytes):
        if (
            self.rom_start is not None
            and self.rom_end is not None
            and self.rom_start != self.rom_end
        ):
            super().scan(CommonSegZlib.decompressZlib(rom_bytes[self.rom_start:self.rom_end]))
