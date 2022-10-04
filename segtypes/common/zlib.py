import zlib

from segtypes.common.compressedsegment import CommonSegCompressedSegment

class CommonSegZlib(CommonSegCompressedSegment):
    @staticmethod
    def decompressZlib(data: bytes) -> bytearray:
        decomp = zlib.decompressobj(-zlib.MAX_WBITS)
        output = bytearray()
        output.extend(decomp.decompress(data))
        while decomp.unconsumed_tail:
            output.extend(decomp.decompress(decomp.unconsumed_tail))
        output.extend(decomp.flush())
        return output

    def decompress_bytes(self, rom_bytes: bytes) -> bytearray:
        return CommonSegZlib.decompressZlib(rom_bytes[self.rom_start:self.rom_end])
