from util.n64.Mio0decompress import Mio0Decompressor

from segtypes.common.decompressor import CommonSegDecompressor


class N64SegMio0(CommonSegDecompressor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.decompressor = Mio0Decompressor()

    @property
    def compression_type(self):
        return "MIO0"

    def decompress(self, compressed_bytes: bytes) -> bytes:
        return self.decompressor.decompress(compressed_bytes)
