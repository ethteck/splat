import crunch64

from .decompressor import CommonSegDecompressor


class N64SegMio0(CommonSegDecompressor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def compression_type(self):
        return "MIO0"

    def decompress(self, compressed_bytes: bytes) -> bytes:
        return crunch64.mio0.decompress(compressed_bytes)
