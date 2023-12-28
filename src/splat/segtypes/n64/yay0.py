import crunch64

from .decompressor import CommonSegDecompressor


class N64SegYay0(CommonSegDecompressor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def compression_type(self):
        return "Yay0"

    def decompress(self, compressed_bytes: bytes) -> bytes:
        return crunch64.yay0.decompress(compressed_bytes)
