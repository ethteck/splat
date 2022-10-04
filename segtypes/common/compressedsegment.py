import zlib
from typing import Optional
from util import log

from segtypes.common.code import CommonSegCode


class CommonSegCompressedSegment(CommonSegCode):
    def __init__(
        self,
        rom_start,
        rom_end,
        type,
        name,
        vram_start,
        args,
        yaml,
    ):
        self._decompressed_size: int = 0
        if isinstance(yaml, dict):
            self._decompressed_size = yaml.get("decompressed_size", 0)

        if self.decompressed_size <= 0:
            log.error(f"segment {type} requires an 'decompressed_size' option")

        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            args=args,
            yaml=yaml,
        )

    @property
    def decompressed_size(self) -> int:
        return self._decompressed_size

    def contains_rom(self, rom: int) -> bool:
        return rom >= 0 and rom < self.decompressed_size

    def rom_to_ram(self, rom_addr: int) -> Optional[int]:
        if not self.contains_rom(rom_addr) and rom_addr != self.decompressed_size:
            return None

        if self.vram_start is not None:
            return self.vram_start + rom_addr
        else:
            return None

    def decompress_bytes(self, rom_bytes: bytes) -> bytearray:
        log.error("decompress_bytes member should be overriden by subclass")

    def scan(self, rom_bytes: bytes):
        if (
            self.rom_start is not None
            and self.rom_end is not None
            and self.rom_start != self.rom_end
        ):
            decompressed_bytes = self.decompress_bytes(rom_bytes)
            if len(decompressed_bytes) != self.decompressed_size:
                log.error(
                    f"Specified 'decompressed_size' option does not match the size of the actual decompressed buffer. Option was '0x{self.decompressed_size:X}', but actual size is 0x{len(decompressed_bytes):X}"
                )
            super().scan(decompressed_bytes)
