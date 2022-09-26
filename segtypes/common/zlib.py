import zlib
from typing import Optional
from util import log

from segtypes.common.code import CommonSegCode


class CommonSegZlib(CommonSegCode):
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
        given_dir,
        symbol_name_format,
        symbol_name_format_no_rom,
        args,
        yaml,
    ):
        self.decompressed_size: int = yaml.get("decompressed_size", 0) if isinstance(yaml, dict) else 0
        if self.decompressed_size <= 0:
            log.error(f"segment {type} requires an 'decompressed_size' option")

        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            extract,
            given_subalign,
            exclusive_ram_id=exclusive_ram_id,
            given_dir=given_dir,
            symbol_name_format=symbol_name_format,
            symbol_name_format_no_rom=symbol_name_format_no_rom,
            args=args,
            yaml=yaml,
        )

    @property
    def vram_end(self) -> Optional[int]:
        if self.vram_start is not None and self.size is not None:
            return self.vram_start + self.decompressed_size + self.bss_size
        else:
            return None

    def contains_rom(self, rom: int) -> bool:
        return rom >= 0 and rom < self.decompressed_size

    def rom_to_ram(self, rom_addr: int) -> Optional[int]:
        if not self.contains_rom(rom_addr) and rom_addr != self.decompressed_size:
            return None

        if self.vram_start is not None:
            return self.vram_start + rom_addr
        else:
            return None

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
            decompressed_bytes = CommonSegZlib.decompressZlib(rom_bytes[self.rom_start:self.rom_end])
            if len(decompressed_bytes) != self.decompressed_size:
                log.error(f"Specified 'decompressed_size' option does not match the size of the actual decompressed buffer. Option was '0x{self.decompressed_size:X}', but actual size is 0x{len(decompressed_bytes):X}")
            super().scan(decompressed_bytes)
