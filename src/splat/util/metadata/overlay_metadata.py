import dataclasses

from .segment_metadata import SegmentMetadata

@dataclasses.dataclass
class OverlayMetadata:
    exclusive_ram_id: str | None

    rom_start: int
    rom_end: int
    vram_start: int
    vram_end: int

    segments: dict[int, SegmentMetadata]
    """key: rom address"""

    def in_rom_range(self, rom: int) -> bool:
        if rom < self.rom_start:
            return False
        if rom >= self.rom_end:
            return False
        return True

    def in_vram_range(self, vram: int) -> bool:
        if vram < self.vram_start:
            return False
        if vram >= self.vram_end:
            return False
        return True
