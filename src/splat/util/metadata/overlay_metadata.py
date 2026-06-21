import dataclasses

from .segment_metadata import SegmentMetadata, SegmentKind

from .. import log


@dataclasses.dataclass
class OverlayMetadata:
    """
    A group of overlays that share the same `exclusive_ram_id`.
    """

    exclusive_ram_id: str

    # Ranges covering all the overlays for this `exclusive_ram_id`.
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

    def add_segment(
        self,
        name: str,
        rom_start: int,
        rom_end: int,
        vram_start: int,
        vram_end: int,
        prioritized_segments: list[str],
    ) -> SegmentMetadata:
        old_segment = self.segments.get(rom_start)
        if old_segment is not None:
            log.error(
                f"Tried to create an overlay at a duplicated rom address {rom_start} for exclusive_ram_id={self.exclusive_ram_id}.\n"
                f"  Old segment '{old_segment.name}'. Rom 0x{old_segment.rom_start:08X}~0x{old_segment.rom_end:08X}. Vram 0x{old_segment.vram_start:08X}~0x{old_segment.vram_start:08X}\n"
                f"  New segment '{name}'. Rom 0x{rom_start:08X}~0x{rom_end:08X}. Vram 0x{vram_start:08X}~0x{vram_start:08X}\n"
            )

        self.rom_start = min(self.rom_start, rom_start)
        self.rom_end = max(self.rom_end, rom_end)
        self.vram_start = min(self.vram_start, vram_start)
        self.vram_end = max(self.vram_end, vram_end)

        seg = SegmentMetadata(
            SegmentKind.Overlay,
            name,
            rom_start,
            rom_end,
            vram_start,
            vram_end,
            prioritized_segments,
            self.exclusive_ram_id,
        )
        self.segments[rom_start] = seg
        return seg
