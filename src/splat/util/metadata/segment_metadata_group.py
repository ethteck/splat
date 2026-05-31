import dataclasses
from typing import Callable

from .segment_metadata import SegmentMetadata
from .parent_segment_info import ParentSegmentInfo
from .overlay_metadata import OverlayMetadata

from ..symbols import Symbol
from .. import log

@dataclasses.dataclass
class SegmentMetadataGroup:
    global_segment: SegmentMetadata

    overlay_segments: dict[str, OverlayMetadata]
    """key: exclusive_ram_id"""

    unknown_segment: SegmentMetadata

    def find_owned_segment(self, info: ParentSegmentInfo) -> SegmentMetadata:
        if info.exclusive_ram_id is not None:
            segments_per_rom = self.overlay_segments.get(info.exclusive_ram_id)
            if segments_per_rom is not None:
                owned_segment = segments_per_rom.segments.get(info.segment_rom)
                if owned_segment is not None:
                    return owned_segment
        else:
            if self.global_segment.in_rom_range(info.segment_rom):
                return self.global_segment
            elif self.global_segment.in_vram_range(info.segment_vram):
                # Global segment doesn't have overlapping issues, so it should
                # be fine to check for vram address.
                # This can be required by segments that only have bss sections.
                return self.global_segment

        log.error(f"Unable to find an owned segment for {info=}")

    def find_referenced_segment(self, vram: int, info: ParentSegmentInfo) -> SegmentMetadata:
        # First check the global segment.
        # Overlays shouldn't overlap with the global segment, so this should be fine.
        if self.global_segment.in_vram_range(vram):
            return self.global_segment

        # Look up in overlays
        if len(self.overlay_segments) > 0:
            overlay_segment = self._find_referenced_overlay_segment(vram, info)
            if overlay_segment is not None:
                return overlay_segment

        # Fallback to the unknown segment
        return self.unknown_segment


    def _find_referenced_overlay_segment(self, vram: int, info: ParentSegmentInfo) -> SegmentMetadata | None:
        if info.exclusive_ram_id is None:
            return None

        segments_per_rom = self.overlay_segments.get(info.exclusive_ram_id)
        if segments_per_rom is not None:
            owned_segment = segments_per_rom.segments.get(info.segment_rom)
            if owned_segment is not None and owned_segment.in_vram_range(vram):
                return owned_segment

        return None


    def find_symbol_from_any_segment(
        self,
        vram: int,
        info: ParentSegmentInfo,
        allow_addend: bool,
        validate: Callable[[Symbol], bool]
    ) -> Symbol | None:
        if self.global_segment.in_vram_range(vram):
            # If we find this vram is within a global segment then we can stop
            # searching, because we know this should be the only segment that
            # should overlap this segment.
            sym = self.global_segment.find_symbol(vram, allow_addend)
            if sym is not None and validate(sym):
                return sym
            return None

        if len(self.overlay_segments) > 0:
            sym = self._find_symbol_from_overlay_segments(vram, info, allow_addend, validate)
            if sym is not None:
                return sym

        sym = self.unknown_segment.find_symbol(vram, allow_addend)
        if sym is not None and validate(sym):
            return sym
        return None

    def _find_symbol_from_overlay_segments(
        self,
        vram: int,
        info: ParentSegmentInfo,
        allow_addend: bool,
        validate: Callable[[Symbol], bool]
    ) -> Symbol | None:
        exclusive_ram_id = info.exclusive_ram_id

        # First, look up for the segment associated to this exclusive_ram_id
        # which matches the rom address of the parent segment so we can
        # prioritize it.
        if exclusive_ram_id is not None:
            segments_per_rom = self.overlay_segments.get(exclusive_ram_id)
            if segments_per_rom is not None:
                owned_segment = segments_per_rom.segments.get(info.segment_rom)
                if owned_segment is not None:
                    if owned_segment.in_vram_range(vram):
                        sym = owned_segment.find_symbol(vram, allow_addend)
                        if sym is not None and validate(sym):
                            return sym
                        return None

        # If not found, then we should check every exclusive_ram_id except the
        # one associated with the parent segment.

        # First, we look for exclusive_ram_id that contain a single segment.
        # This way is less likely we grab the wrong symbol.
        for ovl_id, segments_per_rom in self.overlay_segments.items():
            if exclusive_ram_id == ovl_id:
                continue
            if not segments_per_rom.in_vram_range(vram):
                continue

            if len(segments_per_rom.segments) != 1:
                continue

            for _, segment in segments_per_rom.segments.items():
                if segment.in_vram_range(vram):
                    sym = segment.find_symbol(vram, allow_addend)
                    if sym is not None and validate(sym):
                        return sym

        # if we haven't found the symbol yet, then just look up everywhere else.
        for ovl_id, segments_per_rom in self.overlay_segments.items():
            if exclusive_ram_id == ovl_id:
                continue
            if not segments_per_rom.in_vram_range(vram):
                continue

            if len(segments_per_rom.segments) == 1:
                continue

            for _, segment in segments_per_rom.segments.items():
                if segment.in_vram_range(vram):
                    sym = segment.find_symbol(vram, allow_addend)
                    if sym is not None and validate(sym):
                        return sym

        return None
