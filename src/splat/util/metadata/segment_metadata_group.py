from typing import Callable, TYPE_CHECKING

from .segment_metadata import SegmentMetadata, SegmentKind
from .parent_segment_info import ParentSegmentInfo
from .overlay_metadata import OverlayMetadata

from ..symbols import Symbol
from .. import log, options

# circular import
if TYPE_CHECKING:
    from ...segtypes.segment import Segment

class SegmentMetadataGroup:
    def __init__(self) -> None:
        self.user_segment: SegmentMetadata = SegmentMetadata(SegmentKind.UserSegment, "$user_segment", 0x0, 0x0, 0x00000000, 0xFFFFFFFF, prioritised_segments=list(), exclusive_ram_id=None)

        self.global_segments: list[SegmentMetadata] = list()

        self.overlay_segments: dict[str, OverlayMetadata] = dict()
        """key: exclusive_ram_id"""

        self.unknown_segment: SegmentMetadata = SegmentMetadata(SegmentKind.Unknown, "$unknown", 0x0, 0x0, 0x00000000, 0xFFFFFFFF, prioritised_segments=list(), exclusive_ram_id=None)

        # ?
        self.all_symbols: list[Symbol] = list()

    def find_owned_segment(self, info: ParentSegmentInfo) -> SegmentMetadata:
        if info.exclusive_ram_id is not None:
            segments_per_rom = self.overlay_segments.get(info.exclusive_ram_id)
            if segments_per_rom is not None:
                owned_segment = segments_per_rom.segments.get(info.segment_rom)
                if owned_segment is not None:
                    return owned_segment
        else:
            for owned_segment in self.global_segments:
                if owned_segment.in_rom_range(info.segment_rom):
                    return owned_segment
                elif owned_segment.in_vram_range(info.segment_vram):
                    # Global segment doesn't have overlapping issues, so it should
                    # be fine to check for vram address.
                    # This can be required by segments that only have bss sections.
                    return owned_segment

        # log.write(f"Error: Unable to find an owned segment for {info=}.", status="warn")
        return self.unknown_segment

    def find_referenced_segment_for_creation(self, vram: int, info: ParentSegmentInfo) -> SegmentMetadata:
        # First, check the global segments.
        # Overlays shouldn't overlap with the global segments, so this should be fine.
        for seg in self.global_segments:
            if seg.in_vram_range(vram):
                return seg

        # Look up in overlays
        if len(self.overlay_segments) > 0:
            overlay_segment = self._find_referenced_overlay_segment_for_creation(vram, info)
            if overlay_segment is not None:
                return overlay_segment

        # Fallback to the unknown segment
        return self.unknown_segment


    def _find_referenced_overlay_segment_for_creation(self, vram: int, info: ParentSegmentInfo) -> SegmentMetadata | None:
        # If the parent info has no exclusive_ram_id, then it is a global segment,
        # meaning it shouldn't be referencing an overlay symbol by default.
        if info.exclusive_ram_id is None:
            return None

        # Check the segment corresponding to this specific overlay.
        segments_per_rom = self.overlay_segments.get(info.exclusive_ram_id)
        if segments_per_rom is not None:
            owned_segment = segments_per_rom.segments.get(info.segment_rom)
            if owned_segment is not None:
                if owned_segment.in_vram_range(vram):
                    return owned_segment

                # Check for any prioiritised overlay, if any.
                for prioritised_segment in owned_segment.get_prioritised_segments():
                    for _ovl_cat, segments_per_rom in self.overlay_segments.items():
                        if not segments_per_rom.in_vram_range(vram):
                            continue
                        for _segment_rom, segment in segments_per_rom.segments.items():
                            if segment.name == prioritised_segment and segment.in_vram_range(vram):
                                return segment

        # Don't check other overlay segments here!
        # We don't have a way to know what segment this overlay is referencing,
        # picking an arbitrary one for symbol creation will lead to nasty bugs.

        return None


    def find_symbol_from_any_segment(
        self,
        vram: int,
        info: ParentSegmentInfo,
        allow_addend: bool,
        validate: Callable[[Symbol], bool]
    ) -> tuple[Symbol, SegmentMetadata] | None:
        sym = self.user_segment.find_symbol(vram, allow_addend)
        if sym is not None:
            return sym, self.user_segment

        for seg in self.global_segments:
            if seg.in_vram_range(vram):
                # If we find this vram is within a global segment then we can stop
                # searching, because we know this should be the only segment that
                # should overlap this segment.
                sym = seg.find_symbol(vram, allow_addend)
                if sym is not None and validate(sym):
                    return sym, seg
                return None

        if len(self.overlay_segments) > 0:
            sym = self._find_symbol_from_overlay_segments(vram, info, allow_addend, validate)
            if sym is not None:
                return sym

        sym = self.unknown_segment.find_symbol(vram, allow_addend)
        if sym is not None and validate(sym):
            return sym, self.unknown_segment
        return None

    def _find_symbol_from_overlay_segments(
        self,
        vram: int,
        info: ParentSegmentInfo,
        allow_addend: bool,
        validate: Callable[[Symbol], bool]
    ) -> tuple[Symbol, SegmentMetadata] | None:
        exclusive_ram_id = info.exclusive_ram_id

        # First, look up for the segment associated to this exclusive_ram_id
        # which matches the rom address of the parent segment so we can
        # prioritise it.
        if exclusive_ram_id is not None:
            segments_per_rom = self.overlay_segments.get(exclusive_ram_id)
            if segments_per_rom is not None:
                owned_segment = segments_per_rom.segments.get(info.segment_rom)
                if owned_segment is not None:
                    if owned_segment.in_vram_range(vram):
                        sym = owned_segment.find_symbol(vram, allow_addend)
                        if sym is not None and validate(sym):
                            return sym, owned_segment
                        return None

                    # Check for any prioiritised segment, if any.
                    for prioritised_segment in owned_segment.get_prioritised_segments():
                        for _ovl_cat, segments_per_rom in self.overlay_segments.items():
                            if not segments_per_rom.in_vram_range(vram):
                                continue
                            for _segment_rom, segment in segments_per_rom.segments.items():
                                if segment.name == prioritised_segment and segment.in_vram_range(vram):
                                    sym = segment.find_symbol(vram, allow_addend)
                                    if sym is not None and validate(sym):
                                        return sym, segment

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
                        return sym, segment

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
                        return sym, segment

        return None

    def _add_global_segment(
        self,
        name: str,
        rom_start: int,
        rom_end: int,
        vram_start: int,
        vram_end: int,
        prioritised_segments: list[str],
    ) -> SegmentMetadata:
        seg_meta = SegmentMetadata(SegmentKind.Global, name, rom_start, rom_end, vram_start, vram_end, prioritised_segments, None)
        self.global_segments.append(seg_meta)
        return seg_meta

    def _add_overlay_segment(
        self,
        exclusive_ram_id: str,
        name: str,
        rom_start: int,
        rom_end: int,
        vram_start: int,
        vram_end: int,
        prioritised_segments: list[str],
    ) -> SegmentMetadata:
        ovl_meta = self.overlay_segments.setdefault(exclusive_ram_id, OverlayMetadata(exclusive_ram_id, rom_start, rom_end, vram_start, vram_end, dict()))
        return ovl_meta.add_segment(
            name,
            rom_start,
            rom_end,
            vram_start,
            vram_end,
            prioritised_segments,
        )


metadata_group = SegmentMetadataGroup()

def initialize(all_segments: "list[Segment]", all_symbols: "list[Symbol]") -> None:
    global_rom_start = None
    global_rom_end = None
    global_vram_start = options.opts.global_vram_start
    global_vram_end = options.opts.global_vram_end
    seen_global_rom_start = None
    seen_global_rom_end = None
    seen_global_vram_start = None
    seen_global_vram_end = None
    overlay_segments: list[SegmentMetadata] = list()

    from ...segtypes.common.code import CommonSegCode

    global_segments_after_overlays: list[CommonSegCode] = []

    for segment in all_segments:
        if not isinstance(segment, CommonSegCode):
            # We only care about the VRAMs of code segments
            continue

        if segment.special_vram_segment:
            # Special segments which should not be accounted in the global VRAM calculation, like N64's IPL3
            continue

        if (
            not isinstance(segment.vram_start, int)
            or not isinstance(segment.vram_end, int)
            or not isinstance(segment.rom_start, int)
            or not isinstance(segment.rom_end, int)
        ):
            continue

        ram_id = segment.get_exclusive_ram_id()

        if ram_id is not None:
            if segment.vram_start != segment.vram_end:
                # Skip zero-sized segments.
                seg_meta = metadata_group._add_overlay_segment(
                    ram_id,
                    segment.name,
                    segment.rom_start,
                    segment.rom_end,
                    segment.vram_start,
                    segment.vram_end,
                    segment.prioritised_segments,
                )
                # Add the segment-specific symbols first
                for symbols_list in segment.seg_symbols.values():
                    for sym in symbols_list:
                        seg_meta.add_user_symbol(sym)

                overlay_segments.append(seg_meta)
        else:
            metadata_group._add_global_segment(
                segment.name,
                segment.rom_start,
                segment.rom_end,
                segment.vram_start,
                segment.vram_end,
                segment.prioritised_segments,
            )

            if global_rom_start is None or segment.rom_start < global_rom_start:
                global_rom_start = segment.rom_start

            if global_rom_end is None or global_rom_end < segment.rom_end:
                global_rom_end = segment.rom_end

            if global_vram_start is None or segment.vram_start < global_vram_start:
                global_vram_start = segment.vram_start

            if global_vram_end is None:
                global_vram_end = segment.vram_end
            elif global_vram_end < segment.vram_end:
                global_vram_end = segment.vram_end

                if len(overlay_segments) > 0:
                    # Global segment *after* overlay segments?
                    global_segments_after_overlays.append(segment)

            if seen_global_rom_start is None or segment.rom_start < seen_global_rom_start:
                seen_global_rom_start = segment.rom_start
            if seen_global_rom_end is None or seen_global_rom_end < segment.rom_end:
                seen_global_rom_end = segment.rom_end

            if seen_global_vram_start is None or segment.vram_start < seen_global_vram_start:
                seen_global_vram_start = segment.vram_start
            if seen_global_vram_end is None or seen_global_vram_end < segment.vram_end:
                seen_global_vram_end = segment.vram_end

    if (
        global_vram_start is not None
        and global_vram_end is not None
        and global_rom_start is not None
        and global_rom_end is not None
    ):
        if seen_global_vram_start is not None and seen_global_vram_end is not None and seen_global_rom_start is not None and seen_global_rom_end is not None:
            # Account for options.opts.global_vram_start and options.opts.global_vram_end for PSX and PSP
            if global_vram_start < seen_global_vram_start:
                metadata_group._add_global_segment(
                    segment.name,
                    seen_global_rom_start + global_vram_start - seen_global_vram_start,
                    seen_global_rom_start,
                    global_vram_start,
                    seen_global_vram_start,
                    [],
                )
            if global_vram_end > seen_global_vram_end:
                metadata_group._add_global_segment(
                    segment.name,
                    seen_global_rom_end,
                    seen_global_rom_end + global_vram_end - seen_global_vram_end,
                    seen_global_vram_end,
                    global_vram_end,
                    [],
                )

        overlaps_found = False
        # Check the vram range of the global segment does not overlap with any overlay segment
        for ovl_segment in overlay_segments:
            assert ovl_segment.vram_start <= ovl_segment.vram_end, (
                f"{ovl_segment.vram_start:08X} {ovl_segment.vram_end:08X}"
            )
            if (
                ovl_segment.vram_end > global_vram_start
                and global_vram_end > ovl_segment.vram_start
            ):
                log.write(
                    f"Error: the vram range ([0x{ovl_segment.vram_start:08X}, 0x{ovl_segment.vram_end:08X}]) of the non-global segment at rom address 0x{ovl_segment.rom_start:X} overlaps with the global vram range ([0x{global_vram_start:08X}, 0x{global_vram_end:08X}])",
                    status="warn",
                )
                overlaps_found = True
        if overlaps_found:
            log.write(
                "Many overlaps between non-global and global segments were found.",
            )
            log.write(
                "This is usually caused by missing `exclusive_ram_id` tags on segments that have a higher vram address than other `exclusive_ram_id`-tagged segments"
            )
            if len(global_segments_after_overlays) > 0:
                log.write(
                    "These segments are the main suspects for missing a `exclusive_ram_id` tag:",
                    status="warn",
                )
                for seg in global_segments_after_overlays:
                    log.write(f"    '{seg.name}', rom: 0x{seg.rom_start:06X}")
            else:
                log.write("No suspected segments??", status="warn")
            log.error("Stopping due to the above errors")

    # pass the global symbols to spimdisasm
    for segment in all_segments:
        if not isinstance(segment, CommonSegCode):
            # We only care about the VRAMs of code segments
            continue

        ram_id = segment.get_exclusive_ram_id()
        if ram_id is not None:
            continue

        for symbols_list in segment.seg_symbols.values():
            for sym in symbols_list:
                for seg in metadata_group.global_segments:
                    if seg.in_vram_range(sym.vram_start):
                        seg.add_user_symbol(sym)
                        break

    if global_vram_start and global_vram_end:
        # Pass global symbols to spimdisasm that are not part of any segment on the binary we are splitting (for psx and psp)
        for sym in all_symbols:
            if sym.segment is not None:
                # We already handled this symbol somewhere else
                continue

            if sym.vram_start < global_vram_start or sym.vram_end > global_vram_end:
                # Not global
                continue

            for seg in metadata_group.global_segments:
                if seg.in_vram_range(sym.vram_start):
                    seg.add_user_symbol(sym)
                    break

    for sym in all_symbols:
        if sym._added_to_meta:
            continue
        if sym.user_segment:
            metadata_group.user_segment.add_user_symbol(sym)

    lost_symbols = [f"{sym.name} (Vram: 0x{sym.vram_start:08X})" for sym in all_symbols if not sym._added_to_meta]
    if len(lost_symbols) > 0:
        log.write(
            "WARNING: Unable to determine a segment for the following user-declared symbols.\n"
            "  Try specifying the segment they belong to with 'segment:segment_name' in your symbol_addrs file.\n"
            "  If the address of this symbol is not part of any segment, or if you believe this symbol should be\n"
            "  globally visible and take priority over other symbol references then use the `user_segment:True`\n"
            "  user attribute instead.",
            status="warn",
        )
        log.write("    " + "\n    ".join(lost_symbols))
        log.write("\n")

    metadata_group.all_symbols = all_symbols

def reset() -> None:
    global metadata_group
    metadata_group = SegmentMetadataGroup()
