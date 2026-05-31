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
        self.global_segment: SegmentMetadata = SegmentMetadata(SegmentKind.Global, "$global", 0x0, 0x1000, 0x80000000, 0x80001000, exclusive_ram_id=None)

        self.overlay_segments: dict[str, OverlayMetadata] = dict()
        """key: exclusive_ram_id"""

        self.unknown_segment: SegmentMetadata = SegmentMetadata(SegmentKind.Unknown, "$unknown", 0x0, 0x0, 0x00000000, 0xFFFFFFFF, exclusive_ram_id=None)

        self.all_symbols: list[Symbol] = list()

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

    def _add_overlay_segment(
        self,
        exclusive_ram_id: str,
        name: str,
        rom_start: int,
        rom_end: int,
        vram_start: int,
        vram_end: int,
    ) -> SegmentMetadata:
        ovl_meta = self.overlay_segments.setdefault(exclusive_ram_id, OverlayMetadata(exclusive_ram_id, rom_start, rom_end, vram_start, vram_end, dict()))
        return ovl_meta.add_segment(
            name,
            rom_start,
            rom_end,
            vram_start,
            vram_end,
        )


metadata_group = SegmentMetadataGroup()

def initialize(all_segments: "list[Segment]", all_symbols: "list[Symbol]") -> None:
    global_rom_start = None
    global_rom_end = None
    global_vram_start = options.opts.global_vram_start
    global_vram_end = options.opts.global_vram_end
    # overlay_segments: set[spimdisasm.common.SymbolsSegment] = set()
    overlay_segments: list[SegmentMetadata] = list()

    # spim_context.bannedSymbols |= ignored_addresses

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
                )
                # Add the segment-specific symbols first
                for symbols_list in segment.seg_symbols.values():
                    for sym in symbols_list:
                        seg_meta.add_user_symbol(sym)

                overlay_segments.append(seg_meta)
        else:
            if global_vram_start is None:
                global_vram_start = segment.vram_start
            elif segment.vram_start < global_vram_start:
                global_vram_start = segment.vram_start

            if global_vram_end is None:
                global_vram_end = segment.vram_end
            elif global_vram_end < segment.vram_end:
                global_vram_end = segment.vram_end

                if len(overlay_segments) > 0:
                    # Global segment *after* overlay segments?
                    global_segments_after_overlays.append(segment)

            if global_rom_start is None:
                global_rom_start = segment.rom_start
            elif segment.rom_start < global_rom_start:
                global_rom_start = segment.rom_start

            if global_rom_end is None:
                global_rom_end = segment.rom_end
            elif global_rom_end < segment.rom_end:
                global_rom_end = segment.rom_end


    if (
        global_vram_start is not None
        and global_vram_end is not None
        and global_rom_start is not None
        and global_rom_end is not None
    ):
        metadata_group.global_segment.rom_start = global_rom_start
        metadata_group.global_segment.rom_end = global_rom_end
        metadata_group.global_segment.vram_start = global_vram_start
        metadata_group.global_segment.vram_end = global_vram_end

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
                metadata_group.global_segment.add_user_symbol(sym)

    if global_vram_start and global_vram_end:
        # Pass global symbols to spimdisasm that are not part of any segment on the binary we are splitting (for psx and psp)
        for sym in all_symbols:
            if sym.segment is not None:
                # We already handled this symbol somewhere else
                continue

            if sym.vram_start < global_vram_start or sym.vram_end > global_vram_end:
                # Not global
                continue

            metadata_group.global_segment.add_user_symbol(sym)

    lost_symbols = [f"{sym.name} (Vram: 0x{sym.vram_start:08X})" for sym in all_symbols if not sym._added_to_meta]
    if len(lost_symbols) > 0:
        log.write("WARNING: Unable to determine a segment for the following user-declared symbols:", status="warn")
        log.write("    " + "\n    ".join(lost_symbols))
        log.write("\n")

    metadata_group.all_symbols = all_symbols

def reset() -> None:
    global metadata_group
    metadata_group = SegmentMetadataGroup()
