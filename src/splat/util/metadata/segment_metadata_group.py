from typing import Callable, Dict, Optional, Set, Tuple, TYPE_CHECKING

from .segment_metadata import SegmentMetadata, SegmentKind
from .parent_segment_info import ParentSegmentInfo
from .overlay_metadata import OverlayMetadata

from ..symbols import Symbol
from .. import log, options

# circular import
if TYPE_CHECKING:
    from ...segtypes.segment import Segment


class SegmentMetadataGroup:
    """
    Grouping for all segment metadatas.
    """

    def __init__(self) -> None:
        # User-declared symbols that do not belong to any other segment.
        self.absolute_segment: SegmentMetadata = SegmentMetadata(
            SegmentKind.Absolute,
            "$absolute",
            0x0,
            0x0,
            0x00000000,
            0xFFFFFFFF,
            prioritized_segments=list(),
            exclusive_ram_id=None,
        )

        # Globally visible segments.
        # They have no address overlapping issues with other segments.
        self.global_segments: list[SegmentMetadata] = list()

        # Overlays.
        # They have address overlapping between them.
        self.overlay_segments: dict[str, OverlayMetadata] = dict()
        """key: exclusive_ram_id"""

        # Dumpster for failed segment lookups.
        self.unknown_segment: SegmentMetadata = SegmentMetadata(
            SegmentKind.Unknown,
            "$unknown",
            0x0,
            0x0,
            0x00000000,
            0xFFFFFFFF,
            prioritized_segments=list(),
            exclusive_ram_id=None,
        )

        # ?
        self.all_symbols: list[Symbol] = list()

        self.global_rom_start: Optional[int] = None
        self.global_rom_end: Optional[int] = None
        self.global_vram_start: Optional[int] = None
        self.global_vram_end: Optional[int] = None

    def find_owned_segment(self, info: ParentSegmentInfo) -> SegmentMetadata:
        """
        Find the segment metadata corresponding to the given segment parent info.
        """

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

    def find_referenced_segment_for_creation(
        self,
        vram: int,
        info: ParentSegmentInfo,
    ) -> SegmentMetadata:
        """
        Find a segment where a symbol with the given address could be created.

        For overlays, this will return either only the owned overlay segment or
        a prioritized segment for the given overlay that matches the vram address.
        """

        # First, check the global segments.
        # Overlays shouldn't overlap with the global segments, so this should be fine.
        for seg in self.global_segments:
            if seg.in_vram_range(vram):
                return seg

        # Look up in overlays
        if len(self.overlay_segments) > 0:
            overlay_segment = self._find_referenced_overlay_segment_for_creation(
                vram,
                info,
            )
            if overlay_segment is not None:
                return overlay_segment

        # Fallback to the unknown segment
        return self.unknown_segment

    def _find_referenced_overlay_segment_for_creation(
        self,
        vram: int,
        info: ParentSegmentInfo,
    ) -> Optional[SegmentMetadata]:
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
                segment = self._find_prioritsed_segment(vram, owned_segment)
                if segment is not None:
                    return segment

        # Don't check other overlay segments here!
        # We don't have a way to know what segment this overlay is referencing,
        # picking an arbitrary one for symbol creation will lead to nasty bugs.

        return None

    def _find_prioritsed_segment(
        self,
        vram: int,
        owned_segment: SegmentMetadata,
    ) -> Optional[SegmentMetadata]:
        for prioritized_segment in owned_segment.get_prioritized_segments():
            for _ovl_cat, segments_per_rom in self.overlay_segments.items():
                if not segments_per_rom.in_vram_range(vram):
                    continue
                for _segment_rom, segment in segments_per_rom.segments.items():
                    if segment.name == prioritized_segment and segment.in_vram_range(
                        vram
                    ):
                        return segment
        return None

    def find_symbol_from_any_segment(
        self,
        vram: int,
        info: ParentSegmentInfo,
        allow_addend: bool,
        validate: Callable[[Symbol], bool],
    ) -> Optional[tuple[Symbol, SegmentMetadata]]:
        """
        Check all segments looking for a symbol matching the given address.

        Applies visibility rules based on the segment for `info`.

        The symbol will be checked against the `validate` callback,
        if the callback returns `False` then the next segment will be checked
        and so on.
        """

        sym = self.absolute_segment.find_symbol(vram, allow_addend)
        if sym is not None:
            return sym, self.absolute_segment

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
            aux = self._find_symbol_from_overlay_segments(
                vram,
                info,
                allow_addend,
                validate,
            )
            if aux is not None:
                return aux

        sym = self.unknown_segment.find_symbol(vram, allow_addend)
        if sym is not None and validate(sym):
            return sym, self.unknown_segment
        return None

    def _find_symbol_from_overlay_segments(
        self,
        vram: int,
        info: ParentSegmentInfo,
        allow_addend: bool,
        validate: Callable[[Symbol], bool],
    ) -> Optional[tuple[Symbol, SegmentMetadata]]:
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
                            return sym, owned_segment
                        return None

                    # Check for prioritized segments, if any.
                    aux = self._find_symbol_from_prioritized_segments(
                        vram,
                        allow_addend,
                        owned_segment,
                        validate,
                    )
                    if aux is not None:
                        return aux

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

    def _find_symbol_from_prioritized_segments(
        self,
        vram: int,
        allow_addend: bool,
        owned_segment: SegmentMetadata,
        validate: Callable[[Symbol], bool],
    ) -> Optional[tuple[Symbol, SegmentMetadata]]:
        for prioritized_segment in owned_segment.get_prioritized_segments():
            for _ovl_cat, segments_per_rom in self.overlay_segments.items():
                if not segments_per_rom.in_vram_range(vram):
                    continue
                for _segment_rom, segment in segments_per_rom.segments.items():
                    if segment.name == prioritized_segment and segment.in_vram_range(
                        vram
                    ):
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
        prioritized_segments: list[str],
    ) -> SegmentMetadata:
        if self.global_rom_start is None or rom_start < self.global_rom_start:
            self.global_rom_start = rom_start
        if self.global_rom_end is None or self.global_rom_end < rom_end:
            self.global_rom_end = rom_end
        if self.global_vram_start is None or vram_start < self.global_vram_start:
            self.global_vram_start = vram_start
        if self.global_vram_end is None or self.global_vram_end < vram_end:
            self.global_vram_end = vram_end

        seg_meta = SegmentMetadata(
            SegmentKind.Global,
            name,
            rom_start,
            rom_end,
            vram_start,
            vram_end,
            prioritized_segments,
            None,
        )
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
        prioritized_segments: list[str],
    ) -> SegmentMetadata:
        ovl_meta = self.overlay_segments.setdefault(
            exclusive_ram_id,
            OverlayMetadata(
                exclusive_ram_id, rom_start, rom_end, vram_start, vram_end, dict()
            ),
        )
        return ovl_meta.add_segment(
            name,
            rom_start,
            rom_end,
            vram_start,
            vram_end,
            prioritized_segments,
        )

    def _initialize_segments(
        self,
        all_segments: "list[Segment]",
    ) -> Tuple[Dict[str, SegmentMetadata], Set[str]]:
        global_rom_start: Optional[int] = None
        global_rom_end: Optional[int] = None
        global_vram_start: Optional[int] = options.opts.global_vram_start
        global_vram_end: Optional[int] = options.opts.global_vram_end
        last_global_segment: Optional[Segment] = None

        seen_global_rom_start: Optional[int] = None
        seen_global_rom_end: Optional[int] = None
        seen_global_vram_start: Optional[int] = None
        seen_global_vram_end: Optional[int] = None
        overlay_segments: list[SegmentMetadata] = list()

        segments_by_name: Dict[str, SegmentMetadata] = dict()
        skipped_segments: Set[str] = set()

        global_segments_after_overlays: list[Segment] = []

        # Create all segments in the grouping
        for segment in all_segments:
            if (
                not isinstance(segment.vram_start, int)
                or not isinstance(segment.vram_end, int)
                or not isinstance(segment.rom_start, int)
                or not isinstance(segment.rom_end, int)
            ):
                skipped_segments.add(segment.name)
                continue

            ram_id = segment.get_exclusive_ram_id()
            if ram_id is None and segment.special_vram_segment:
                # Special segments which should not be accounted in the global VRAM calculation, like N64's IPL3
                ram_id = "$special_vram_segment"

            if ram_id is not None:
                # Overlay

                if segment.vram_start == segment.vram_end:
                    # Skip zero-sized segments.
                    continue

                seg_meta = self._add_overlay_segment(
                    ram_id,
                    segment.name,
                    segment.rom_start,
                    segment.rom_end,
                    segment.vram_start,
                    segment.vram_end,
                    segment.prioritized_segments,
                )
                segment.owned_metadata = seg_meta
                overlay_segments.append(seg_meta)
                segments_by_name[seg_meta.name] = seg_meta
            else:
                # Global segment

                seg_meta = self._add_global_segment(
                    segment.name,
                    segment.rom_start,
                    segment.rom_end,
                    segment.vram_start,
                    segment.vram_end,
                    segment.prioritized_segments,
                )
                segment.owned_metadata = seg_meta
                segments_by_name[seg_meta.name] = seg_meta

                if global_rom_start is None or segment.rom_start < global_rom_start:
                    global_rom_start = segment.rom_start

                if global_rom_end is None or global_rom_end < segment.rom_end:
                    global_rom_end = segment.rom_end

                if global_vram_start is None or segment.vram_start < global_vram_start:
                    global_vram_start = segment.vram_start

                if global_vram_end is None:
                    global_vram_end = segment.vram_end
                    last_global_segment = segment
                elif global_vram_end < segment.vram_end:
                    global_vram_end = segment.vram_end
                    last_global_segment = segment

                    if len(overlay_segments) > 0:
                        # Global segment *after* overlay segments?
                        global_segments_after_overlays.append(segment)

                if (
                    seen_global_rom_start is None
                    or segment.rom_start < seen_global_rom_start
                ):
                    seen_global_rom_start = segment.rom_start
                if seen_global_rom_end is None or seen_global_rom_end < segment.rom_end:
                    seen_global_rom_end = segment.rom_end

                if (
                    seen_global_vram_start is None
                    or segment.vram_start < seen_global_vram_start
                ):
                    seen_global_vram_start = segment.vram_start
                if (
                    seen_global_vram_end is None
                    or seen_global_vram_end < segment.vram_end
                ):
                    seen_global_vram_end = segment.vram_end

        if (
            global_vram_start is not None
            and global_vram_end is not None
            and global_rom_start is not None
            and global_rom_end is not None
        ):
            # Create extra global segments in case they are needed
            if (
                seen_global_vram_start is not None
                and seen_global_vram_end is not None
                and seen_global_rom_start is not None
                and seen_global_rom_end is not None
            ):
                # Account for options.opts.global_vram_start and options.opts.global_vram_end for PSX and PSP
                if global_vram_start < seen_global_vram_start:
                    rom_start = (
                        seen_global_rom_start
                        + global_vram_start
                        - seen_global_vram_start
                    )
                    seg_meta = self._add_global_segment(
                        "$global_left",
                        rom_start,
                        seen_global_rom_start,
                        global_vram_start,
                        seen_global_vram_start,
                        [],
                    )
                    segments_by_name[seg_meta.name] = seg_meta
                if global_vram_end > seen_global_vram_end:
                    rom_end = (
                        seen_global_rom_end + global_vram_end - seen_global_vram_end
                    )
                    seg_meta = self._add_global_segment(
                        "$global_right",
                        seen_global_rom_end,
                        rom_end,
                        seen_global_vram_end,
                        global_vram_end,
                        [],
                    )
                    segments_by_name[seg_meta.name] = seg_meta

            # Validation

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
                        f"Error: Segment {ovl_segment.name} with vram range ([0x{ovl_segment.vram_start:08X}, 0x{ovl_segment.vram_end:08X}]) of the non-global segment at rom address 0x{ovl_segment.rom_start:X} overlaps with the global vram range ([0x{global_vram_start:08X}, 0x{global_vram_end:08X}])",
                        status="warn",
                    )
                    overlaps_found = True
            if overlaps_found:
                log.write(
                    "Overlaps between non-global and global segments were found.\n"
                    "This is usually caused by missing `exclusive_ram_id` tags on segments that have a higher vram address than other `exclusive_ram_id`-tagged segments"
                )
                if last_global_segment is not None:
                    log.write(
                        f"The last global segment seen is {last_global_segment}. Rom: 0x{last_global_segment.rom_start:X}, Vram: 0x{last_global_segment.vram_start:08X}"
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

        return segments_by_name, skipped_segments

    def _initialize_symbols(
        self,
        all_symbols: "list[Symbol]",
        segments_by_name: Dict[str, SegmentMetadata],
        skipped_segments: Set[str],
    ) -> None:
        # Pass every symbol to its corresponding segment.
        lost_symbols = []
        for sym in all_symbols:
            # User segment takes priority over everything
            if sym.absolute:
                self.absolute_segment.add_user_symbol(sym)
                continue

            # Then look up for explicit associated segments first.
            if sym.segment is not None:
                meta = segments_by_name.get(sym.segment.name)
                if meta is not None:
                    meta.add_user_symbol(sym)
                    continue
                elif sym.segment.name in skipped_segments:
                    log.write(
                        f"Error: Unable to associated '{sym}' to segment '{sym.segment}' because that segment is missing a vram/rom address.",
                        status="warn",
                    )
                else:
                    log.write(
                        f"Warning (Maybe bug): User-declared symbol '{sym}' is unexpectely associated to segment '{sym.segment}'.\n"
                        "  This is an issue because unexpected segments should have been filtered on a previous step.\n"
                        "  Please report.",
                        status="warn",
                    )

            # Then try to look up for global segments.
            found_global = False
            for meta_seg in self.global_segments:
                if meta_seg.in_vram_range(sym.vram_start):
                    meta_seg.add_user_symbol(sym)
                    found_global = True
                    break
            if found_global:
                continue

            # We run out of places to put this symbol into.
            # We need the user to give us more info on what to do with this.
            possible_segments = [
                f"{seg_meta.name} (Vram: 0x{seg_meta.vram_start:08X}, Rom: 0x{seg_meta.rom_start:X})"
                for seg_meta in segments_by_name.values()
                if seg_meta.in_vram_range(sym.vram_start)
            ]
            possible_segments_str = (
                f"[{', '.join(possible_segments)}]"
                if len(possible_segments) > 0
                else "None"
            )
            lost_symbols.append(
                f"{sym.name} (Vram: 0x{sym.vram_start:08X}). Suspected segments: {possible_segments_str}"
            )
            self.unknown_segment.add_user_symbol(sym)

        if len(lost_symbols) > 0:
            log.write(
                "\nError: Unable to determine a segment for the following user-declared symbols.\n"
                "  Try specifying the segment they belong to with 'segment:segment_name' in your symbol_addrs file.\n"
                "  If the address of this symbol is not part of any segment, or if you believe this symbol should be\n"
                "  globally visible and take priority over other symbol references then use the `absolute:True`\n"
                "  user attribute instead.",
                status="warn",
            )
            log.write("    " + "\n    ".join(lost_symbols))
            log.write("\n")
            # TODO: uncomment on a future version
            # log.error("Stopping due to the above issues.")

        self.all_symbols = all_symbols


metadata_group = SegmentMetadataGroup()


def initialize(all_segments: "list[Segment]", all_symbols: "list[Symbol]") -> None:
    global metadata_group
    segments_by_name, skipped_segments = metadata_group._initialize_segments(
        all_segments
    )
    metadata_group._initialize_symbols(all_symbols, segments_by_name, skipped_segments)


def reset() -> None:
    global metadata_group
    metadata_group = SegmentMetadataGroup()
