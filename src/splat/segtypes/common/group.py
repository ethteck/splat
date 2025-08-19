from typing import List, Optional

from ...util import log

from .segment import CommonSegment
from ..segment import empty_statistics, Segment, SegmentStatistics


class CommonSegGroup(CommonSegment):
    def __init__(
        self,
        rom_start: Optional[int],
        rom_end: Optional[int],
        type: str,
        name: str,
        vram_start: Optional[int],
        args: list,
        yaml,
    ):
        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            args=args,
            yaml=yaml,
        )

        self.subsegments: List[Segment] = self.parse_subsegments(yaml)

    def get_next_seg_start(self, i, subsegment_yamls) -> Optional[int]:
        j = i + 1
        while j < len(subsegment_yamls):
            ret, is_auto_segment = Segment.parse_segment_start(subsegment_yamls[j])
            if ret is not None:
                return ret
            j += 1

        # Fallback
        return self.rom_end

    def parse_subsegments(self, yaml) -> List[Segment]:
        ret: List[Segment] = []

        if not yaml or "subsegments" not in yaml:
            return ret

        prev_start: Optional[int] = -1
        last_rom_end = 0

        for i, subsegment_yaml in enumerate(yaml["subsegments"]):
            # endpos marker
            if isinstance(subsegment_yaml, list) and len(subsegment_yaml) == 1:
                continue

            typ = Segment.parse_segment_type(subsegment_yaml)
            start, is_auto_segment = Segment.parse_segment_start(subsegment_yaml)

            segment_class = Segment.get_class_for_type(typ)

            if start is None:
                # Attempt to infer the start address
                if i == 0:
                    # The start address of this segment is the start address of the group
                    start = self.rom_start
                else:
                    # The start address is the end address of the previous segment
                    start = last_rom_end

            # First, try to get the end address from the next segment's start address
            # Second, try to get the end address from the estimated size of this segment
            # Third, try to get the end address from the next segment with a start address
            end: Optional[int] = None
            if i < len(yaml["subsegments"]) - 1:
                end, end_is_auto_segment = Segment.parse_segment_start(
                    yaml["subsegments"][i + 1]
                )
            if start is not None and end is None:
                est_size = segment_class.estimate_size(subsegment_yaml)
                if est_size is not None:
                    end = start + est_size
            if end is None:
                end = self.get_next_seg_start(i, yaml["subsegments"])

            if start is not None and prev_start is not None and start < prev_start:
                log.error(
                    f"Error: Group segment {self.name} contains subsegments which are out of ascending rom order (0x{prev_start:X} followed by 0x{start:X})"
                )

            vram = None
            if start is not None:
                most_parent = self.get_most_parent()
                if (
                    most_parent.vram_start is not None
                    and most_parent.rom_start is not None
                ):
                    vram = most_parent.vram_start + start - most_parent.rom_start

            if segment_class.is_noload():
                # Pretend bss's rom address is after the last actual rom segment
                start = last_rom_end
                # and it has a rom size of zero
                end = last_rom_end

            segment: Segment = Segment.from_yaml(
                segment_class, subsegment_yaml, start, end, self, vram
            )
            if segment.special_vram_segment:
                self.special_vram_segment = True
            segment.is_auto_segment = is_auto_segment

            segment.index_within_group = len(ret)

            ret.append(segment)
            prev_start = start
            if end is not None:
                last_rom_end = end

        for i, seg in enumerate(ret):
            seg.index_within_group = i

        return ret

    @property
    def needs_symbols(self) -> bool:
        for seg in self.subsegments:
            if seg.needs_symbols:
                return True
        return False

    @property
    def statistics(self) -> SegmentStatistics:
        stats = empty_statistics()
        for sub in self.subsegments:
            for ty, info in sub.statistics.items():
                stats[ty] = stats[ty].merge(info)
        return stats

    def get_linker_entries(self):
        return [entry for sub in self.subsegments for entry in sub.get_linker_entries()]

    def scan(self, rom_bytes):
        for sub in self.subsegments:
            if sub.should_scan():
                sub.scan(rom_bytes)

    def split(self, rom_bytes):
        for sub in self.subsegments:
            if sub.should_split():
                sub.split(rom_bytes)

    def should_split(self) -> bool:
        return self.extract

    def should_scan(self) -> bool:
        return self.extract

    def cache(self):
        c = []

        for sub in self.subsegments:
            c.append(sub.cache())

        return c

    def get_subsegment_for_ram(self, addr: int) -> Optional[Segment]:
        for sub in self.subsegments:
            if sub.contains_vram(addr):
                return sub
        if isinstance(self.paired_segment, CommonSegGroup):
            for sub in self.paired_segment.subsegments:
                if sub.contains_vram(addr):
                    return sub
        return None

    def get_next_subsegment_for_ram(
        self, addr: int, current_subseg_index: Optional[int]
    ) -> Optional[Segment]:
        """
        Returns the first subsegment which comes after the specified address,
        or None in case this address belongs to the last subsegment of this group
        """

        start = current_subseg_index if current_subseg_index is not None else 0

        for sub in self.subsegments[start:]:
            if sub.vram_start is None:
                continue
            assert isinstance(sub.vram_start, int)
            if sub.vram_start > addr:
                return sub
        return None

    def pair_subsegments_to_other_segment(
        self,
        other_segment: "CommonSegGroup",
    ):
        # Pair cousins with the same name
        for segment in self.subsegments:
            for sibling in other_segment.subsegments:
                if segment.name == sibling.name:
                    # Make them reference each other
                    segment.siblings[sibling.get_linker_section_linksection()] = sibling
                    sibling.siblings[segment.get_linker_section_linksection()] = segment

                    if segment.is_text():
                        sibling.sibling = segment
                    elif sibling.is_text():
                        segment.sibling = sibling

                    break
