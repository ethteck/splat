from typing import List, Optional, Union

from ...util import log

from .segment import CommonSegment
from ..segment import empty_statistics, Segment, SegmentStatistics, parse_segment_vram


class CommonSegGroup(CommonSegment):
    def __init__(
        self,
        rom_start: Optional[int],
        rom_end: Optional[int],
        type: str,
        name: str,
        vram_start: Optional[int],
        args: list,
        yaml: Union[dict, list],
        bss_size: Optional[int] = None,
    ):
        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            args=args,
            yaml=yaml,
            bss_size=bss_size,
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

    def _calculate_noload_values(
        self,
        segment_class: type["Segment"],
        subsegment_yaml: Union[dict, list],
        next_subsegment_yaml: Union[dict, list, None],
        start: Optional[int],
        end: Optional[int],
        vram: Optional[int],
        last_rom_end: Optional[int],
    ) -> tuple[Optional[int], Optional[int], Optional[int], Optional[int]]:
        """
        Calculate the start, end, vram and bss_size for noload (i.e. bss)
        segments.

        If the segment isn't a noload segment, then the returned values are the
        same as the input values.
        """

        bss_size: Optional[int] = None
        if segment_class.is_noload():
            # Pretend bss's rom address is after the last actual rom segment
            start = last_rom_end
            # and it has a rom size of zero
            end = last_rom_end

            # noload segments can specify their vram address in the yaml
            # directly because their rom address is meaningless.
            vram = parse_segment_vram(subsegment_yaml)

            if vram is not None:
                # Calculate the bss_size by substracting the vram address
                # of the next segment from the current one.
                # If there's no next segment, then use the vram_end from the parent.
                if next_subsegment_yaml is not None:
                    next_vram = parse_segment_vram(next_subsegment_yaml)
                else:
                    next_vram = self.get_most_parent().vram_end
                if next_vram is not None:
                    if vram > next_vram:
                        log.error(
                            f"Error: Group segment {self.name} contains noload subsegments (i.e. bss) which are out of ascending vram order (0x{next_vram:X} followed by 0x{vram:X})"
                        )
                    bss_size = next_vram - vram

        return start, end, vram, bss_size

    def parse_subsegments(self, yaml) -> List[Segment]:
        ret: List[Segment] = []

        if not yaml or not isinstance(yaml, dict):
            return ret
        yaml_subsegments = yaml.get("subsegments")
        if not yaml_subsegments:
            return ret

        prev_start: Optional[int] = None

        # Start as the "start" address of the group.
        last_rom_end = self.rom_start

        for i, subsegment_yaml in enumerate(yaml_subsegments):
            # endpos marker
            if isinstance(subsegment_yaml, list) and len(subsegment_yaml) == 1:
                continue

            next_subsegment_yaml = (
                yaml_subsegments[i + 1] if i + 1 < len(yaml_subsegments) else None
            )

            typ = Segment.parse_segment_type(subsegment_yaml)
            start, is_auto_segment = Segment.parse_segment_start(subsegment_yaml)

            segment_class = Segment.get_class_for_type(typ)

            if start is None:
                # Attempt to infer the start address.
                # The start address is the end address of the previous segment.
                # If this is the first subsegment then this value will fallback
                # to the start address of the group.
                start = last_rom_end

            # First, try to get the end address from the next segment's start address
            # Second, try to get the end address from the estimated size of this segment
            # Third, try to get the end address from the next segment with a start address
            end: Optional[int] = None
            if next_subsegment_yaml is not None:
                end, end_is_auto_segment = Segment.parse_segment_start(
                    next_subsegment_yaml
                )
            if start is not None and end is None:
                est_size = segment_class.estimate_size(subsegment_yaml)
                if est_size is not None:
                    end = start + est_size
            if end is None:
                end = self.get_next_seg_start(i, yaml_subsegments)

            if start is not None and prev_start is not None and start < prev_start:
                log.error(
                    f"Error: Group segment '{self.name}' contains subsegments which are out of ascending rom order (0x{prev_start:X} followed by 0x{start:X})"
                )

            vram = None
            if start is not None:
                most_parent = self.get_most_parent()
                if (
                    most_parent.vram_start is not None
                    and most_parent.rom_start is not None
                ):
                    vram = most_parent.vram_start + start - most_parent.rom_start

            # noload (bss) segments need a bit of special calculation
            start, end, vram, bss_size = self._calculate_noload_values(
                segment_class,
                subsegment_yaml,
                next_subsegment_yaml,
                start,
                end,
                vram,
                last_rom_end,
            )

            segment = Segment.from_yaml(
                segment_class,
                subsegment_yaml,
                start,
                end,
                self,
                vram,
                bss_size,
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
