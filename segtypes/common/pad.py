from pathlib import Path
from typing import List

from segtypes.common.segment import CommonSegment
from segtypes.linker_entry import LinkerEntry, LinkerWriter
from segtypes.segment import Segment


class LinkerEntryPad(LinkerEntry):
    def __init__(
        self,
        segment: Segment,
    ):
        super().__init__(segment, [], Path(), "pad", "pad", False)
        self.object_path = None

    def emit_entry(self, linker_writer: LinkerWriter):
        linker_writer._writeln(f". += 0x{self.segment.size:X};")


class CommonSegPad(CommonSegment):
    def get_linker_entries(self) -> List[LinkerEntry]:
        return [LinkerEntryPad(self)]
