from pathlib import Path
from typing import List

from .segment import CommonSegment
from ..linker_entry import LinkerEntry, LinkerWriter
from ..segment import Segment


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
    def get_linker_section_order(self) -> str:
        return ""

    def get_linker_section_linksection(self) -> str:
        return ""

    def get_linker_entries(self) -> List[LinkerEntry]:
        return [LinkerEntryPad(self)]
