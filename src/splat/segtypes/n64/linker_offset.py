from pathlib import Path
from typing import List

from .segment import N64Segment
from ..linker_entry import LinkerEntry, LinkerWriter
from ..segment import Segment


class LinkerEntryOffset(LinkerEntry):
    def __init__(
        self,
        segment: Segment,
    ):
        super().__init__(segment, [], Path(), "linker_offset", "linker_offset", False)
        self.object_path = None

    def emit_entry(self, linker_writer: LinkerWriter):
        linker_writer._write_symbol(f"{self.segment.get_cname()}_OFFSET", ".")


class N64SegLinker_offset(N64Segment):
    def get_linker_entries(self) -> List[LinkerEntry]:
        return [LinkerEntryOffset(self)]
