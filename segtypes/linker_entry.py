from typing import Union
from pathlib import Path
from segtypes.segment import Segment
from segtypes.n64.code import Subsegment

class LinkerEntry:
    def __init__(self, src_segment: Union[Segment, Subsegment], dest_path: Path, section: str):
        self.src_segment = src_segment
        self.dest_path = dest_path.with_suffix(dest_path.suffix + ".o")
        self.section = section
