from pathlib import Path
from segtypes.segment import Segment
from segtypes.n64.code import Subsegment
from typing import Union

class LinkerEntry:
    def __init__(self, src_segment: Union[Segment, Subsegment], dest_path: Path):
        self.src_segment = src_segment
        self.dest_path = dest_path
