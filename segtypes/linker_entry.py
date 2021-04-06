from typing import Union, List
from pathlib import Path
from util import options
from segtypes.segment import Segment
from segtypes.n64.code import Subsegment

#def is_asset(path: Path) -> bool:
#    return path.is_relative_to(options.get_asset_path())

class LinkerEntry:
    def __init__(self, segment: Union[Segment, Subsegment], src_paths: List[Path], object_path: Path, section: str):
        self.segment = segment
        self.src_paths = src_paths
        self.object_path = object_path.with_suffix(object_path.suffix + ".o")
        self.section = section
