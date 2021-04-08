from typing import Union, List
from pathlib import Path
from util import options
from segtypes.segment import Segment
from segtypes.n64.code import Subsegment

# clean 'foo/../bar' to 'bar'
def clean_up_path(path: Path) -> Path:
    return path.resolve().relative_to(options.get_base_path().resolve())

def path_to_object_path(path: Path) -> Path:
    path = options.get_build_path() / path.with_suffix(path.suffix + ".o").relative_to(options.get_base_path())
    return clean_up_path(path)

class LinkerEntry:
    def __init__(self, segment: Union[Segment, Subsegment], src_paths: List[Path], object_path: Path, section: str):
        self.segment = segment
        self.src_paths = [clean_up_path(p) for p in src_paths]
        self.object_path = path_to_object_path(object_path)
        self.section = section
