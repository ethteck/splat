from typing import Tuple

__package_name__ = __name__

# Should be synced with pyproject.toml
__version_info__: Tuple[int, int, int] = (0, 21, 11)
__version__ = ".".join(map(str, __version_info__))
__author__ = "ethteck"

from . import util as util
from . import disassembler as disassembler
from . import platforms as platforms
from . import segtypes as segtypes

from . import scripts as scripts
