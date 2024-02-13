from typing import Tuple

__package_name__ = __name__

# Should be synced with pyproject.toml
__version__ = "0.22.0"
__author__ = "ethteck"

from . import util as util
from . import disassembler as disassembler
from . import platforms as platforms
from . import segtypes as segtypes

from . import scripts as scripts
