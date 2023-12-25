__package_name__ = __name__

__version_info__: tuple[int, int, int] = (0, 20, 0)
__version__ = ".".join(map(str, __version_info__))
__author__ = "ethteck"

from . import util as util
from . import disassembler as disassembler
from . import platforms as platforms
from . import segtypes as segtypes

from . import scripts as scripts
