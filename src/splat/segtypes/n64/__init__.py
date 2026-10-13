from . import decompressor as decompressor
from . import header as header
from . import ipl3 as ipl3
from . import palette as palette
from . import rsp as rsp
from . import vtx as vtx

# Segments that require optional dependencies

# assets-n64 (pygfxd)
try:
    from . import gfx as gfx
except ImportError:
    pass

# assets-n64 (n64img)
try:
    from . import ci as ci
    from . import ci4 as ci4
    from . import ci8 as ci8
    from . import i1 as i1
    from . import i4 as i4
    from . import i8 as i8
    from . import ia16 as ia16
    from . import ia4 as ia4
    from . import ia8 as ia8
    from . import img as img
    from . import rgba16 as rgba16
    from . import rgba32 as rgba32
except ImportError:
    pass

# compression (crunch64)
try:
    from . import mio0 as mio0
    from . import yay0 as yay0
except ImportError:
    pass
