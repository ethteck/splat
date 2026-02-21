from __future__ import annotations

from typing import TYPE_CHECKING
from math import ceil

from . import options

if TYPE_CHECKING:
    from collections.abc import Sequence


# RRRRRGGG GGBBBBBA
def unpack_color(data: Sequence[int]) -> tuple[int, int, int, int]:
    s = int.from_bytes(data[0:2], byteorder=options.opts.endianness)

    r = (s >> 11) & 0x1F
    g = (s >> 6) & 0x1F
    b = (s >> 1) & 0x1F
    a = (s & 1) * 0xFF

    r = ceil(0xFF * (r / 31))
    g = ceil(0xFF * (g / 31))
    b = ceil(0xFF * (b / 31))

    return r, g, b, a
