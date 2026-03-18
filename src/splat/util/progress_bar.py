from __future__ import annotations

import tqdm
import sys
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from collections.abc import Sequence

out_file: TextIO = sys.stderr


def get_progress_bar(elements: Sequence[object]) -> tqdm.tqdm:
    return tqdm.tqdm(elements, total=len(elements), file=out_file)
