from typing import List, Optional, TypeVar

T = TypeVar("T")


def list_index(l: List[T], value: T) -> Optional[int]:
    if value not in l:
        return None
    return l.index(value)
