from typing import List, Optional, TypeVar

T = TypeVar("T")


def list_index(the_list: List[T], value: T) -> Optional[int]:
    if value not in the_list:
        return None
    return the_list.index(value)
