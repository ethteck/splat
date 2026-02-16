from __future__ import annotations

from typing import TypeVar

T = TypeVar("T")


def list_index(the_list: list[T], value: T) -> int | None:
    if value not in the_list:
        return None
    return the_list.index(value)
