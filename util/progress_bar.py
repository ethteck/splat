from typing import TextIO, TypeVar
import tqdm
import sys

T = TypeVar("T")

out_file: TextIO = sys.stderr

def get_progress_bar(elements: list[T]) -> tqdm.tqdm[T]:
    return tqdm.tqdm(
        elements,
        total=len(elements),
        file=out_file
    )
