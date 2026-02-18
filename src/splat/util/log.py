from __future__ import annotations

import sys
from typing import TYPE_CHECKING, NoReturn, Optional, TextIO, TypeAlias

from colorama import Fore, Style, init

if TYPE_CHECKING:
    from pathlib import Path

init(autoreset=True)

newline = True

Status: TypeAlias = Optional[str]


def write(*args: object, status: Status = None, sep: str | None = None, end: str | None = None, flush: bool = False) -> None:
    global newline

    if not newline:
        print("")
        newline = True

    print(
        status_to_ansi(status) + str(args[0]),
        *args[1:],
        sep=sep,
        end=end,
        file=output_file(status),
        flush=flush,
    )


def error(*args: object, sep: str | None = None, end: str | None = None, flush: bool = False) -> NoReturn:
    write(*args, status="error", sep=sep, end=end, flush=flush)
    sys.exit(2)


# The line_num is expected to be zero-indexed
def parsing_error_preamble(path: Path, line_num: int, line: str) -> None:
    write("")
    write(f"error reading {path}, line {line_num + 1}:", status="error")
    write(f"\t{line}")


def status_to_ansi(status: Status) -> Fore | str:
    if status == "ok":
        return Fore.GREEN
    if status == "warn":
        return Fore.YELLOW + Style.BRIGHT
    if status == "error":
        return Fore.RED + Style.BRIGHT
    if status == "skip":
        return Style.DIM
    return ""


def output_file(status: Status) -> TextIO:
    if status == "warn" or status == "error":
        return sys.stderr
    return sys.stdout
