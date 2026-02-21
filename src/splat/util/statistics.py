from __future__ import annotations

from colorama import Fore, Style

from . import log


def fmt_size(size: int) -> str:
    if size > 1000000:
        return f"{size // 1000000} MB"
    if size > 1000:
        return f"{size // 1000} KB"
    return f"{size} B"


class Statistics:
    __slots__ = ("seg_cached", "seg_sizes", "seg_split")

    def __init__(self) -> None:
        self.seg_sizes: dict[str, int] = {}
        self.seg_split: dict[str, int] = {}
        self.seg_cached: dict[str, int] = {}

    def add_size(self, typ: str, size: int | None) -> None:
        if typ not in self.seg_sizes:
            self.seg_sizes[typ] = 0
        self.seg_sizes[typ] += 0 if size is None else size

    def count_split(self, typ: str, count: int = 1) -> None:
        if typ not in self.seg_split:
            self.seg_split[typ] = 0
        self.seg_split[typ] += count

    def count_cached(self, typ: str, count: int = 1) -> None:
        if typ not in self.seg_cached:
            self.seg_cached[typ] = 0
        self.seg_cached[typ] += count

    def print_statistics(self, total_size: int) -> None:
        unk_size = self.seg_sizes.get("unk", 0)
        rest_size = 0

        for typ, size in self.seg_sizes.items():
            if typ != "unk":
                rest_size += size

        known_ratio = rest_size / total_size
        unk_ratio = unk_size / total_size

        log.write(
            f"Split {fmt_size(rest_size)} ({known_ratio:.2%}) in defined segments"
        )
        for typ, size in self.seg_sizes.items():
            if typ != "unk":
                tmp_ratio = size / total_size
                log.write(
                    f"{typ:>20}: {fmt_size(size):>8} ({tmp_ratio:.2%}) {Fore.GREEN}{self.seg_split.get(typ, 0)} split{Style.RESET_ALL}, {Style.DIM}{self.seg_cached.get(typ, 0)} cached"
                )
        log.write(
            f"{'unknown':>20}: {fmt_size(unk_size):>8} ({unk_ratio:.2%}) from unknown bin files"
        )
