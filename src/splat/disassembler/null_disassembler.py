from __future__ import annotations

from . import disassembler


class NullDisassembler(disassembler.Disassembler):
    __slots__ = ()
    def configure(self) -> None:
        pass

    def check_version(self, skip_version_check: bool, splat_version: str):
        pass

    def known_types(self) -> set[str]:
        return set()
