from __future__ import annotations

from abc import ABC, abstractmethod


class Disassembler(ABC):
    __slots__ = ()

    @abstractmethod
    def configure(self) -> None:
        raise NotImplementedError("configure")

    @abstractmethod
    def check_version(self, skip_version_check: bool, splat_version: str):
        raise NotImplementedError("check_version")

    @abstractmethod
    def known_types(self) -> set[str]:
        raise NotImplementedError("known_types")
