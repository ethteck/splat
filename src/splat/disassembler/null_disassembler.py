from . import disassembler
from typing import Set


class NullDisassembler(disassembler.Disassembler):
    def configure(self):
        pass

    def check_version(self, skip_version_check: bool, splat_version: str):
        pass

    def known_types(self) -> Set[str]:
        return set()
