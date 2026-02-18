
from . import disassembler


class NullDisassembler(disassembler.Disassembler):
    def configure(self):
        pass

    def check_version(self, skip_version_check: bool, splat_version: str):
        pass

    def known_types(self) -> set[str]:
        return set()
