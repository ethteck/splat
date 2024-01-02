from . import disassembler
from ..util import log, compiler
from ..util.options import SplatOpts
from typing import Set


# Just a dummy class as it is not used yet.
class WasmDisassembler(disassembler.Disassembler):
    def configure(self, opts: SplatOpts):
        pass

    def check_version(self, skip_version_check: bool, splat_version: str):
        pass

    def known_types(self) -> Set[str]:
        return set()
