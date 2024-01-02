from . import disassembler
from ..util import log, compiler
from ..util.options import SplatOpts
from typing import Set

class WasmDisassembler(disassembler.Disassembler):
    def configure(self, opts: SplatOpts):
        print("Configuring WASM Disassembler!")

    def check_version(self, skip_version_check: bool, splat_version: str):
        print("Version check WASM Disassembler!")

    def known_types(self) -> Set[str]:
        print("Known types WASM Disassembler!")