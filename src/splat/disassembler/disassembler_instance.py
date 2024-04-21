from .disassembler import Disassembler
from .spimdisasm_disassembler import SpimdisasmDisassembler
from .null_disassembler import NullDisassembler

from ..util import options

__instance: Disassembler = NullDisassembler()
__initialized = False


def create_disassembler_instance(skip_version_check: bool, splat_version: str):
    global __instance
    global __initialized
    if options.opts.platform in ["n64", "psx", "ps2", "psp"]:
        __instance = SpimdisasmDisassembler()
        __initialized = True

        __instance.check_version(skip_version_check, splat_version)
        __instance.configure()
        return

    raise NotImplementedError("No disassembler for requested platform")


def get_instance() -> Disassembler:
    global __instance
    global __initialized
    if not __initialized:
        raise Exception("Disassembler instance not initialized")
        return None
    return __instance
