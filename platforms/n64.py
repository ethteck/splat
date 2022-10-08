from util import compiler, log, options, palettes, symbols


def init(target_bytes: bytes):
    symbols.spim_context.fillDefaultBannedSymbols()

    symbols.spim_context.globalSegment.fillLibultraSymbols()
    symbols.spim_context.globalSegment.fillHardwareRegs(True)
