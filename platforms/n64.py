from util import compiler, log, options, palettes, symbols


def init(target_bytes: bytes):
    symbols.spim_context.fillDefaultBannedSymbols()
