import rabbitizer

from ..util import compiler, options

def init(target_bytes: bytes):
    if options.opts.compiler == compiler.GCC:
        rabbitizer.config.toolchainTweaks_treatJAsUnconditionalBranch = False
