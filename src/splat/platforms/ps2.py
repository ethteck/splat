import spimdisasm
import rabbitizer

from ..util import compiler, options

def init(target_bytes: bytes):
    if options.opts.compiler == compiler.GCC:
        rabbitizer.config.toolchainTweaks_treatJAsUnconditionalBranch = False

    spimdisasm.common.GlobalConfig.ABI = spimdisasm.common.Abi.EABI64
