import spimdisasm
import rabbitizer

from ..util import compiler, options


def init(target_bytes: bytes):
    rabbitizer.config.toolchainTweaks_treatJAsUnconditionalBranch = False

    spimdisasm.common.GlobalConfig.ABI = spimdisasm.common.Abi.EABI64
    spimdisasm.common.GlobalConfig.SYMBOL_ALIGNMENT_REQUIRES_ALIGNED_SECTION = True
