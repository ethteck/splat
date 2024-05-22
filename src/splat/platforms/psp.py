import spimdisasm
import rabbitizer


def init(target_bytes: bytes):
    rabbitizer.config.toolchainTweaks_treatJAsUnconditionalBranch = False
    spimdisasm.common.GlobalConfig.SYMBOL_FINDER_FILTER_LOW_ADDRESSES = False
    spimdisasm.common.GlobalConfig.SYMBOL_FINDER_FILTER_HIGH_ADDRESSES = False
