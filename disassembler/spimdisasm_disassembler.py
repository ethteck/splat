from disassembler import disassembler
import spimdisasm
import rabbitizer
from util import log, compiler
from util.options import SplatOpts
from typing import Set


class SpimdisasmDisassembler(disassembler.Disassembler):
    # This value should be kept in sync with the version listed on requirements.txt
    SPIMDISASM_MIN = (1, 17, 0)

    def configure(self, opts: SplatOpts):
        # Configure spimdisasm
        spimdisasm.common.GlobalConfig.PRODUCE_SYMBOLS_PLUS_OFFSET = True
        spimdisasm.common.GlobalConfig.TRUST_USER_FUNCTIONS = True
        spimdisasm.common.GlobalConfig.TRUST_JAL_FUNCTIONS = True
        spimdisasm.common.GlobalConfig.GLABEL_ASM_COUNT = False

        if opts.rom_address_padding:
            spimdisasm.common.GlobalConfig.ASM_COMMENT_OFFSET_WIDTH = 6
        else:
            spimdisasm.common.GlobalConfig.ASM_COMMENT_OFFSET_WIDTH = 0

        # spimdisasm is not performing any analyzis on non-text sections so enabling this options is pointless
        spimdisasm.common.GlobalConfig.AUTOGENERATED_NAMES_BASED_ON_SECTION_TYPE = False
        spimdisasm.common.GlobalConfig.AUTOGENERATED_NAMES_BASED_ON_DATA_TYPE = False

        spimdisasm.common.GlobalConfig.SYMBOL_FINDER_FILTERED_ADDRESSES_AS_HILO = False

        if opts.rodata_string_guesser_level is not None:
            spimdisasm.common.GlobalConfig.RODATA_STRING_GUESSER_LEVEL = (
                opts.rodata_string_guesser_level
            )

        if opts.data_string_guesser_level is not None:
            spimdisasm.common.GlobalConfig.DATA_STRING_GUESSER_LEVEL = (
                opts.data_string_guesser_level
            )

        rabbitizer.config.regNames_userFpcCsr = False
        rabbitizer.config.regNames_vr4300Cop0NamedRegisters = False

        rabbitizer.config.misc_opcodeLJust = opts.mnemonic_ljust - 1

        rabbitizer.config.regNames_gprAbiNames = rabbitizer.Abi.fromStr(
            opts.mips_abi_gpr
        )
        rabbitizer.config.regNames_fprAbiNames = rabbitizer.Abi.fromStr(
            opts.mips_abi_float_regs
        )

        if opts.endianness == "big":
            spimdisasm.common.GlobalConfig.ENDIAN = spimdisasm.common.InputEndian.BIG
        else:
            spimdisasm.common.GlobalConfig.ENDIAN = spimdisasm.common.InputEndian.LITTLE

        rabbitizer.config.pseudos_pseudoMove = False

        selected_compiler = opts.compiler
        if selected_compiler == compiler.SN64:
            rabbitizer.config.regNames_namedRegisters = False
            rabbitizer.config.toolchainTweaks_sn64DivFix = True
            rabbitizer.config.toolchainTweaks_treatJAsUnconditionalBranch = True
            spimdisasm.common.GlobalConfig.ASM_COMMENT = False
            spimdisasm.common.GlobalConfig.SYMBOL_FINDER_FILTERED_ADDRESSES_AS_HILO = (
                False
            )
            spimdisasm.common.GlobalConfig.COMPILER = spimdisasm.common.Compiler.SN64
        elif selected_compiler == compiler.GCC:
            rabbitizer.config.toolchainTweaks_treatJAsUnconditionalBranch = True
            spimdisasm.common.GlobalConfig.COMPILER = spimdisasm.common.Compiler.GCC
        elif selected_compiler == compiler.IDO:
            spimdisasm.common.GlobalConfig.COMPILER = spimdisasm.common.Compiler.IDO

        spimdisasm.common.GlobalConfig.DETECT_REDUNDANT_FUNCTION_END = (
            opts.detect_redundant_function_end
        )

        spimdisasm.common.GlobalConfig.GP_VALUE = opts.gp

        spimdisasm.common.GlobalConfig.ASM_TEXT_LABEL = opts.asm_function_macro
        spimdisasm.common.GlobalConfig.ASM_TEXT_ALT_LABEL = opts.asm_function_alt_macro
        spimdisasm.common.GlobalConfig.ASM_JTBL_LABEL = opts.asm_jtbl_label_macro
        spimdisasm.common.GlobalConfig.ASM_DATA_LABEL = opts.asm_data_macro
        spimdisasm.common.GlobalConfig.ASM_TEXT_END_LABEL = opts.asm_end_label

        if opts.asm_emit_size_directive is not None:
            spimdisasm.common.GlobalConfig.ASM_EMIT_SIZE_DIRECTIVE = (
                opts.asm_emit_size_directive
            )

        if spimdisasm.common.GlobalConfig.ASM_TEXT_LABEL == ".globl":
            spimdisasm.common.GlobalConfig.ASM_TEXT_ENT_LABEL = ".ent"
            spimdisasm.common.GlobalConfig.ASM_TEXT_FUNC_AS_LABEL = True

        if spimdisasm.common.GlobalConfig.ASM_DATA_LABEL == ".globl":
            spimdisasm.common.GlobalConfig.ASM_DATA_SYM_AS_LABEL = True

        spimdisasm.common.GlobalConfig.LINE_ENDS = opts.c_newline

        spimdisasm.common.GlobalConfig.ALLOW_ALL_ADDENDS_ON_DATA = (
            opts.allow_data_addends
        )

        spimdisasm.common.GlobalConfig.ASM_GENERATED_BY = opts.asm_generated_by

        spimdisasm.common.GlobalConfig.DISASSEMBLE_UNKNOWN_INSTRUCTIONS = (
            opts.disasm_unknown
        )

    def check_version(self, skip_version_check: bool, splat_version: str):
        if not skip_version_check and spimdisasm.__version_info__ < self.SPIMDISASM_MIN:
            log.error(
                f"splat {splat_version} requires as minimum spimdisasm {self.SPIMDISASM_MIN}, but the installed version is {spimdisasm.__version_info__}"
            )

        log.write(
            f"splat {splat_version} (powered by spimdisasm {spimdisasm.__version__})"
        )

    def known_types(self) -> Set[str]:
        return spimdisasm.common.gKnownTypes
