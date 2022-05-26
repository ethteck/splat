#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import enum


class AbiNames(enum.Enum):
    numeric = enum.auto()
    o32 = enum.auto()
    n32 = enum.auto()
    n64 = enum.auto()

    @staticmethod
    def fromStr(x: str) -> AbiNames:
        if x in ("32", "o32"):
            return AbiNames.o32
        if x in ("n32",):
            return AbiNames.n32
        if x in ("64", "n64"):
            return AbiNames.n64
        return AbiNames.numeric


class InstructionConfig:
    NAMED_REGISTERS: bool = True
    """Enables using named registers

    This option takes precedence over the other named register options"""

    GPR_ABI_NAMES: AbiNames = AbiNames.o32
    """The ABI names to be used for general purpose registers when disassembling the main processor's instructions"""
    FPR_ABI_NAMES: AbiNames = AbiNames.numeric
    """The ABI names to be used for floating point registers when disassembling the floating point (coprocessor 1) instructions"""

    USE_FPCCSR: bool = True
    """Use FpcCsr as register $31 for the FP control/status register"""

    VR4300_COP0_NAMED_REGISTERS: bool = True
    """Use named registers for VR4300's coprocessor 0 registers"""
    VR4300_RSP_COP0_NAMED_REGISTERS: bool = True
    """Use named registers for VR4300's RSP's coprocessor 0 registers"""

    PSEUDO_INSTRUCTIONS: bool = True
    """Produce pseudo instructions (like `move`, `nop` or `b`) whenever those should match the desired original instruction"""

    SN64_DIV_FIX: bool = False
    """Enables a few fixes for SN64's assembler related to div/divu instructions

    - SN64's assembler doesn't like assembling `div $0, a, b` with .set noat active.
    Removing the $0 fixes this issue.

    - SN64's assembler expands div to have break if dividing by zero
    However, the break it generates is different than the one it generates with `break N`
    So we replace break instrutions for SN64 with the exact word that the assembler generates when expanding div
    """

    OPCODE_LJUST: int = 7+4
    """The minimal number of characters to left-align the opcode name"""

    UNKNOWN_INSTR_COMMENT: bool = True
    """Generate a pseudo-disassembly comment when disassembling non implemented instructions"""

    @staticmethod
    def addParametersToArgParse(parser: argparse.ArgumentParser):
        registerNames = parser.add_argument_group("MIPS register names options")

        registerNames.add_argument("--named-registers", help=f"(Dis)allows named registers for every instruction. This flag takes precedence over similar flags in this category. Defaults to {InstructionConfig.NAMED_REGISTERS}", action=argparse.BooleanOptionalAction)

        abi_choices = ["numeric", "32", "o32", "n32", "n64"]
        registerNames.add_argument("--Mgpr-names", help=f"Use GPR names according to the specified ABI. Defaults to {InstructionConfig.GPR_ABI_NAMES.name}", choices=abi_choices)
        registerNames.add_argument("--Mfpr-names", help=f"Use FPR names according to the specified ABI. Defaults to {InstructionConfig.FPR_ABI_NAMES.name}", choices=abi_choices)
        registerNames.add_argument("--Mreg-names", help=f"Use GPR and FPR names according to the specified ABI. This flag takes precedence over --Mgpr-names and --Mfpr-names", choices=abi_choices)

        registerNames.add_argument("--use-fpccsr", help=f"Toggles using the FpcCsr alias for float register $31 when using the numeric ABI. Defaults to {InstructionConfig.USE_FPCCSR}", action=argparse.BooleanOptionalAction)

        registerNames.add_argument("--cop0-named-registers", help=f"Toggles using the built-in names for registers of the VR4300's Coprocessor 0. Defaults to {InstructionConfig.USE_FPCCSR}", action=argparse.BooleanOptionalAction)
        registerNames.add_argument("--rsp-cop0-named-registers", help=f"Toggles using the built-in names for registers of the RSP's Coprocessor 0. Defaults to {InstructionConfig.USE_FPCCSR}", action=argparse.BooleanOptionalAction)


        miscOpts = parser.add_argument_group("MIPS misc instructions options")

        miscOpts.add_argument("--pseudo-instr", help=f"Toggles producing pseudo instructions. Defaults to {InstructionConfig.PSEUDO_INSTRUCTIONS}", action=argparse.BooleanOptionalAction)

        miscOpts.add_argument("--sn64-div-fix", help=f"Enables a few fixes for SN64's assembler related to div/divu instructions. Defaults to {InstructionConfig.SN64_DIV_FIX}", action=argparse.BooleanOptionalAction)

        miscOpts.add_argument("--opcode-ljust", help=f"Set the minimal number of characters to left-align the opcode name. Defaults to {InstructionConfig.OPCODE_LJUST}")

        miscOpts.add_argument("--unk-instr-comment", help=f"Disables the extra comment produced after unknown instructions. Defaults to {InstructionConfig.UNKNOWN_INSTR_COMMENT}", action=argparse.BooleanOptionalAction)


    @classmethod
    def parseArgs(cls, args: argparse.Namespace):
        if args.named_registers is not None:
            InstructionConfig.NAMED_REGISTERS = args.named_registers

        if args.Mgpr_names:
            InstructionConfig.GPR_ABI_NAMES = AbiNames.fromStr(args.Mgpr_names)
        if args.Mfpr_names:
            InstructionConfig.FPR_ABI_NAMES = AbiNames.fromStr(args.Mfpr_names)
        if args.Mreg_names:
            InstructionConfig.GPR_ABI_NAMES = AbiNames.fromStr(args.Mreg_names)
            InstructionConfig.FPR_ABI_NAMES = AbiNames.fromStr(args.Mreg_names)

        if args.use_fpccsr is not None:
            InstructionConfig.USE_FPCCSR = args.use_fpccsr

        if args.cop0_named_registers is not None:
            InstructionConfig.VR4300_COP0_NAMED_REGISTERS = args.cop0_named_registers
        if args.rsp_cop0_named_registers is not None:
            InstructionConfig.VR4300_RSP_COP0_NAMED_REGISTERS = args.rsp_cop0_named_registers

        if args.pseudo_instr is not None:
            InstructionConfig.PSEUDO_INSTRUCTIONS = args.pseudo_instr

        if args.sn64_div_fix is not None:
            InstructionConfig.SN64_DIV_FIX = args.sn64_div_fix

        if args.opcode_ljust is not None:
            InstructionConfig.OPCODE_LJUST = int(args.opcode_ljust, 0)

        if args.unk_instr_comment is not None:
            InstructionConfig.UNKNOWN_INSTR_COMMENT = args.unk_instr_comment
