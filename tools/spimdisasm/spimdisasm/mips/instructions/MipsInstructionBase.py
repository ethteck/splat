#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from typing import Callable

from ... import common

from .MipsInstructionConfig import InstructionConfig, AbiNames
from .MipsConstants import InstructionId, InstructionVectorId, InstrType, InstrDescriptor, instructionDescriptorDict


class InstructionBase:
    GprO32RegisterNames = {
        0:  "$zero",
        1:  "$at",
        2:  "$v0",
        3:  "$v1",
        4:  "$a0",
        5:  "$a1",
        6:  "$a2",
        7:  "$a3",
        8:  "$t0",
        9:  "$t1",
        10: "$t2",
        11: "$t3",
        12: "$t4",
        13: "$t5",
        14: "$t6",
        15: "$t7",
        16: "$s0",
        17: "$s1",
        18: "$s2",
        19: "$s3",
        20: "$s4",
        21: "$s5",
        22: "$s6",
        23: "$s7",
        24: "$t8",
        25: "$t9",
        26: "$k0",
        27: "$k1",
        28: "$gp",
        29: "$sp",
        30: "$fp",
        31: "$ra",
    }
    GprN32RegisterNames = {
        0:  "$zero",
        1:  "$at",
        2:  "$v0",
        3:  "$v1",
        4:  "$a0",
        5:  "$a1",
        6:  "$a2",
        7:  "$a3",
        8:  "$a4",
        9:  "$a5",
        10: "$a6",
        11: "$a7",
        12: "$t0",
        13: "$t1",
        14: "$t2",
        15: "$t3",
        16: "$s0",
        17: "$s1",
        18: "$s2",
        19: "$s3",
        20: "$s4",
        21: "$s5",
        22: "$s6",
        23: "$s7",
        24: "$t8",
        25: "$t9",
        26: "$k0",
        27: "$k1",
        28: "$gp",
        29: "$sp",
        30: "$fp",
        31: "$ra",
    }

    Cop0RegisterNames = {
        0:  "Index",
        1:  "Random",
        2:  "EntryLo0",
        3:  "EntryLo1",
        4:  "Context",
        5:  "PageMask",
        6:  "Wired",
        7:  "Reserved07",
        8:  "BadVaddr",
        9:  "Count",
        10: "EntryHi",
        11: "Compare",
        12: "Status",
        13: "Cause",
        14: "EPC",
        15: "PRevID",
        16: "Config",
        17: "LLAddr",
        18: "WatchLo",
        19: "WatchHi",
        20: "XContext",
        21: "Reserved21",
        22: "Reserved22",
        23: "Reserved23",
        24: "Reserved24",
        25: "Reserved25",
        26: "PErr",
        27: "CacheErr",
        28: "TagLo",
        29: "TagHi",
        30: "ErrorEPC",
        31: "Reserved31",
    }

    # Float registers
    Cop1NumericRegisterNames = {
        0:  "$f0",
        1:  "$f1",
        2:  "$f2",
        3:  "$f3",
        4:  "$f4",
        5:  "$f5",
        6:  "$f6",
        7:  "$f7",
        8:  "$f8",
        9:  "$f9",
        10: "$f10",
        11: "$f11",
        12: "$f12",
        13: "$f13",
        14: "$f14",
        15: "$f15",
        16: "$f16",
        17: "$f17",
        18: "$f18",
        19: "$f19",
        20: "$f20",
        21: "$f21",
        22: "$f22",
        23: "$f23",
        24: "$f24",
        25: "$f25",
        26: "$f26",
        27: "$f27",
        28: "$f28",
        29: "$f29",
        30: "$f30",
        31: "FpcCsr",
    }
    Cop1O32RegisterNames = {
        0:  "$fv0",
        1:  "$fv0f",
        2:  "$fv1",
        3:  "$fv1f",
        4:  "$ft0",
        5:  "$ft0f",
        6:  "$ft1",
        7:  "$ft1f",
        8:  "$ft2",
        9:  "$ft2f",
        10: "$ft3",
        11: "$ft3f",
        12: "$fa0",
        13: "$fa0f",
        14: "$fa1",
        15: "$fa1f",
        16: "$ft4",
        17: "$ft4f",
        18: "$ft5",
        19: "$ft5f",
        20: "$fs0",
        21: "$fs0f",
        22: "$fs1",
        23: "$fs1f",
        24: "$fs2",
        25: "$fs2f",
        26: "$fs3",
        27: "$fs3f",
        28: "$fs4",
        29: "$fs4f",
        30: "$fs5",
        31: "$fs5f",
    }
    Cop1N32RegisterNames = {
        0:  "$fv0",
        1:  "$ft14",
        2:  "$fv1",
        3:  "$ft15",
        4:  "$ft0",
        5:  "$ft1",
        6:  "$ft2",
        7:  "$ft3",
        8:  "$ft4",
        9:  "$ft5",
        10: "$ft6",
        11: "$ft7",
        12: "$fa0",
        13: "$fa1",
        14: "$fa2",
        15: "$fa3",
        16: "$fa4",
        17: "$fa5",
        18: "$fa6",
        19: "$fa7",
        20: "$fs0",
        21: "$ft8",
        22: "$fs1",
        23: "$ft9",
        24: "$fs2",
        25: "$ft10",
        26: "$fs3",
        27: "$ft11",
        28: "$fs4",
        29: "$ft12",
        30: "$fs5",
        31: "$ft13",
    }
    Cop1N64RegisterNames = {
        0:  "$fv0",
        1:  "$ft12",
        2:  "$fv1",
        3:  "$ft13",
        4:  "$ft0",
        5:  "$ft1",
        6:  "$ft2",
        7:  "$ft3",
        8:  "$ft4",
        9:  "$ft5",
        10: "$ft6",
        11: "$ft7",
        12: "$fa0",
        13: "$fa1",
        14: "$fa2",
        15: "$fa3",
        16: "$fa4",
        17: "$fa5",
        18: "$fa6",
        19: "$fa7",
        20: "$ft8",
        21: "$ft9",
        22: "$ft10",
        23: "$ft11",
        24: "$fs0",
        25: "$fs1",
        26: "$fs2",
        27: "$fs3",
        28: "$fs4",
        29: "$fs5",
        30: "$fs6",
        31: "$fs7",
    }

    GprRspRegisterNames = {
        0:  "$zero",
        1:  "$1",
        2:  "$2",
        3:  "$3",
        4:  "$4",
        5:  "$5",
        6:  "$6",
        7:  "$7",
        8:  "$8",
        9:  "$9",
        10: "$10",
        11: "$11",
        12: "$12",
        13: "$13",
        14: "$14",
        15: "$15",
        16: "$16",
        17: "$17",
        18: "$18",
        19: "$19",
        20: "$20",
        21: "$21",
        22: "$22",
        23: "$23",
        24: "$24",
        25: "$25",
        26: "$26",
        27: "$27",
        28: "$28",
        29: "$29",
        30: "$30",
        31: "$31",
    }

    Cop0RspRegisterNames = {
        0:  "SP_MEM_ADDR",
        1:  "SP_DRAM_ADDR",
        2:  "SP_RD_LEN",
        3:  "SP_WR_LEN",
        4:  "SP_STATUS",
        5:  "SP_DMA_FULL",
        6:  "SP_DMA_BUSY",
        7:  "SP_SEMAPHORE",
        8:  "DPC_START",
        9:  "DPC_END",
        10: "DPC_CURRENT",
        11: "DPC_STATUS",
        12: "DPC_CLOCK",
        13: "DPC_BUFBUSY",
        14: "DPC_PIPEBUSY",
        15: "DPC_TMEM",
    }

    VectorRspRegisterNames = {
        0:  "$v0",
        1:  "$v1",
        2:  "$v2",
        3:  "$v3",
        4:  "$v4",
        5:  "$v5",
        6:  "$v6",
        7:  "$v7",
        8:  "$v8",
        9:  "$v9",
        10: "$v10",
        11: "$v11",
        12: "$v12",
        13: "$v13",
        14: "$v14",
        15: "$v15",
        16: "$v16",
        17: "$v17",
        18: "$v18",
        19: "$v19",
        20: "$v20",
        21: "$v21",
        22: "$v22",
        23: "$v23",
        24: "$v24",
        25: "$v25",
        26: "$v26",
        27: "$v27",
        28: "$v28",
        29: "$v29",
        30: "$v30",
        31: "$v31",
    }

    instrArgumentsCallbacks: dict[str, Callable[[InstructionBase, str|None], str]] = {
        "rs":        lambda instr, immOverride: instr.getRegisterName(instr.rs),
        "rt":        lambda instr, immOverride: instr.getRegisterName(instr.rt),
        "rd":        lambda instr, immOverride: instr.getRegisterName(instr.rd),
        "sa":        lambda instr, immOverride: str(instr.sa),
        "ft":        lambda instr, immOverride: instr.getFloatRegisterName(instr.ft),
        "fs":        lambda instr, immOverride: instr.getFloatRegisterName(instr.fs),
        "fd":        lambda instr, immOverride: instr.getFloatRegisterName(instr.fd),
        "IMM":       lambda instr, immOverride: instr.processImmediate(immOverride),
        "LABEL":     lambda instr, immOverride: immOverride if immOverride is not None else f"func_{instr.getInstrIndexAsVram():06X}",
        "cop2t":     lambda instr, immOverride: instr.getCop2RegisterName(instr.rt),
        "cop0d":     lambda instr, immOverride: instr.getCop0RegisterName(instr.rd),
        "code":      lambda instr, immOverride: instr.processCodeParameter(),
        "op":        lambda instr, immOverride: f"0x{instr.rt:02X}",
        "IMM(base)": lambda instr, immOverride: f"{instr.processImmediate(immOverride)}({instr.getRegisterName(instr.baseRegister)})",
    }
    """Dictionary of callbacks to process the operands of an instruction.

    The keys should match the ones used in InstrDescriptor#operands
    """

    def __init__(self, instr: int):
        self.opcode = (instr >> 26) & 0x3F
        self.rs = (instr >> 21) & 0x1F # rs
        self.rt = (instr >> 16) & 0x1F # usually the destiny of the operation
        self.rd = (instr >> 11) & 0x1F # destination register in R-Type instructions
        self.sa = (instr >>  6) & 0x1F
        self.function = (instr >> 0) & 0x3F

        self.uniqueId: InstructionId|InstructionVectorId = InstructionId.INVALID
        self.descriptor: InstrDescriptor = instructionDescriptorDict[self.uniqueId]

        self.extraLjustWidthOpcode = 0

        self.vram: int|None = None
        self._handwrittenCategory: bool = False

    @property
    def instr(self) -> int:
        return (self.opcode << 26) | (self.rs << 21) | (self.rt << 16) | (self.rd << 11) | (self.sa << 6) | (self.function)

    @property
    def immediate(self) -> int:
        return (self.rd << 11) | (self.sa << 6) | (self.function)
    @property
    def instr_index(self) -> int:
        return (self.rs << 21) | (self.rt << 16) | (self.immediate)
    @property
    def baseRegister(self) -> int:
        return self.rs

    @property
    def fmt(self) -> int:
        return self.rs

    @property
    def ft(self) -> int:
        return self.rt
    @property
    def fs(self) -> int:
        return self.rd
    @property
    def fd(self) -> int:
        return self.sa

    @property
    def nd(self) -> int:
        return (self.rt >> 0) & 0x01
    @property
    def tf(self) -> int:
        return (self.rt >> 1) & 0x01
    @property
    def fc(self) -> int:
        return (self.function >> 4) & 0x03
    @property
    def cond(self) -> int:
        return (self.function >> 0) & 0x0F

    # vector registers
    @property
    def vd(self) -> int:
        return self.sa
    @property
    def vs(self) -> int:
        return self.rd
    @property
    def vt(self) -> int:
        return self.rt
    @property
    def elementHigh(self) -> int:
        return self.rs & 0xF
    @property
    def elementLow(self) -> int:
        return (self.sa >> 1) & 0xF
    @property
    def offsetVector(self) -> int:
        return self.immediate & 0x7F

    def getInstrIndexAsVram(self) -> int:
        vram = self.instr_index << 2
        if self.vram is None:
            vram |= 0x80000000
        else:
            # Jumps are PC-region branches. The upper bits are filled with the address in the delay slot
            vram |= (self.vram+4) & 0xFF000000
        return vram


    def __getitem__(self, key):
        if key < 0 or key > 31:
            raise IndexError()
        return (self.instr >> key) & 0x1


    def processUniqueId(self):
        if self.uniqueId in instructionDescriptorDict:
            self.descriptor = instructionDescriptorDict[self.uniqueId]

    def isImplemented(self) -> bool:
        if self.uniqueId == InstructionId.INVALID:
            return False
        if self.uniqueId == InstructionVectorId.INVALID:
            return False
        return True

    def isFloatInstruction(self) -> bool:
        return self.descriptor.isFloat

    def isDoubleFloatInstruction(self) -> bool:
        return self.descriptor.isDouble


    def isBranch(self) -> bool:
        return self.descriptor.isBranch
    def isBranchLikely(self) -> bool:
        return self.descriptor.isBranchLikely
    def isJump(self) -> bool:
        return self.descriptor.isJump
    def isTrap(self) -> bool:
        return self.descriptor.isTrap

    def isJType(self) -> bool:
        return self.descriptor.instrType == InstrType.typeJ

    def isIType(self) -> bool:
        return self.descriptor.instrType == InstrType.typeI

    def isRType(self) -> bool:
        return self.descriptor.instrType == InstrType.typeR


    def sameOpcode(self, other: InstructionBase) -> bool:
        if not self.isImplemented():
            return False
        if not other.isImplemented():
            return False
        return self.uniqueId == other.uniqueId

    def sameBaseRegister(self, other: InstructionBase):
        return self.baseRegister == other.baseRegister

    def sameOpcodeButDifferentArguments(self, other: InstructionBase) -> bool:
        if not self.sameOpcode(other):
            return False
        return self.instr != other.instr


    def modifiesRt(self) -> bool:
        return self.descriptor.modifiesRt
    def modifiesRd(self) -> bool:
        return self.descriptor.modifiesRd


    def blankOut(self):
        self.rs = 0
        self.rt = 0
        self.rd = 0
        self.sa = 0
        self.function = 0


    def getOpcodeName(self) -> str:
        if self.isImplemented():
            return self.uniqueId.name
        return f"(0x{self.opcode:02X})"


    def getRegisterName(self, register: int) -> str:
        if not InstructionConfig.NAMED_REGISTERS:
            return f"${register}"
        if InstructionConfig.GPR_ABI_NAMES == AbiNames.o32:
            return self.GprO32RegisterNames.get(register, f"${register}")
        if InstructionConfig.GPR_ABI_NAMES == AbiNames.numeric:
            return f"${register}"
        # AbiNames.n32 or AbiNames.n64
        return self.GprN32RegisterNames.get(register, f"${register}")

    def getFloatRegisterName(self, register: int) -> str:
        if not InstructionConfig.NAMED_REGISTERS:
            return f"$f{register}"
        if InstructionConfig.FPR_ABI_NAMES == AbiNames.numeric:
            if register == 31 and not InstructionConfig.USE_FPCCSR:
                return "$31"
            return self.Cop1NumericRegisterNames.get(register, f"${register}")
        if InstructionConfig.FPR_ABI_NAMES == AbiNames.o32:
            return self.Cop1O32RegisterNames.get(register, f"${register}")
        if InstructionConfig.FPR_ABI_NAMES == AbiNames.n32:
            return self.Cop1N32RegisterNames.get(register, f"${register}")
        # AbiNames.n64
        return self.Cop1N64RegisterNames.get(register, f"${register}")

    def getCop0RegisterName(self, register: int) -> str:
        if not InstructionConfig.NAMED_REGISTERS:
            return f"${register}"
        if InstructionConfig.VR4300_COP0_NAMED_REGISTERS:
            return self.Cop0RegisterNames.get(register, f"${register}")
        return f"${register}"

    def getCop2RegisterName(self, register: int) -> str:
        return f"${register}"

    def getGprRspRegisterName(self, register: int) -> str:
        if not InstructionConfig.NAMED_REGISTERS:
            return f"${register}"
        return self.GprRspRegisterNames.get(register, f"${register}")

    def getCop0RspRegisterName(self, register: int) -> str:
        if not InstructionConfig.NAMED_REGISTERS:
            return f"${register}"
        if InstructionConfig.VR4300_RSP_COP0_NAMED_REGISTERS:
            return self.Cop0RspRegisterNames.get(register, f"${register}")
        return f"${register}"

    def getVectorRspRegisterName(self, register: int) -> str:
        if not InstructionConfig.NAMED_REGISTERS:
            return f"${register}"
        return self.VectorRspRegisterNames.get(register, f"${register}")


    def processVectorElement(self, element: int) -> int:
        if (element & 0x8) == 0x8:
            return element & 7
        if (element & 0xC) == 0x4:
            return element & 4
        if (element & 0xE) == 0x2:
            return element & 2
        return element

    def getBranchOffset(self) -> int:
        diff = common.Utils.from2Complement(self.immediate, 16)
        return diff*4 + 4


    def processImmediate(self, immOverride: str|None=None) -> str:
        if immOverride is not None:
            return immOverride

        if not self.descriptor.isUnsigned:
            number = common.Utils.from2Complement(self.immediate, 16)
            if number < 0:
                return f"-0x{-number:X}"
            return f"0x{number:X}"

        return f"0x{self.immediate:X}"

    def processCodeParameter(self) -> str:
        code = f"{self.instr_index >> 16}"
        lower = (self.rd << 11) | (self.sa << 6) >> 6
        if lower:
            code += f", {lower}"
        return code

    def disassembleInstruction(self, immOverride: str|None=None) -> str:
        opcode = self.getOpcodeName().lower()
        if len(self.descriptor.operands) == 0:
            return opcode

        result = opcode.ljust(InstructionConfig.OPCODE_LJUST + self.extraLjustWidthOpcode, ' ') + " "
        for i, operand in enumerate(self.descriptor.operands):
            if i != 0:
                result += ", "
            result += self.instrArgumentsCallbacks[operand](self, immOverride)

        return result

    def disassembleAsData(self) -> str:
        result = ".word".ljust(InstructionConfig.OPCODE_LJUST + self.extraLjustWidthOpcode, ' ')
        result += f" 0x{self.instr:08X}"

        return result

    def disassemble(self, immOverride: str|None=None) -> str:
        if not self.isImplemented():
            result = self.disassembleAsData()
            if InstructionConfig.UNKNOWN_INSTR_COMMENT:
                result = result.ljust(40, ' ')
                result += " # "
                result += self.disassembleInstruction(immOverride)
            return result
        return self.disassembleInstruction(immOverride)


    def mapInstrToType(self) -> str|None:
        if self.isFloatInstruction():
            if self.isDoubleFloatInstruction():
                return "f64"
            else:
                return "f32"
        # Way too general instruction to ensure the type
        # if self.uniqueId == InstructionId.LW or self.uniqueId == InstructionId.SW:
        #     return "s32"
        if self.uniqueId == InstructionId.LWU:
            return "u32"
        if self.uniqueId == InstructionId.LH or self.uniqueId == InstructionId.SH:
            return "s16"
        if self.uniqueId == InstructionId.LHU:
            return "u16"
        if self.uniqueId == InstructionId.LB or self.uniqueId == InstructionId.SB:
            return "s8"
        if self.uniqueId == InstructionId.LBU:
            return "u8"
        if self.uniqueId == InstructionId.LD or self.uniqueId == InstructionId.SD:
            return "s64"
        # if self.uniqueId == InstructionId.LDU or self.uniqueId == InstructionId.SDU:
        #     return "u64"
        return None

    def isLikelyHandwritten(self):
        if self._handwrittenCategory:
            return True

        if self.isIType() and not self.isFloatInstruction():
            if self.rs in (26, 27): # "$k0", "$k1"
                return True
            elif self.rt in (26, 27): # "$k0", "$k1"
                return True

        return False


    def __str__(self) -> str:
        return self.disassemble()

    def __repr__(self) -> str:
        return self.__str__()
