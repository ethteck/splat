#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from .MipsInstructionConfig import InstructionConfig
from .MipsConstants import InstructionId, instructionDescriptorDict, InstrType
from .MipsInstructionBase import InstructionBase


class InstructionSpecial(InstructionBase):
    SpecialOpcodes: dict[int, InstructionId] = {
        0b000_000: InstructionId.SLL,
        # 0b000_001: "MOVCI", # TODO
        0b000_010: InstructionId.SRL,
        0b000_011: InstructionId.SRA,
        0b000_100: InstructionId.SLLV,
        # 0b000_101: "",
        0b000_110: InstructionId.SRLV,
        0b000_111: InstructionId.SRAV,

        0b001_000: InstructionId.JR,
        0b001_001: InstructionId.JALR,
        0b001_010: InstructionId.MOVZ,
        0b001_011: InstructionId.MOVN,
        0b001_100: InstructionId.SYSCALL,
        0b001_101: InstructionId.BREAK,
        # 0b001_110: "",
        0b001_111: InstructionId.SYNC,

        0b010_000: InstructionId.MFHI,
        0b010_001: InstructionId.MTHI,
        0b010_010: InstructionId.MFLO,
        0b010_011: InstructionId.MTLO,
        0b010_100: InstructionId.DSLLV,
        # 0b010_101: "",
        0b010_110: InstructionId.DSRLV,
        0b010_111: InstructionId.DSRAV,

        0b011_000: InstructionId.MULT,
        0b011_001: InstructionId.MULTU,
        0b011_010: InstructionId.DIV,
        0b011_011: InstructionId.DIVU,
        0b011_100: InstructionId.DMULT,
        0b011_101: InstructionId.DMULTU,
        0b011_110: InstructionId.DDIV,
        0b011_111: InstructionId.DDIVU,

        0b100_000: InstructionId.ADD,
        0b100_001: InstructionId.ADDU,
        0b100_010: InstructionId.SUB,
        0b100_011: InstructionId.SUBU,
        0b100_100: InstructionId.AND,
        0b100_101: InstructionId.OR,
        0b100_110: InstructionId.XOR,
        0b100_111: InstructionId.NOR,

        # 0b101_000: "",
        # 0b101_001: "",
        0b101_010: InstructionId.SLT,
        0b101_011: InstructionId.SLTU,
        0b101_100: InstructionId.DADD,
        0b101_101: InstructionId.DADDU,
        0b101_110: InstructionId.DSUB,
        0b101_111: InstructionId.DSUBU,

        0b110_000: InstructionId.TGE,
        0b110_001: InstructionId.TGEU,
        0b110_010: InstructionId.TLT,
        0b110_011: InstructionId.TLTU,
        0b110_100: InstructionId.TEQ,
        # 0b110_101: "",
        0b110_110: InstructionId.TNE,
        # 0b110_111: "",

        0b111_000: InstructionId.DSLL,
        # 0b111_001: "",
        0b111_010: InstructionId.DSRL,
        0b111_011: InstructionId.DSRA,
        0b111_100: InstructionId.DSLL32,
        # 0b111_101: "",
        0b111_110: InstructionId.DSRL32,
        0b111_111: InstructionId.DSRA32,
    }

    def __init__(self, instr: int):
        super().__init__(instr)

        self.processUniqueId()


    def processUniqueId(self):
        self.uniqueId = self.SpecialOpcodes.get(self.function, InstructionId.INVALID)

        if InstructionConfig.PSEUDO_INSTRUCTIONS:
            if self.instr == 0:
                self.uniqueId = InstructionId.NOP
            elif self.rt == 0:
                if self.uniqueId == InstructionId.OR:
                    self.uniqueId = InstructionId.MOVE
                elif self.uniqueId == InstructionId.NOR:
                    self.uniqueId = InstructionId.NOT
            elif self.uniqueId == InstructionId.SUBU:
                if self.rs == 0:
                    self.uniqueId = InstructionId.NEGU

        self.descriptor = instructionDescriptorDict[self.uniqueId]

        if self.uniqueId == InstructionId.JALR:
            # $ra
            if self.rd != 31:
                self.descriptor = instructionDescriptorDict[InstructionId.JALR_RD]

        if InstructionConfig.SN64_DIV_FIX:
            if self.uniqueId in (InstructionId.DIV, InstructionId.DIVU):
                self.descriptor.operands = ["rs", "rt"]


    def blankOut(self):
        self.rs = 0
        self.rt = 0
        self.rd = 0
        self.sa = 0


    def disassembleInstruction(self, immOverride: str|None=None) -> str:
        patch = False

        if self.descriptor.instrType == InstrType.typeR and "code" not in self.descriptor.operands:
            if "rs" not in self.descriptor.operands and self.rs != 0:
                patch = True
            if "rt" not in self.descriptor.operands and self.rt != 0:
                patch = True
            if "rd" not in self.descriptor.operands and self.rd != 0 and self.uniqueId != InstructionId.JALR:
                patch = True
            if "sa" not in self.descriptor.operands and self.sa != 0:
                patch = True

        if InstructionConfig.SN64_DIV_FIX:
            if self.uniqueId == InstructionId.BREAK:
                patch = True

        if patch:
            patchedResult = self.disassembleAsData()
            patchedResult += " # "
            patchedResult += super().disassembleInstruction(immOverride)
            return patchedResult

        return super().disassembleInstruction(immOverride)
