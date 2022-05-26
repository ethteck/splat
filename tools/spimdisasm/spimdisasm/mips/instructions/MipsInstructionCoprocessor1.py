#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from . import InstructionId, InstructionBase, instructionDescriptorDict
from .MipsInstructionConfig import InstructionConfig


class InstructionCoprocessor1(InstructionBase):
    Cop1Opcodes_ByFormat = {
        0b00_000: InstructionId.MFC1,
        0b00_001: InstructionId.DMFC1,
        0b00_010: InstructionId.CFC1,

        0b00_100: InstructionId.MTC1,
        0b00_101: InstructionId.DMTC1,
        0b00_110: InstructionId.CTC1,
    }
    Cop1Opcodes_ByFunction = {
        0b000_000: { 0: InstructionId.ADD_S, 1: InstructionId.ADD_D },
        0b000_001: { 0: InstructionId.SUB_S, 1: InstructionId.SUB_D },
        0b000_010: { 0: InstructionId.MUL_S, 1: InstructionId.MUL_D },
        0b000_011: { 0: InstructionId.DIV_S, 1: InstructionId.DIV_D },

        0b000_100: { 0: InstructionId.SQRT_S, 1: InstructionId.SQRT_D },
        0b000_101: { 0: InstructionId.ABS_S,  1: InstructionId.ABS_D },
        0b000_110: { 0: InstructionId.MOV_S,  1: InstructionId.MOV_D },
        0b000_111: { 0: InstructionId.NEG_S,  1: InstructionId.NEG_D },

        0b001_000: { 0: InstructionId.ROUND_L_S, 1: InstructionId.ROUND_L_D },
        0b001_001: { 0: InstructionId.TRUNC_L_S, 1: InstructionId.TRUNC_L_D },
        0b001_010: { 0: InstructionId.CEIL_L_S, 1: InstructionId.CEIL_L_D },
        0b001_011: { 0: InstructionId.FLOOR_L_S, 1: InstructionId.FLOOR_L_D },

        0b001_100: { 0: InstructionId.ROUND_W_S, 1: InstructionId.ROUND_W_D },
        0b001_101: { 0: InstructionId.TRUNC_W_S, 1: InstructionId.TRUNC_W_D },
        0b001_110: { 0: InstructionId.CEIL_W_S, 1: InstructionId.CEIL_W_D },
        0b001_111: { 0: InstructionId.FLOOR_W_S, 1: InstructionId.FLOOR_W_D },
    }
    CompareConditionsCodes = {
        0b0_000: { 0: InstructionId.C_F_S,    1: InstructionId.C_F_D }, # False
        0b0_001: { 0: InstructionId.C_UN_S,   1: InstructionId.C_UN_D }, # UNordered
        0b0_010: { 0: InstructionId.C_EQ_S,   1: InstructionId.C_EQ_D }, # EQual
        0b0_011: { 0: InstructionId.C_UEQ_S,  1: InstructionId.C_UEQ_D }, # Unordered or EQual
        0b0_100: { 0: InstructionId.C_OLT_S,  1: InstructionId.C_OLT_D }, # Ordered or Less Than
        0b0_101: { 0: InstructionId.C_ULT_S,  1: InstructionId.C_ULT_D }, # Unordered or Less Than
        0b0_110: { 0: InstructionId.C_OLE_S,  1: InstructionId.C_OLE_D }, # Ordered or Less than or Equal
        0b0_111: { 0: InstructionId.C_ULE_S,  1: InstructionId.C_ULE_D }, # Unordered or Less than or Equal

        0b1_000: { 0: InstructionId.C_SF_S,   1: InstructionId.C_SF_D }, # Signaling False
        0b1_001: { 0: InstructionId.C_NGLE_S, 1: InstructionId.C_NGLE_D }, # Not Greater than or Less than or Equal
        0b1_010: { 0: InstructionId.C_SEQ_S,  1: InstructionId.C_SEQ_D }, # Signaling Equal
        0b1_011: { 0: InstructionId.C_NGL_S,  1: InstructionId.C_NGL_D }, # Not Greater than or Less than
        0b1_100: { 0: InstructionId.C_LT_S,   1: InstructionId.C_LT_D }, # Less than
        0b1_101: { 0: InstructionId.C_NGE_S,  1: InstructionId.C_NGE_D }, # Not Greater than or Equal
        0b1_110: { 0: InstructionId.C_LE_S,   1: InstructionId.C_LE_D }, # Less than or Equal
        0b1_111: { 0: InstructionId.C_NGT_S,  1: InstructionId.C_NGT_D }, # Not Greater than
    }
    ConvertCodes = {
        0b000: { 0b001: InstructionId.CVT_S_D, 0b100: InstructionId.CVT_S_W, 0b101: InstructionId.CVT_S_L },
        0b001: { 0b000: InstructionId.CVT_D_S, 0b100: InstructionId.CVT_D_W, 0b101: InstructionId.CVT_D_L },
        0b100: { 0b000: InstructionId.CVT_W_S, 0b001: InstructionId.CVT_W_D, },
        0b101: { 0b000: InstructionId.CVT_L_S, 0b001: InstructionId.CVT_L_D, },
    }

    def __init__(self, instr: int):
        super().__init__(instr)

        self.processUniqueId()


    def processUniqueId(self):
        if self.fmt in InstructionCoprocessor1.Cop1Opcodes_ByFormat:
            self.uniqueId = InstructionCoprocessor1.Cop1Opcodes_ByFormat[self.fmt]

        elif self.fmt == 0b01_000: # fmt = BC
            tf = (self.instr >> 16) & 0x01
            nd = (self.instr >> 17) & 0x01
            if tf:
                if nd:
                    self.uniqueId = InstructionId.BC1TL
                else:
                    self.uniqueId = InstructionId.BC1T
            else:
                if nd:
                    self.uniqueId = InstructionId.BC1FL
                else:
                    self.uniqueId = InstructionId.BC1F

        elif self.function in InstructionCoprocessor1.Cop1Opcodes_ByFunction:
            perFmt = InstructionCoprocessor1.Cop1Opcodes_ByFunction[self.function]
            fmt = self.fmt & 0x07
            if fmt in perFmt:
                self.uniqueId = perFmt[fmt]

        elif self.fc == 0b11:
            if self.cond in InstructionCoprocessor1.CompareConditionsCodes:
                perFmt = InstructionCoprocessor1.CompareConditionsCodes[self.cond]
                fmt = self.fmt & 0x07
                if fmt in perFmt:
                    self.uniqueId = perFmt[fmt]

        elif self.fc == 0b10:
            fun = self.function & 0x07
            if fun in InstructionCoprocessor1.ConvertCodes:
                perFmt = InstructionCoprocessor1.ConvertCodes[fun]
                fmt = self.fmt & 0x07
                if fmt in perFmt:
                    self.uniqueId = perFmt[fmt]

        self.descriptor = instructionDescriptorDict[self.uniqueId]

    def blankOut(self):
        if self.fmt in InstructionCoprocessor1.Cop1Opcodes_ByFormat:
            self.rt = 0
            self.rd = 0
            self.sa = 0
            self.function = 0
        elif self.fmt == 0b01_000: # fmt = BC
            self.rd = 0
            self.sa = 0
            self.function = 0
        elif self.function in InstructionCoprocessor1.Cop1Opcodes_ByFunction:
            self.rt = 0
            self.rd = 0
            self.sa = 0
        elif self.fc == 0b11 or self.fc == 0b10:
            self.rt = 0
            self.rd = 0
            self.sa = 0

    def getOpcodeName(self) -> str:
        return super().getOpcodeName().replace("_", ".")
