#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from . import InstructionId, InstructionVectorId, InstructionNormal, instructionDescriptorDict
from .MipsInstructionConfig import InstructionConfig


class InstructionNormalRsp(InstructionNormal):
    RemovedOpcodes: dict[int, InstructionId] = {
        0b010_100: InstructionId.BEQL,
        0b010_101: InstructionId.BNEL,
        0b010_110: InstructionId.BLEZL,
        0b010_111: InstructionId.BGTZL,

        0b011_000: InstructionId.DADDI,
        0b011_001: InstructionId.DADDIU,
        0b011_010: InstructionId.LDL,
        0b011_011: InstructionId.LDR,

        0b100_010: InstructionId.LWL,
        0b100_110: InstructionId.LWR,
        0b100_111: InstructionId.LWU,

        0b101_010: InstructionId.SWL,
        0b101_100: InstructionId.SDL,
        0b101_101: InstructionId.SDR,
        0b101_110: InstructionId.SWR,

        0b110_000: InstructionId.LL,
        0b110_010: InstructionId.LWC2,
        0b110_100: InstructionId.LLD,
        0b110_101: InstructionId.LDC1,
        0b110_110: InstructionId.LDC2,
        0b110_111: InstructionId.LD,

        0b111_000: InstructionId.SC,
        0b111_010: InstructionId.SWC2,
        0b111_100: InstructionId.SCD,
        0b111_101: InstructionId.SDC1,
        0b111_110: InstructionId.SDC2,
        0b111_111: InstructionId.SD,
    }
    Opcodes_BySWC2: dict[int, InstructionVectorId] = {
        0b00_000: InstructionVectorId.SBV,
        0b00_001: InstructionVectorId.SSV,
        0b00_010: InstructionVectorId.SLV,
        0b00_011: InstructionVectorId.SDV,

        0b00_100: InstructionVectorId.SQV,
        0b00_101: InstructionVectorId.SRV,

        0b00_110: InstructionVectorId.SPV,

        # 0b00_111: InstructionVectorId.SUV,
        0b00_111: InstructionVectorId.SWV,

        0b01_000: InstructionVectorId.SHV,
        0b01_001: InstructionVectorId.SFV,

        0b01_011: InstructionVectorId.STV,
    }
    Opcodes_ByLWC2: dict[int, InstructionVectorId] = {
        0b00_000: InstructionVectorId.LBV,
        0b00_001: InstructionVectorId.LSV,
        0b00_010: InstructionVectorId.LLV,
        0b00_011: InstructionVectorId.LDV,

        0b00_100: InstructionVectorId.LQV,
        0b00_101: InstructionVectorId.LRV,

        0b00_110: InstructionVectorId.LPV,

        0b00_111: InstructionVectorId.LUV,

        0b01_000: InstructionVectorId.LHV,
        0b01_001: InstructionVectorId.LFV,

        0b01_011: InstructionVectorId.LTV,
    }

    def __init__(self, instr: int):
        super().__init__(instr)

        self.processUniqueId()
        self._handwrittenCategory = True


    def processUniqueId(self):
        if self.opcode not in self.RemovedOpcodes:
            self.uniqueId = self.NormalOpcodes.get(self.opcode, InstructionId.INVALID)

        # SWC2
        if self.opcode == 0b111_010:
            if self.rd in self.Opcodes_BySWC2:
                self.uniqueId = self.Opcodes_BySWC2[self.rd]
                if self.elementLow == 0:
                    if self.uniqueId == InstructionVectorId.SWV:
                        self.uniqueId = InstructionVectorId.SUV
        # LWC2
        elif self.opcode == 0b110_010:
            if self.rd in self.Opcodes_ByLWC2:
                self.uniqueId = self.Opcodes_ByLWC2[self.rd]

        if self.uniqueId in instructionDescriptorDict:
            self.descriptor = instructionDescriptorDict[self.uniqueId]


    def getRegisterName(self, register: int) -> str:
        return self.getGprRspRegisterName(register)


    def disassembleInstruction(self, immOverride: str|None=None) -> str:
        opcode = self.getOpcodeName()
        formated_opcode = opcode.lower().ljust(InstructionConfig.OPCODE_LJUST + self.extraLjustWidthOpcode, ' ')
        vt = self.getVectorRspRegisterName(self.vt)
        base = self.getGprRspRegisterName(self.baseRegister)
        offset = hex(self.offsetVector)
        element = self.processVectorElement(self.elementLow)

        if self.uniqueId in (InstructionVectorId.LSV, InstructionVectorId.SSV, ):
            offset = hex(self.offsetVector << 1)
        elif self.uniqueId in (InstructionVectorId.LLV, InstructionVectorId.SLV, ):
            offset = hex(self.offsetVector << 2)
        elif self.uniqueId in (InstructionVectorId.LDV, InstructionVectorId.SDV,
                               InstructionVectorId.LPV, InstructionVectorId.SPV,
                               InstructionVectorId.LUV, InstructionVectorId.SUV, ):
            offset = hex(self.offsetVector << 3)
        elif self.uniqueId in (InstructionVectorId.LQV, InstructionVectorId.SQV,
                               InstructionVectorId.LRV, InstructionVectorId.SRV,
                               InstructionVectorId.LHV, InstructionVectorId.SHV,
                               InstructionVectorId.LFV, InstructionVectorId.SFV,
                               InstructionVectorId.LTV, InstructionVectorId.STV, InstructionVectorId.SWV, ):
            offset = hex(self.offsetVector << 4)

        result = f"{formated_opcode} "
        # SWC2, LWC2
        if self.opcode in (0b111_010, 0b110_010, ):
            result += f"{vt}[{element}],"
            result = result.ljust(14, ' ')
            result += f" {offset}({base})"

            return result

        return super().disassembleInstruction(immOverride)
