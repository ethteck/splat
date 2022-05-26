#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from . import InstructionId, InstructionVectorId, InstructionCoprocessor2
from .MipsInstructionConfig import InstructionConfig


class InstructionCoprocessor2Rsp(InstructionCoprocessor2):
    Cop2Opcodes: dict[int, InstructionVectorId] = {
        0x00: InstructionVectorId.VMULF,
        0x01: InstructionVectorId.VMULU,
        0b000_010: InstructionVectorId.VRNDP,
        0b000_011: InstructionVectorId.VMULQ,
        0x04: InstructionVectorId.VMUDL,
        0x05: InstructionVectorId.VMUDM,
        0x06: InstructionVectorId.VMUDN,
        0x07: InstructionVectorId.VMUDH,
        0x08: InstructionVectorId.VMACF,
        0x09: InstructionVectorId.VMACU,
        0b001_010: InstructionVectorId.VRNDN,
        0b001_011: InstructionVectorId.VMACQ,
        0x0C: InstructionVectorId.VMADL,
        0x0D: InstructionVectorId.VMADM,
        0x0E: InstructionVectorId.VMADN,
        0x0F: InstructionVectorId.VMADH,
        0x10: InstructionVectorId.VADD,
        0b010_001: InstructionVectorId.VSUB,
        0b010_011: InstructionVectorId.VABS,
        0x14: InstructionVectorId.VADDC,
        0b010_101: InstructionVectorId.VSUBC,
        0x1D: InstructionVectorId.VSAR,
        0x28: InstructionVectorId.VAND,
        0x29: InstructionVectorId.VNAND,
        0x2A: InstructionVectorId.VOR,
        0x2B: InstructionVectorId.VNOR,
        0x2C: InstructionVectorId.VXOR,
        0x2D: InstructionVectorId.VNXOR,

        0x20: InstructionVectorId.VLT,
        0x21: InstructionVectorId.VEQ,
        0x22: InstructionVectorId.VNE,
        0x23: InstructionVectorId.VGE,
        0x24: InstructionVectorId.VCL,
        0x25: InstructionVectorId.VCH,
        0x26: InstructionVectorId.VCR,
        0x27: InstructionVectorId.VMRG,

        0b110_000: InstructionVectorId.VRCP,
        0b110_001: InstructionVectorId.VRCPL,
        0b110_010: InstructionVectorId.VRCPH,
        0b110_011: InstructionVectorId.VMOV,
        0b110_100: InstructionVectorId.VRSQ,
        0b110_101: InstructionVectorId.VRSQL,
        0b110_110: InstructionVectorId.VRSQH,
        0b110_111: InstructionVectorId.VNOP,
    }
    Cop2MoveOpcodes: dict[int, InstructionVectorId] = {
        0b00_000: InstructionVectorId.MFC2,
        0b00_100: InstructionVectorId.MTC2,
        0b00_010: InstructionVectorId.CFC2,
        0b00_110: InstructionVectorId.CTC2,
    }

    def __init__(self, instr: int):
        super().__init__(instr)

        self.processUniqueId()
        self._handwrittenCategory = True


    def processUniqueId(self):
        super().processUniqueId()

        self.uniqueId = self.Cop2Opcodes.get(self.function, InstructionVectorId.INVALID)
        if self[25] == 0:
            self.uniqueId = self.Cop2MoveOpcodes.get(self.elementHigh, InstructionVectorId.INVALID)


    def modifiesRt(self) -> bool:
        if self.uniqueId in (InstructionVectorId.CFC2, InstructionVectorId.MFC2):
            return True
        return super().modifiesRt()


    def disassembleInstruction(self, immOverride: str|None=None) -> str:
        opcode = self.getOpcodeName()
        formated_opcode = opcode.lower().ljust(InstructionConfig.OPCODE_LJUST + self.extraLjustWidthOpcode, ' ')
        e_upper = self[25]
        e = self.processVectorElement(self.elementHigh)
        vt = self.getVectorRspRegisterName(self.vt)
        vs = self.getVectorRspRegisterName(self.vs)
        vd = self.getVectorRspRegisterName(self.vd)

        result = formated_opcode

        if self.uniqueId == InstructionVectorId.VNOP:
            return opcode.lower()

        if self.uniqueId in (InstructionVectorId.VMOV, InstructionVectorId.VRCP, InstructionVectorId.VRCPH, InstructionVectorId.VRSQ, InstructionVectorId.VRSQH, InstructionVectorId.VRSQL):
            result += f" {vd}[{self.vs}], "
            result = result.ljust(14, ' ')
            result += f" {vt}[{e}]"
            return result

        if e_upper == 0:
            rt = f"${self.rt}"
            rd = f"${self.rd}"
            result += f" {rt},"
            result = result.ljust(14, ' ')
            if self.uniqueId in (InstructionVectorId.CFC2, InstructionVectorId.CTC2):
                result += f" {rd}"
            else:
                # TODO: improve
                index = self.sa>>1
                # TODO: use vector register instead of rd
                result += f" {rd}[{index}]"
        else:
            result += f" {vd},"
            result = result.ljust(14, ' ')
            result += f" {vs},"
            result = result.ljust(19, ' ')
            result += f" {vt}"
            if self.elementHigh != 0:
                # TODO: do this properly
                result += f"[{e}]"

        if not self.isImplemented():
            result = "ERROR # " + result
        return result
