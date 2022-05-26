#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from . import InstructionId, InstructionBase, instructionDescriptorDict
from .MipsInstructionConfig import InstructionConfig


class InstructionCoprocessor0(InstructionBase):
    Cop0Opcodes_ByFormat = {
        0b00_000: InstructionId.MFC0,
        0b00_001: InstructionId.DMFC0,
        0b00_010: InstructionId.CFC0,
        # 0b00_011: "",
        0b00_100: InstructionId.MTC0,
        0b00_101: InstructionId.DMTC0,
        0b00_110: InstructionId.CTC0,
        # 0b00_111: "",
    }
    Cop0Opcodes_ByFunction = {
        0b000_001: InstructionId.TLBR,
        0b000_010: InstructionId.TLBWI,
        0b000_110: InstructionId.TLBWR,
        0b001_000: InstructionId.TLBP,
        0b011_000: InstructionId.ERET,
    }

    def __init__(self, instr: int):
        super().__init__(instr)

        self.processUniqueId()
        self._handwrittenCategory = True


    def processUniqueId(self):
        if self.fmt in InstructionCoprocessor0.Cop0Opcodes_ByFormat:
            self.uniqueId = InstructionCoprocessor0.Cop0Opcodes_ByFormat[self.fmt]
        elif self.fmt == 0b01_000: # fmt = BC
            if self.tf:
                if self.nd:
                    self.uniqueId = InstructionId.BC0TL
                else:
                    self.uniqueId = InstructionId.BC0T
            else:
                if self.nd:
                    self.uniqueId = InstructionId.BC0FL
                else:
                    self.uniqueId = InstructionId.BC0F
        elif self.function in InstructionCoprocessor0.Cop0Opcodes_ByFunction:
            self.uniqueId = InstructionCoprocessor0.Cop0Opcodes_ByFunction[self.function]

        self.descriptor = instructionDescriptorDict[self.uniqueId]

    def blankOut(self):
        if self.fmt in InstructionCoprocessor0.Cop0Opcodes_ByFormat:
            self.rt = 0
            self.rd = 0
            self.sa = 0
            self.function = 0
        elif self.fmt == 0b01_000:
            self.rd = 0
            self.sa = 0
            self.function = 0
        elif self.function in InstructionCoprocessor0.Cop0Opcodes_ByFunction:
            self.rt = 0
            self.rd = 0
            self.sa = 0
