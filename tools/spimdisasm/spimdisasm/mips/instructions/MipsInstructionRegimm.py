#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from . import InstructionId, InstructionBase, instructionDescriptorDict


class InstructionRegimm(InstructionBase):
    RegimmOpcodes: dict[int, InstructionId] = {
        0b00_000: InstructionId.BLTZ,
        0b00_001: InstructionId.BGEZ,
        0b00_010: InstructionId.BLTZL,
        0b00_011: InstructionId.BGEZL,

        0b01_000: InstructionId.TGEI,
        0b01_001: InstructionId.TGEIU,
        0b01_010: InstructionId.TLTI,
        0b01_011: InstructionId.TLTIU,

        0b10_000: InstructionId.BLTZAL,
        0b10_001: InstructionId.BGEZAL,
        0b10_010: InstructionId.BLTZALL,
        0b10_011: InstructionId.BGEZALL,

        0b01_100: InstructionId.TEQI,
        0b01_110: InstructionId.TNEI,
    }

    def __init__(self, instr: int):
        super().__init__(instr)

        self.processUniqueId()


    def processUniqueId(self):
        self.uniqueId = self.RegimmOpcodes.get(self.rt, InstructionId.INVALID)

        self.descriptor = instructionDescriptorDict[self.uniqueId]


    def blankOut(self):
        self.rs = 0
        self.rd = 0
        self.sa = 0
        self.function = 0
