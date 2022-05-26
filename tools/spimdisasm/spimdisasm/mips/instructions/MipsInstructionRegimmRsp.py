#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from . import InstructionId, InstructionRegimm


class InstructionRegimmRsp(InstructionRegimm):
    RemovedOpcodes: dict[int, InstructionId] = {
        0b00_010: InstructionId.BLTZL,
        0b00_011: InstructionId.BGEZL,

        0b01_000: InstructionId.TGEI,
        0b01_001: InstructionId.TGEIU,
        0b01_010: InstructionId.TLTI,
        0b01_011: InstructionId.TLTIU,

        0b10_010: InstructionId.BLTZALL,
        0b10_011: InstructionId.BGEZALL,

        0b01_100: InstructionId.TEQI,
        0b01_110: InstructionId.TNEI,
    }

    def __init__(self, instr: int):
        super().__init__(instr)

        for opcode in self.RemovedOpcodes:
            if opcode in self.opcodesDict:
                del self.opcodesDict[opcode]

        self.processUniqueId()
        self._handwrittenCategory = True


    def getRegisterName(self, register: int) -> str:
        return self.getGprRspRegisterName(register)
