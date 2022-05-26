#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from . import InstructionId, InstructionCoprocessor0
from .MipsInstructionConfig import InstructionConfig


class InstructionCoprocessor0Rsp(InstructionCoprocessor0):
    Cop0Opcodes_ByFormat = {
        0b00_000: InstructionId.MFC0,
        0b00_100: InstructionId.MTC0,
    }

    def __init__(self, instr: int):
        super().__init__(instr)

        self.processUniqueId()
        self._handwrittenCategory = True


    def processUniqueId(self):
        self.uniqueId = self.Cop0Opcodes_ByFormat.get(self.fmt, InstructionId.INVALID)


    def disassembleInstruction(self, immOverride: str|None=None) -> str:
        opcode = self.getOpcodeName()
        formated_opcode = opcode.lower().ljust(InstructionConfig.OPCODE_LJUST + self.extraLjustWidthOpcode, ' ')
        # rt = self.getRegisterName(self.rt)
        # rd = self.getCop0RegisterName(self.rd)
        rt = self.getGprRspRegisterName(self.rt)
        rd = self.getCop0RspRegisterName(self.rd)

        if not self.isImplemented():
            return super().disassembleInstruction(immOverride)

        result = f"{formated_opcode} {rt},"
        result = result.ljust(14, ' ')
        result += f" {rd}"
        return result
