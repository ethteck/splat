#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from . import InstructionId, InstructionSpecial


class InstructionSpecialRsp(InstructionSpecial):
    RemovedOpcodes: dict[int, InstructionId] = {
        0b001_100: InstructionId.SYSCALL,
        0b001_111: InstructionId.SYNC,

        0b010_000: InstructionId.MFHI,
        0b010_001: InstructionId.MTHI,
        0b010_010: InstructionId.MFLO,
        0b010_011: InstructionId.MTLO,
        0b010_100: InstructionId.DSLLV,
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

        0b101_100: InstructionId.DADD,
        0b101_101: InstructionId.DADDU,
        0b101_110: InstructionId.DSUB,
        0b101_111: InstructionId.DSUBU,

        0b110_000: InstructionId.TGE,
        0b110_001: InstructionId.TGEU,
        0b110_010: InstructionId.TLT,
        0b110_011: InstructionId.TLTU,
        0b110_100: InstructionId.TEQ,
        0b110_110: InstructionId.TNE,

        0b111_000: InstructionId.DSLL,
        0b111_010: InstructionId.DSRL,
        0b111_011: InstructionId.DSRA,
        0b111_100: InstructionId.DSLL32,
        0b111_110: InstructionId.DSRL32,
        0b111_111: InstructionId.DSRA32,
    }

    def __init__(self, instr: int):
        super().__init__(instr)

        for opcode in InstructionSpecialRsp.RemovedOpcodes:
            if opcode in self.opcodesDict:
                del self.opcodesDict[opcode]
        self.processUniqueId()


    def getRegisterName(self, register: int) -> str:
        return self.getGprRspRegisterName(register)
