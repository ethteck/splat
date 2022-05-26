#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from ... import common

from . import InstructionId, InstructionBase, instructionDescriptorDict
from .MipsInstructionConfig import InstructionConfig


class InstructionNormal(InstructionBase):
    NormalOpcodes: dict[int, InstructionId] = {
        # 0b000_000: "SPECIAL",
        # 0b000_001: "REGIMM",
        0b000_010: InstructionId.J,
        0b000_011: InstructionId.JAL,
        0b000_100: InstructionId.BEQ,
        0b000_101: InstructionId.BNE,
        0b000_110: InstructionId.BLEZ,
        0b000_111: InstructionId.BGTZ,

        0b001_000: InstructionId.ADDI,
        0b001_001: InstructionId.ADDIU,
        0b001_010: InstructionId.SLTI,
        0b001_011: InstructionId.SLTIU,
        0b001_100: InstructionId.ANDI,
        0b001_101: InstructionId.ORI,
        0b001_110: InstructionId.XORI,
        0b001_111: InstructionId.LUI,

        # 0b010_000: "COP0", # Coprocessor OPeration z
        # 0b010_001: "COP1", # Coprocessor OPeration z
        # 0b010_010: "COP2", # Coprocessor OPeration z
        # 0b010_011: "COP3", # Coprocessor OPeration z
        0b010_100: InstructionId.BEQL,
        0b010_101: InstructionId.BNEL,
        0b010_110: InstructionId.BLEZL,
        0b010_111: InstructionId.BGTZL,

        0b011_000: InstructionId.DADDI,
        0b011_001: InstructionId.DADDIU,
        0b011_010: InstructionId.LDL,
        0b011_011: InstructionId.LDR,
        # 0b011_100: "",
        # 0b011_101: "",
        # 0b011_110: "",
        # 0b011_111: "",

        0b100_000: InstructionId.LB,
        0b100_001: InstructionId.LH,
        0b100_010: InstructionId.LWL,
        0b100_011: InstructionId.LW,
        0b100_100: InstructionId.LBU,
        0b100_101: InstructionId.LHU,
        0b100_110: InstructionId.LWR,
        0b100_111: InstructionId.LWU,

        0b101_000: InstructionId.SB,
        0b101_001: InstructionId.SH,
        0b101_010: InstructionId.SWL,
        0b101_011: InstructionId.SW,
        0b101_100: InstructionId.SDL,
        0b101_101: InstructionId.SDR,
        0b101_110: InstructionId.SWR,
        0b101_111: InstructionId.CACHE,

        0b110_000: InstructionId.LL,
        0b110_001: InstructionId.LWC1,
        0b110_010: InstructionId.LWC2,
        0b110_011: InstructionId.PREF,
        0b110_100: InstructionId.LLD,
        0b110_101: InstructionId.LDC1,
        0b110_110: InstructionId.LDC2,
        0b110_111: InstructionId.LD,

        0b111_000: InstructionId.SC,
        0b111_001: InstructionId.SWC1,
        0b111_010: InstructionId.SWC2,
        # 0b111_011: "",
        0b111_100: InstructionId.SCD,
        0b111_101: InstructionId.SDC1,
        0b111_110: InstructionId.SDC2,
        0b111_111: InstructionId.SD,
    }

    def __init__(self, instr: int):
        super().__init__(instr)

        self.processUniqueId()


    def processUniqueId(self):
        self.uniqueId = self.NormalOpcodes.get(self.opcode, InstructionId.INVALID)

        if InstructionConfig.PSEUDO_INSTRUCTIONS:
            if self.rt == 0:
                if self.uniqueId == InstructionId.BEQ:
                    if self.rs == 0:
                        self.uniqueId = InstructionId.B
                    else:
                        self.uniqueId = InstructionId.BEQZ
                elif self.uniqueId == InstructionId.BNE:
                    self.uniqueId = InstructionId.BNEZ

        self.descriptor = instructionDescriptorDict[self.uniqueId]
