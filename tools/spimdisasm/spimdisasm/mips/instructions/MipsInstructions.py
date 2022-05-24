#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from . import InstructionBase, InstructionNormal, InstructionSpecial, InstructionRegimm, InstructionCoprocessor0, InstructionCoprocessor1, InstructionCoprocessor2, InstructionNormalRsp, InstructionSpecialRsp, InstructionRegimmRsp, InstructionCoprocessor0Rsp, InstructionCoprocessor2Rsp


def wordToInstruction(word: int) -> InstructionBase:
    if ((word >> 26) & 0x3F) == 0x00:
        return InstructionSpecial(word)
    if ((word >> 26) & 0x3F) == 0x01:
        return InstructionRegimm(word)
    if ((word >> 26) & 0x3F) == 0x10:
        return InstructionCoprocessor0(word)
    if ((word >> 26) & 0x3F) == 0x11:
        return InstructionCoprocessor1(word)
    if ((word >> 26) & 0x3F) == 0x12:
        return InstructionCoprocessor2(word)
    return InstructionNormal(word)

def wordToInstructionRsp(word: int) -> InstructionBase:
    if ((word >> 26) & 0x3F) == 0x00:
        return InstructionSpecialRsp(word)
    if ((word >> 26) & 0x3F) == 0x01:
        return InstructionRegimmRsp(word)
    if ((word >> 26) & 0x3F) == 0x10:
        return InstructionCoprocessor0Rsp(word)
    # TODO?
    # if ((word >> 26) & 0x3F) == 0x11:
    #     return InstructionCoprocessor1Rsp(word)
    if ((word >> 26) & 0x3F) == 0x12:
        return InstructionCoprocessor2Rsp(word)
    return InstructionNormalRsp(word)
