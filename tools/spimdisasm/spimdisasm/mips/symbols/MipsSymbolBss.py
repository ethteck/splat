#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from ... import common

from . import SymbolBase


class SymbolBss(SymbolBase):
    def __init__(self, context: common.Context, inFileOffset: int, vram: int|None, name: str, spaceSize: int):
        super().__init__(context, inFileOffset, vram, name, list(), common.FileSectionType.Bss)

        self.spaceSize: int = spaceSize


    def disassembleAsBss(self) -> str:
        output = self.getLabel()
        output += self.generateAsmLineComment(0)
        output += f" .space 0x{self.spaceSize:02X}" + common.GlobalConfig.LINE_ENDS
        return output

    def disassemble(self) -> str:
        return self.disassembleAsBss()
