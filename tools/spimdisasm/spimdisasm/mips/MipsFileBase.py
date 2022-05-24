#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys
from typing import TextIO

from .. import common

from . import symbols


class FileBase(common.ElementBase):
    def __init__(self, context: common.Context, vram: int|None, filename: str, array_of_bytes: bytearray, sectionType: common.FileSectionType):
        super().__init__(context, 0, vram, filename, common.Utils.bytesToBEWords(array_of_bytes), sectionType)

        self.symbolList: list[symbols.SymbolBase] = []

        self.pointersOffsets: set[int] = set()

        self.isHandwritten: bool = False
        self.isRsp: bool = False


    def setCommentOffset(self, commentOffset: int):
        self.commentOffset = commentOffset
        for sym in self.symbolList:
            sym.setCommentOffset(self.commentOffset)

    def getVramOffset(self, localOffset: int) -> int:
        if self.vram is None:
            return self.inFileOffset + localOffset
        # return self.vram + localOffset
        return self.vram + self.inFileOffset + localOffset

    def getAsmPrelude(self) -> str:
        output = ""

        output += ".include \"macro.inc\"\n"
        output += "\n"
        output += "# assembler directives\n"
        output += ".set noat      # allow manual use of $at\n"
        output += ".set noreorder # don't insert nops after branches\n"
        output += ".set gp=64     # allow use of 64-bit general purpose registers\n"
        output += "\n"
        output += f".section {self.sectionType.toSectionName()}\n"
        output += "\n"
        output += ".balign 16\n"

        return output

    def getHash(self) -> str:
        buffer = bytearray(4*len(self.words))
        common.Utils.beWordsToBytes(self.words, buffer)
        return common.Utils.getStrHash(buffer)

    def printAnalyzisResults(self):
        pass

    def compareToFile(self, other_file: FileBase) -> dict:
        hash_one = self.getHash()
        hash_two = other_file.getHash()

        result = {
            "equal": hash_one == hash_two,
            "hash_one": hash_one,
            "hash_two": hash_two,
            "size_one": self.sizew * 4,
            "size_two": other_file.sizew * 4,
            "diff_bytes": 0,
            "diff_words": 0,
        }

        diff_bytes = 0
        diff_words = 0

        if not result["equal"]:
            min_len = min(self.sizew, other_file.sizew)
            for i in range(min_len):
                for j in range(4):
                    if (self.words[i] & (0xFF << (j * 8))) != (other_file.words[i] & (0xFF << (j * 8))):
                        diff_bytes += 1

            min_len = min(self.sizew, other_file.sizew)
            for i in range(min_len):
                if self.words[i] != other_file.words[i]:
                    diff_words += 1

        result["diff_bytes"] = diff_bytes
        result["diff_words"] = diff_words

        return result

    def blankOutDifferences(self, other: FileBase) -> bool:
        if not common.GlobalConfig.REMOVE_POINTERS:
            return False

        return False

    def removePointers(self) -> bool:
        if not common.GlobalConfig.REMOVE_POINTERS:
            return False

        return False


    def disassemble(self) -> str:
        output = ""
        for i, sym in enumerate(self.symbolList):
            output += sym.disassemble()
            if i + 1 < len(self.symbolList):
                output += "\n"
        return output

    def disassembleToFile(self, f: TextIO):
        f.write(self.getAsmPrelude())
        f.write("\n")
        f.write(self.disassemble())


    def saveToFile(self, filepath: str):
        if len(self.symbolList) == 0:
            return

        if filepath == "-":
            self.disassembleToFile(sys.stdout)
        else:
            if common.GlobalConfig.WRITE_BINARY:
                if self.sizew > 0:
                    buffer = bytearray(4*len(self.words))
                    common.Utils.beWordsToBytes(self.words, buffer)
                    common.Utils.writeBytearrayToFile(filepath + self.sectionType.toStr(), buffer)
            with open(filepath + self.sectionType.toStr() + ".s", "w") as f:
                self.disassembleToFile(f)


def createEmptyFile() -> FileBase:
    return FileBase(common.Context(), None, "", bytearray(), common.FileSectionType.Unknown)
