#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from . import Utils
from .FileSectionType import FileSectionType


class FileSplitEntry:
    def __init__(self, offset: int, vram: int|None, fileName: str, section: FileSectionType, nextOffset: int, isHandwritten: bool, isRsp: bool):
        self.offset: int = offset
        self.vram: int|None = vram
        self.fileName: str = fileName
        self.section: FileSectionType = section
        self.nextOffset: int = nextOffset
        self.isHandwritten: bool = isHandwritten
        self.isRsp: bool = isRsp


class FileSplitFormat:
    def __init__(self, csvPath: str|None = None):
        self.splits: list[list[str]] = list()
        if csvPath is not None:
            self.readCsvFile(csvPath)

    def __len__(self):
        return len(self.splits)

    def __iter__(self):
        section = FileSectionType.Invalid

        for i, row in enumerate(self.splits):
            offset, vram, fileName = row

            isHandwritten = False
            isRsp = False
            offset = offset.upper()
            if offset[-1] == "H":
                isHandwritten = True
                offset = offset[:-1]
            elif offset[-1] == "R":
                isRsp = True
                offset = offset[:-1]

            if fileName == ".text":
                section = FileSectionType.Text
                continue
            elif fileName == ".data":
                section = FileSectionType.Data
                continue
            elif fileName == ".rodata":
                section = FileSectionType.Rodata
                continue
            elif fileName == ".bss":
                section = FileSectionType.Bss
                continue
            elif fileName == ".end":
                break

            if vram.lower() == "none":
                vram = None
            else:
                vram = int(vram, 16)
            offset = int(offset, 16)
            nextOffset = 0xFFFFFF
            if i + 1 < len(self.splits):
                if self.splits[i+1][2] == ".end":
                    nextOffsetStr = self.splits[i+1][0]
                elif self.splits[i+1][2].startswith("."):
                    nextOffsetStr = self.splits[i+2][0]
                else:
                    nextOffsetStr = self.splits[i+1][0]
                if nextOffsetStr.upper()[-1] == "H":
                    nextOffsetStr = nextOffsetStr[:-1]
                nextOffset = int(nextOffsetStr, 16)

            yield FileSplitEntry(offset, vram, fileName, section, nextOffset, isHandwritten, isRsp)

    def readCsvFile(self, csvPath: str):
        self.splits = Utils.readCsv(csvPath)
        self.splits = [x for x in self.splits if len(x) > 0]

    def append(self, element: FileSplitEntry | list[str]):
        if isinstance(element, FileSplitEntry):

            offset = f"{element.offset:X}"
            if element.isRsp:
                offset += "R"
            elif element.isHandwritten:
                offset += "H"

            vram = "None"
            if element.vram is not None:
                vram = f"{element.vram:X}"
            fileName = element.fileName

            if element.section != FileSectionType.Invalid:
                section = element.section.toStr()
                self.splits.append(["offset", "vram", section])

            self.splits.append([offset, vram, fileName])

            # nextOffset # ignored
        elif isinstance(element, list):
            if len(element) != 3:
                # TODO: error message
                raise TypeError()
            for x in element:
                if not isinstance(x, str):
                    # TODO: error message
                    raise TypeError()
            self.splits.append(element)
        else:
            # TODO: error message
            raise TypeError()

    def appendEndSection(self, offset: int, vram: int|None):
        vramStr = "None"
        if vram is not None:
            vramStr = f"{vram:X}"
        self.splits.append([f"{offset:X}", vramStr, ".end"])
