#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

# Relocation format used by overlays of Zelda64, Yoshi Story and Doubutsu no Mori (Animal Forest)

from __future__ import annotations

from ... import common

from .. import symbols

from ..MipsRelocTypes import RelocTypes

from . import SectionBase


class RelocEntry:
    def __init__(self, entry: int):
        self.sectionId = entry >> 30
        self.relocType = (entry >> 24) & 0x3F
        self.offset = entry & 0x00FFFFFF

    @property
    def reloc(self):
        return (self.sectionId << 30) | (self.relocType << 24) | (self.offset)

    def getSectionType(self) -> common.FileSectionType:
        return common.FileSectionType.fromId(self.sectionId)

    def getRelocType(self) -> RelocTypes:
        return RelocTypes.fromValue(self.relocType)

    def __str__(self) -> str:
        section = self.getSectionType().toStr()
        reloc = self.getRelocType().name
        return f"{section} {reloc} 0x{self.offset:X}"
    def __repr__(self) -> str:
        return self.__str__()


class SectionRelocZ64(SectionBase):
    def __init__(self, context: common.Context, vram: int|None, filename: str, array_of_bytes: bytearray):
        super().__init__(context, vram, filename, array_of_bytes, common.FileSectionType.Reloc)

        self.seekup = self.words[-1]

        self.setCommentOffset(self.sizew*4 - self.seekup)

        # Remove non reloc stuff
        self.words = self.words[-self.seekup // 4:]

        self.sectionSizes = {
            common.FileSectionType.Text: self.words[0],
            common.FileSectionType.Data: self.words[1],
            common.FileSectionType.Rodata: self.words[2],
            common.FileSectionType.Bss: self.words[3],
        }
        self.relocCount = self.words[4]

        self.tail = self.words[self.relocCount+5:-1]

        self.entries: list[RelocEntry] = list()
        for word in self.words[5:self.relocCount+5]:
            self.entries.append(RelocEntry(word))

        self.differentSegment: bool = False

    @property
    def nRelocs(self) -> int:
        return len(self.entries)

    @property
    def textSize(self) -> int:
        return self.sectionSizes[common.FileSectionType.Text]
    @property
    def dataSize(self) -> int:
        return self.sectionSizes[common.FileSectionType.Data]
    @property
    def rodataSize(self) -> int:
        return self.sectionSizes[common.FileSectionType.Rodata]
    @property
    def bssSize(self) -> int:
        return self.sectionSizes[common.FileSectionType.Bss]


    def analyze(self):
        localOffset = 0

        currentVram = self.getVramOffset(localOffset)
        sym = symbols.SymbolData(self.context, localOffset + self.inFileOffset, currentVram, f"{self.name}_OverlayInfo", self.words[0:4])
        sym.setCommentOffset(self.commentOffset)
        sym.endOfLineComment = [f" # _{self.name}Segment{sectName.toCapitalizedStr()}Size" for sectName in common.FileSections_ListBasic]
        sym.analyze()
        self.symbolList.append(sym)
        localOffset += 4 * 4

        currentVram = self.getVramOffset(localOffset)
        sym = symbols.SymbolData(self.context, localOffset + self.inFileOffset, currentVram, f"{self.name}_RelocCount", [self.relocCount])
        sym.setCommentOffset(self.commentOffset)
        sym.analyze()
        self.symbolList.append(sym)
        localOffset += 4

        currentVram = self.getVramOffset(localOffset)
        sym = symbols.SymbolData(self.context, localOffset + self.inFileOffset, currentVram, f"{self.name}_OverlayRelocations", [r.reloc for r in self.entries])
        sym.setCommentOffset(self.commentOffset)
        sym.endOfLineComment = [f" # {str(r)}" for r in self.entries]
        sym.analyze()
        self.symbolList.append(sym)
        localOffset += 4 * len(self.entries)

        if len(self.tail) > 0:
            currentVram = self.getVramOffset(localOffset)
            sym = symbols.SymbolData(self.context, localOffset + self.inFileOffset, currentVram, f"{self.name}_Padding", self.tail)
            sym.setCommentOffset(self.commentOffset)
            sym.analyze()
            self.symbolList.append(sym)
            localOffset += 4 * len(self.tail)

        currentVram = self.getVramOffset(localOffset)
        sym = symbols.SymbolData(self.context, localOffset + self.inFileOffset, currentVram, f"{self.name}_OverlayInfoOffset", [self.seekup])
        sym.setCommentOffset(self.commentOffset)
        sym.analyze()
        self.symbolList.append(sym)
