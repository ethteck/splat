#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

import enum


@enum.unique
class FileSectionType(enum.Enum):
    Unknown = -2
    Invalid = -1

    Text    = 1
    Data    = 2
    Rodata  = 3
    Bss     = 4
    Reloc   = 5

    @staticmethod
    def fromId(sectionId: int) -> FileSectionType:
        if sectionId == 1:
            return FileSectionType.Text
        if sectionId == 2:
            return FileSectionType.Data
        if sectionId == 3:
            return FileSectionType.Rodata
        if sectionId == 4:
            return FileSectionType.Bss
        if sectionId == 5:
            return FileSectionType.Reloc
        return FileSectionType.Invalid

    @staticmethod
    def fromStr(x: str) -> FileSectionType:
        if x == ".text":
            return FileSectionType.Text
        if x == ".data":
            return FileSectionType.Data
        if x == ".rodata":
            return FileSectionType.Rodata
        if x == ".bss":
            return FileSectionType.Bss
        if x == ".reloc":
            return FileSectionType.Reloc
        return FileSectionType.Invalid

    def toStr(self) -> str:
        if self == FileSectionType.Text:
            return ".text"
        if self == FileSectionType.Data:
            return ".data"
        if self == FileSectionType.Rodata:
            return ".rodata"
        if self == FileSectionType.Bss:
            return ".bss"
        if self == FileSectionType.Reloc:
            return ".reloc"
        return ""

    def toCapitalizedStr(self) -> str:
        if self == FileSectionType.Text:
            return "Text"
        if self == FileSectionType.Data:
            return "Data"
        if self == FileSectionType.Rodata:
            return "RoData"
        if self == FileSectionType.Bss:
            return "Bss"
        if self == FileSectionType.Reloc:
            return "Reloc"
        return ""

    def toSectionName(self) -> str:
        if self == FileSectionType.Text:
            return ".text"
        if self == FileSectionType.Data:
            return ".data"
        if self == FileSectionType.Rodata:
            return ".rodata"
        if self == FileSectionType.Bss:
            return ".bss"
        if self == FileSectionType.Reloc:
            return ".ovl"
        return ""

FileSections_ListBasic = [FileSectionType.Text, FileSectionType.Data, FileSectionType.Rodata, FileSectionType.Bss]
FileSections_ListAll = [FileSectionType.Text, FileSectionType.Data, FileSectionType.Rodata, FileSectionType.Bss, FileSectionType.Reloc]
