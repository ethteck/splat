#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

import dataclasses
import struct


# a.k.a. Shdr (section header)
@dataclasses.dataclass
class Elf32SectionHeaderEntry:
    name:       int  # word     # 0x00
    type:       int  # word     # 0x04
    flags:      int  # word     # 0x08
    addr:       int  # address  # 0x0C
    offset:     int  # offset   # 0x10
    size:       int  # word     # 0x14
    link:       int  # word     # 0x18
    info:       int  # word     # 0x1C
    addralign:  int  # word     # 0x20
    entsize:    int  # word     # 0x24
                                # 0x28

    @staticmethod
    def fromBytearray(array_of_bytes: bytearray, offset: int = 0) -> Elf32SectionHeaderEntry:
        headerFormat = ">10I"
        unpacked = struct.unpack_from(headerFormat, array_of_bytes, offset)

        return Elf32SectionHeaderEntry(*unpacked)


class Elf32SectionHeaders:
    def __init__(self, array_of_bytes: bytearray, shoff: int, shnum: int):
        self.sections: list[Elf32SectionHeaderEntry] = list()
        self.shoff: int = shoff
        self.shnum: int = shnum

        for i in range(shnum):
            sectionHeaderEntry = Elf32SectionHeaderEntry.fromBytearray(array_of_bytes, shoff + i * 0x28)
            self.sections.append(sectionHeaderEntry)
            # print(sectionHeaderEntry)

    def __getitem__(self, key: int) -> Elf32SectionHeaderEntry | None:
        if key > len(self.sections):
            return None
        return self.sections[key]

    def __iter__(self):
        for entry in self.sections:
            yield entry
