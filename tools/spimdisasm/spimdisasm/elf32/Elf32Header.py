#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

import dataclasses
import struct


# a.k.a. Ehdr (elf header)
@dataclasses.dataclass
class Elf32Header:
    ident:      list[int]  # 16 bytes  # 0x00
    type:       int        # half      # 0x10
    machine:    int        # half      # 0x12
    version:    int        # word      # 0x14
    entry:      int        # address   # 0x18
    phoff:      int        # offset    # 0x1C
    shoff:      int        # offset    # 0x20
    flags:      int        # word      # 0x24
    ehsize:     int        # half      # 0x28
    phentsize:  int        # half      # 0x2A
    phnum:      int        # half      # 0x2C
    shentsize:  int        # half      # 0x2E
    shnum:      int        # half      # 0x30
    shstrndx:   int        # half      # 0x32
                                       # 0x34

    @staticmethod
    def fromBytearray(array_of_bytes: bytearray, offset: int = 0) -> Elf32Header:
        identFormat = ">16B"
        ident = list(struct.unpack_from(identFormat, array_of_bytes, 0 + offset))
        # print(ident)

        headerFormat = ">HHIIIIIHHHHHH"
        unpacked = struct.unpack_from(headerFormat, array_of_bytes, 0x10 + offset)
        # print(unpacked)

        return Elf32Header(ident, *unpacked)
