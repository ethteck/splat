#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

import enum


# a.k.a. SHT (section header type)
@enum.unique
class Elf32SectionHeaderType(enum.Enum):
    NULL          =  0
    PROGBITS      =  1
    SYMTAB        =  2
    STRTAB        =  3
    RELA          =  4
    HASH          =  5
    DYNAMIC       =  6
    NOTE          =  7
    NOBITS        =  8
    REL           =  9

    MIPS_GPTAB    = 0x70000003
    MIPS_DEBUG    = 0x70000005
    MIPS_REGINFO  = 0x70000006
    MIPS_OPTIONS  = 0x7000000D
    MIPS_ABIFLAGS = 0x7000002A


# a.k.a. STT (symbol table type)
@enum.unique
class Elf32SymbolTableType(enum.Enum):
    NOTYPE       =  0
    OBJECT       =  1
    FUNC         =  2
    SECTION      =  3
    FILE         =  4
    COMMON       =  5
    TLS          =  6
    NUM          =  7
