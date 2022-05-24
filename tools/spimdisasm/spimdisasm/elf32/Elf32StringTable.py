#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations


# a.k.a. strtab (string table)
class Elf32StringTable:
    def __init__(self, array_of_bytes: bytearray, offset: int, rawsize: int):
        self.strings: bytearray = array_of_bytes[offset:offset+rawsize]
        self.offset: int = offset
        self.rawsize: int = rawsize

    def __getitem__(self, key: int) -> str:
        buffer = bytearray()

        i = key
        while self.strings[i] != 0:
            buffer.append(self.strings[i])
            i += 1

        return buffer.decode()

    def __iter__(self):
        i = 0
        while i < self.rawsize:
            string = self[i]
            yield string
            i += len(string.encode()) + 1
