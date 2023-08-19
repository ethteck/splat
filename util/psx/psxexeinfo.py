#! /usr/bin/env python3

from __future__ import annotations

import argparse

import hashlib
import itertools
import struct

import sys
import zlib
import dataclasses

from pathlib import Path
from typing import Optional

import rabbitizer
import spimdisasm

@dataclasses.dataclass
class PsxExe:
    # Based on https://psx-spx.consoledev.net/cdromdrive/#filenameexe-general-purpose-executable
    initial_pc: int # offset: 0x10
    initial_gp: int # offset: 0x14
    text_vram: int # offset: 0x18
    text_size: int # offset: 0x1C
    data_vram: int # offset: 0x20
    data_size: int # offset: 0x24
    bss_vram: int # offset: 0x28
    bss_size: int # offset: 0x2C
    initial_sp_base: int # offset: 0x30
    initial_sp_offset: int # offset: 0x34

    size: int
    sha1: str

    @property
    def text_offset(self) -> int:
        return self.initial_pc - self.text_vram + 0x800

    @staticmethod
    def get_info(exe_path: Path, exe_bytes: bytes) -> PsxExe:
        initial_pc = struct.unpack("<I", exe_bytes[0x10:0x10+4])[0]
        initial_gp = struct.unpack("<I", exe_bytes[0x14:0x14+4])[0]
        text_vram = struct.unpack("<I", exe_bytes[0x18:0x18+4])[0]
        text_size = struct.unpack("<I", exe_bytes[0x1C:0x1C+4])[0]
        data_vram = struct.unpack("<I", exe_bytes[0x20:0x20+4])[0]
        data_size = struct.unpack("<I", exe_bytes[0x24:0x24+4])[0]
        bss_vram = struct.unpack("<I", exe_bytes[0x28:0x28+4])[0]
        bss_size = struct.unpack("<I", exe_bytes[0x2C:0x2C+4])[0]
        initial_sp_base = struct.unpack("<I", exe_bytes[0x30:0x30+4])[0]
        initial_sp_offset = struct.unpack("<I", exe_bytes[0x34:0x34+4])[0]

        sha1 = hashlib.sha1(exe_bytes).hexdigest()

        return PsxExe(
            initial_pc,
            initial_gp,
            text_vram,
            text_size,
            data_vram,
            data_size,
            bss_vram,
            bss_size,
            initial_sp_base,
            initial_sp_offset,
            len(exe_bytes),
            sha1,
        )
