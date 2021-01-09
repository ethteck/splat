#! /usr/bin/python3

from capstone import *
from capstone.mips import *

import argparse
import hashlib
import rominfo
import zlib

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)

parser = argparse.ArgumentParser(description="Given a rom and start offset, find where the code ends")
parser.add_argument("rom", help="path to a .z64 rom")
parser.add_argument("start", help="start offset")
parser.add_argument("--vram", help="vram address to start disassembly at", default="0x80000000")

def run(rom_bytes, start_offset, vram):
    rom_addr = start_offset
    last_return = rom_addr

    for insn in md.disasm(rom_bytes[start_offset:], vram):
        if insn.mnemonic == "jr" and insn.op_str == "$ra":
            last_return = rom_addr
        rom_addr += 4

    return last_return + 4


def main():
    args = parser.parse_args()

    rom_bytes = rominfo.read_rom(args.rom)
    start = int(args.start, 0)
    vram = int(args.vram, 0)
    print(f"{run(rom_bytes, start, vram):X}")


if __name__ == "__main__":
    main()
