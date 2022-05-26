#! /usr/bin/env python3

import argparse
import spimdisasm

parser = argparse.ArgumentParser(
    description="Given a rom and start offset, find where the code ends"
)
parser.add_argument("rom", help="path to a .z64 rom")
parser.add_argument("start", help="start offset")
parser.add_argument("--end", help="end offset", default=None)
parser.add_argument(
    "--vram", help="vram address to start disassembly at", default="0x80000000"
)


def run(rom_bytes, start_offset, vram, end_offset=None):
    rom_addr = start_offset
    last_return = rom_addr

    wordList = spimdisasm.common.Utils.bytesToBEWords(rom_bytes[start_offset:])

    for word in wordList:
        insn = spimdisasm.mips.instructions.wordToInstruction(word)
        insn.vram = vram

        if not insn.isImplemented():
            break

        # insn.rs == $ra
        if insn.uniqueId == spimdisasm.mips.instructions.InstructionId.JR and insn.rs == 31:
            last_return = rom_addr
        rom_addr += 4
        vram += 4
        if end_offset and rom_addr >= end_offset:
            break

    return last_return + (0x10 - (last_return % 0x10))


def main():
    args = parser.parse_args()

    rom_bytes = open(args.rom, "rb").read()
    start = int(args.start, 0)
    end = None
    vram = int(args.vram, 0)

    if args.end:
        end = int(args.end, 0)

    print(f"{run(rom_bytes, start, vram, end):X}")


if __name__ == "__main__":
    main()
