#! /usr/bin/env python3

from __future__ import annotations

import argparse

import hashlib
import struct

import dataclasses

from pathlib import Path

import rabbitizer
import spimdisasm

# PSX EXE has the following layout
# header   ; 0x80 bytes
# padding  ; 0x780 bytes
# .rodata  ; variable length
# .text    ; variable length
# .data    ; variable length
# .sdata   ; variable length
# .bss     ; variable length, all zeroes
# .sbss    ; variable length, all zeroes

PAYLOAD_OFFSET = 0x800  # 0x80 byte header followed by 0x780 bytes of zeroes
WORD_SIZE_BYTES = 4

UNSUPPORTED_OPS = {
    # MIPS II
    "beql",
    "bgtzl",
    "blezl",
    "bnel",
    "ldc1",
    "ldc2",
    "ll",
    "sc",
    "sdc1",
    "sdc2",
    "sync",
    "teq",
    "tge",
    "tgei",
    "tgeiu",
    "tgeu",
    "tlt",
    "tltu",
    "tne",
    "tnei",
    # MIPS III
    "dadd",
    "daddi",
    "daddiu",
    "daddu",
    "dsub",
    "dsubu",
    "ld",
    "ldl",
    "ldr",
    "lld",
    "lwu",
    "scd",
    "sd",
    "sdl",
    "sdr",
    # MIPS IV
    "movn",
    "movz",
    "pref",
    "prefx",
}


def is_valid(insn) -> bool:
    if not insn.isValid():
        if insn.instrIdType.name in ("CPU_SPECIAL", "CPU_COP2"):
            return True
        else:
            return False

    opcode = insn.getOpcodeName()
    if opcode in UNSUPPORTED_OPS:
        return False

    return True


def try_find_text(
    rom_bytes, start_offset=PAYLOAD_OFFSET, valid_threshold=32
) -> tuple[int, int]:
    start = end = 0
    good_count = valid_count = 0

    in_text = False
    last_opcode = None

    words = struct.iter_unpack("<I", rom_bytes[start_offset:])
    for i, (word,) in enumerate(words):
        insn = rabbitizer.Instruction(word)

        if in_text:
            if not is_valid(insn):
                end = start_offset + i * WORD_SIZE_BYTES
                break
        else:
            if is_valid(insn):
                valid_count += 1

                opcode = insn.getOpcodeName()
                if last_opcode != opcode and opcode != "nop":
                    good_count += 1
            else:
                # reset
                good_count = valid_count = 0

            if good_count > valid_threshold:
                in_text = True
                start = start_offset + ((i + 1 - valid_count) * WORD_SIZE_BYTES)

            last_opcode = insn.getOpcodeName()

    return (start, end)


def try_get_gp(rom_bytes, start_offset, max_instructions=50) -> int:
    # $gp is set like this:
    # /* A7738 800B7138 0E801C3C */  lui        $gp, (0x800E0000 >> 16)
    # /* A773C 800B713C 90409C27 */  addiu      $gp, $gp, 0x4090
    gp = 0
    words = struct.iter_unpack("<I", rom_bytes[start_offset:])
    for i, (word,) in enumerate(words):
        if i > max_instructions:
            # give up
            break
        insn = rabbitizer.Instruction(word)
        if insn.getOpcodeName() == "lui" and insn.rt.name == "gp":
            gp = insn.getProcessedImmediate() << 16
        elif insn.getOpcodeName() == "addiu" and insn.rt.name == "gp":
            gp += insn.getProcessedImmediate()
            break
    return gp


def read_word(exe_bytes, offset) -> int:
    return struct.unpack("<I", exe_bytes[offset : offset + 4])[0]


@dataclasses.dataclass
class PsxExe:
    # Based on https://psx-spx.consoledev.net/cdromdrive/#filenameexe-general-purpose-executable
    entrypoint: int  # offset: 0x10
    initial_gp: int  # offset: 0x14
    destination_vram: int  # offset: 0x18
    payload_size: int  # offset: 0x1C
    # data_vram: int  # offset: 0x20
    # data_size: int  # offset: 0x24
    # bss_vram: int  # offset: 0x28
    # bss_size: int  # offset: 0x2C
    # initial_sp_base: int  # offset: 0x30
    # initial_sp_offset: int  # offset: 0x34

    text_start: int
    data_start: int

    size: int
    sha1: str

    @property
    def text_offset(self) -> int:
        return self.text_start

    @property
    def data_offset(self) -> int:
        return self.data_start

    @staticmethod
    def get_info(exe_path: Path, exe_bytes: bytes) -> PsxExe:
        entrypoint = read_word(exe_bytes, 0x10)
        destination_vram = read_word(exe_bytes, 0x18)
        payload_size = read_word(exe_bytes, 0x1C)

        text_start, data_start = try_find_text(exe_bytes)

        if text_start:
            entrypoint_rom = entrypoint + PAYLOAD_OFFSET - destination_vram
            initial_gp = try_get_gp(exe_bytes, entrypoint_rom)
        else:
            initial_gp = 0

        sha1 = hashlib.sha1(exe_bytes).hexdigest()

        return PsxExe(
            entrypoint,
            initial_gp,
            destination_vram,
            payload_size,
            text_start,
            data_start,
            len(exe_bytes),
            sha1,
        )


def main():
    parser = argparse.ArgumentParser(description="Gives information on PSX EXEs")
    parser.add_argument("exe", help="Path to an PSX EXE")

    args = parser.parse_args()

    exe_path = Path(args.exe)
    exe_bytes = exe_path.read_bytes()
    exe = PsxExe.get_info(exe_path, exe_bytes)

    print(f"Entrypoint: 0x{exe.entrypoint:08X}")

    print(f"Initial GP: ", end="")
    if exe.initial_gp != 0:
        print(f"0x{exe.initial_gp:08X}")
    else:
        print(f"No")

    print()
    print(f"Destination VRAM: 0x{exe.destination_vram:08X}")
    print(f"Payload size (without header): 0x{exe.payload_size:X}")

    print()
    print(f"Text binary offset (estimate): 0x{exe.text_offset:X}")
    if exe.data_offset != 0:
        print(f"Data binary offset (estimate): 0x{exe.data_offset:X}")

    print()
    print(f"File size: 0x{exe.size:X}")
    print(f"sha1: {exe.sha1}")


if __name__ == "__main__":
    main()
