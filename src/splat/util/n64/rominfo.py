#! /usr/bin/env python3

import argparse

import hashlib
import itertools
import struct

import sys
import zlib
from dataclasses import dataclass

from pathlib import Path
from typing import Optional, List

import rabbitizer
import spimdisasm

parser = argparse.ArgumentParser(description="Gives information on N64 roms")
parser.add_argument("rom", help="path to an N64 rom")
parser.add_argument(
    "--header-encoding",
    dest="header_encoding",
    help=(
        "Text encoding the game header is using;"
        " see docs.python.org/3/library/codecs.html#standard-encodings for valid encodings"
    ),
)

country_codes = {
    0x00: "Unknown",
    0x37: "Beta",
    0x41: "Asian (NTSC)",
    0x42: "Brazilian",
    0x43: "Chinese",
    0x44: "German",
    0x45: "North America",
    0x46: "French",
    0x47: "Gateway 64 (NTSC)",
    0x48: "Dutch",
    0x49: "Italian",
    0x4A: "Japanese",
    0x4B: "Korean",
    0x4C: "Gateway 64 (PAL)",
    0x4E: "Canadian",
    0x50: "European (basic spec.)",
    0x53: "Spanish",
    0x55: "Australian",
    0x57: "Scandinavian",
    0x58: "European",
    0x59: "European",
}


@dataclass
class CIC:
    ntsc_name: str
    pal_name: str
    offset: int


crc_to_cic = {
    0x6170A4A1: CIC("6101", "7102", 0x000000),
    0x90BB6CB5: CIC("6102", "7101", 0x000000),
    0x0B050EE0: CIC("6103", "7103", 0x100000),
    0x98BC2C86: CIC("6105", "7105", 0x000000),
    0xACC8580A: CIC("6106", "7106", 0x200000),
}
unknown_cic = CIC("unknown", "unknown", 0x0000000)


@dataclass
class EntryAddressInfo:
    value: int
    rom_hi: int
    rom_lo: int

    @staticmethod
    def new(
        value: Optional[int], hi: Optional[int], lo: Optional[int]
    ) -> Optional["EntryAddressInfo"]:
        if value is not None and hi is not None and lo is not None:
            return EntryAddressInfo(value, hi, lo)
        return None


@dataclass
class N64EntrypointInfo:
    entry_size: int
    data_size: Optional[int]
    bss_start_address: Optional[EntryAddressInfo]
    bss_size: Optional[EntryAddressInfo]
    bss_end_address: Optional[EntryAddressInfo]
    main_address: Optional[EntryAddressInfo]
    stack_top: Optional[EntryAddressInfo]
    traditional_entrypoint: bool

    def segment_size(self) -> int:
        if self.data_size is not None:
            return self.entry_size + self.data_size
        return self.entry_size

    def get_bss_size(self) -> Optional[int]:
        if self.bss_size is not None:
            return self.bss_size.value
        if self.bss_start_address is not None and self.bss_end_address is not None:
            return self.bss_end_address.value - self.bss_start_address.value
        return None

    @staticmethod
    def parse_rom_bytes(
        rom_bytes, vram: int, offset: int = 0x1000, size: int = 0x60
    ) -> "N64EntrypointInfo":
        word_list = spimdisasm.common.Utils.bytesToWords(
            rom_bytes, offset, offset + size
        )
        nops_count = 0

        register_values = [0 for _ in range(32)]
        completed_pair = [False for _ in range(32)]
        hi_assignments: List[Optional[int]] = [None for _ in range(32)]
        lo_assignments: List[Optional[int]] = [None for _ in range(32)]

        register_bss_address: Optional[int] = None
        register_bss_size: Optional[int] = None
        register_main_address: Optional[int] = None

        bss_address: Optional[EntryAddressInfo] = None
        bss_size: Optional[EntryAddressInfo] = None
        bss_end_address: Optional[EntryAddressInfo] = None

        traditional_entrypoint = True
        decrementing_bss_routine = True
        data_size: Optional[int] = None
        func_call_target: Optional[EntryAddressInfo] = None

        size = 0
        i = 0
        while i < len(word_list):
            word = word_list[i]
            current_rom = offset + i * 4
            insn = rabbitizer.Instruction(word, vram)
            if not insn.isValid():
                break

            if insn.isNop():
                nops_count += 1
            elif nops_count >= 3:
                break
            elif insn.canBeHi():
                register_values[insn.rt.value] = insn.getProcessedImmediate() << 16
                completed_pair[insn.rt.value] = False
                hi_assignments[insn.rt.value] = current_rom
            elif insn.canBeLo():
                if insn.isLikelyHandwritten():
                    # Try to skip these instructions:
                    # addi        $t0, $t0, 0x8
                    # addi        $t1, $t1, -0x8
                    pass
                elif insn.modifiesRt() and not completed_pair[insn.rt.value]:
                    register_values[insn.rt.value] = (
                        register_values[insn.rs.value] + insn.getProcessedImmediate()
                    )
                    completed_pair[insn.rt.value] = True
                    if not insn.isUnsigned():
                        lo_assignments[insn.rt.value] = current_rom
                elif insn.doesStore():
                    if insn.rt == rabbitizer.RegGprO32.zero:
                        # Try to detect the zero-ing bss algorithm
                        # sw          $zero, 0x0($t0)
                        register_bss_address = insn.rs.value
            elif insn.isBranch():
                if insn.uniqueId == rabbitizer.InstrId.cpu_beq:
                    traditional_entrypoint = False
                    decrementing_bss_routine = False
                elif insn.uniqueId == rabbitizer.InstrId.cpu_bnez:
                    # Traditional entrypoints set the bss size into a register
                    # and loop through it by decrementing it, with a pattern
                    # like the following:
                    #
                    # lui         $t1, %hi(BSS_SIZE)
                    # addiu       $t1, $t1, %lo(BSS_SIZE)
                    # ...
                    # addi        $t1, $t1, -0x8
                    # ...
                    # bnez        $t1, label
                    register_bss_size = insn.rs.value

            elif insn.isJumptableJump() or insn.isReturn():
                # lui         $t2, 0x8000
                # addiu       $t2, $t2, 0x494
                # ...
                # jr          $t2
                register_main_address = insn.rs.value

            elif insn.uniqueId == rabbitizer.InstrId.cpu_sltu:
                # Some non-traditional entrypoints clear bss by loading the
                # bss start and looping though it until reaches the address
                # of the bss end instead of looping by using the bss size
                # explicitly.
                #
                # .clear_bss:
                # addiu      $t0, $t0, 0x4
                # sltu       $at, $t0, $t1
                # bnez       $at, .clear_bss
                #  sw        $zero, -0x4($t0)
                if bss_address is None and bss_size is None:
                    bss_address = EntryAddressInfo.new(
                        register_values[insn.rs.value],
                        hi_assignments[insn.rs.value],
                        lo_assignments[insn.rs.value],
                    )
                    bss_end_address = EntryAddressInfo.new(
                        register_values[insn.rt.value],
                        hi_assignments[insn.rt.value],
                        lo_assignments[insn.rt.value],
                    )

            elif insn.isFunctionCall():
                # Some games don't follow the usual pattern for entrypoints.
                # Those usually use `jal` instead of `jr` to jump out of the
                # entrypoint to actual code.
                traditional_entrypoint = False
                func_call_target = EntryAddressInfo(
                    insn.getInstrIndexAsVram(), current_rom, current_rom
                )

            elif insn.uniqueId == rabbitizer.InstrId.cpu_break:
                traditional_entrypoint = False
                size += 4
                vram += 4
                i += 1
                break

            # Traditional entrypoints don't touch the $gp register.
            if insn.modifiesRd() and insn.rd == rabbitizer.RegGprO32.gp:
                traditional_entrypoint = False
            if insn.modifiesRs() and insn.rs == rabbitizer.RegGprO32.gp:
                traditional_entrypoint = False
            if insn.modifiesRt() and insn.rt == rabbitizer.RegGprO32.gp:
                traditional_entrypoint = False

            # print(f"{word:08X}", insn)
            size += 4
            vram += 4
            i += 1

        # for i, val in enumerate(register_values):
        #     if val != 0:
        #         print(i, f"{val:08X}")

        if decrementing_bss_routine:
            if register_bss_address is not None:
                bss_address = EntryAddressInfo.new(
                    register_values[register_bss_address],
                    hi_assignments[register_bss_address],
                    lo_assignments[register_bss_address],
                )
            if register_bss_size is not None:
                bss_size = EntryAddressInfo.new(
                    register_values[register_bss_size],
                    hi_assignments[register_bss_size],
                    lo_assignments[register_bss_size],
                )

        if register_main_address is not None:
            main_address = EntryAddressInfo.new(
                register_values[register_main_address],
                hi_assignments[register_main_address],
                lo_assignments[register_main_address],
            )
        else:
            main_address = None

        stack_top = EntryAddressInfo.new(
            register_values[rabbitizer.RegGprO32.sp.value],
            hi_assignments[rabbitizer.RegGprO32.sp.value],
            lo_assignments[rabbitizer.RegGprO32.sp.value],
        )

        if not traditional_entrypoint:
            if func_call_target is not None:
                main_address = func_call_target
                if func_call_target.value > vram:
                    # Some weird-entrypoint games have non-code between the
                    # entrypoint and the actual user code.
                    # We try to find where actual code may begin, and tag
                    # everything in between as "entrypoint data".

                    code_start = find_code_after_data(rom_bytes, offset + i * 4, vram)
                    if code_start is not None and code_start > offset + size:
                        data_size = code_start - (offset + size)

        return N64EntrypointInfo(
            size,
            data_size,
            bss_address,
            bss_size,
            bss_end_address,
            main_address,
            stack_top,
            traditional_entrypoint,
        )


def find_code_after_data(
    rom_bytes: bytes, offset: int, vram: int, threshold: int = 0x18000
) -> Optional[int]:
    code_offset: Optional[int] = None

    # We loop through every word until we find a valid `jr $ra` instruction and
    # hope for it to be part of valid code.
    # Once we find it, we loop back until we find anything that is invalid
    # again to try to find the start of this function.

    jr_ra_found = False
    while offset < len(rom_bytes) // 4 and offset < threshold:
        word = spimdisasm.common.Utils.bytesToWords(rom_bytes, offset, offset + 4)[0]
        insn = rabbitizer.Instruction(word, vram)

        if insn.isValid() and insn.isReturn():
            # Check the instruction on the delay slot of the `jr $ra` is valid too.
            next_word = spimdisasm.common.Utils.bytesToWords(
                rom_bytes, offset + 4, offset + 4 + 4
            )[0]
            if rabbitizer.Instruction(next_word, vram + 4).isValid():
                jr_ra_found = True
                break

        vram += 4
        offset += 4

    if jr_ra_found:
        code_offset = offset

        vram -= 4
        offset -= 4

        while offset >= 0:
            word = spimdisasm.common.Utils.bytesToWords(rom_bytes, offset, offset + 4)[
                0
            ]
            insn = rabbitizer.Instruction(word, vram)

            if not insn.isValid():
                # Garbage instructions, stop
                break

            if not insn.isNop():
                # Ignore `nop`s as the code start since they may be file padding.
                code_offset = offset

            vram -= 4
            offset -= 4
    return code_offset


@dataclass
class N64Rom:
    name: str
    header_encoding: str
    country_code: int
    libultra_version: str
    checksum: str
    cic: CIC
    entry_point: int
    size: int
    compiler: str
    sha1: str
    entrypoint_info: N64EntrypointInfo

    def get_country_name(self) -> str:
        return country_codes[self.country_code]


def swap_bytes(data):
    return bytes(
        itertools.chain.from_iterable(
            struct.pack(">H", x) for (x,) in struct.iter_unpack("<H", data)
        )
    )


def read_rom(rom_path: Path):
    rom_bytes = rom_path.read_bytes()

    if rom_path.suffix.lower() == ".n64":
        print("Warning: Input file has .n64 suffix, byte-swapping!")
        rom_bytes = swap_bytes(rom_bytes)
        as_z64 = rom_path.with_suffix(".z64")
        if not as_z64.exists():
            print(f"Writing down {as_z64}")
            as_z64.write_bytes(rom_bytes)
    return rom_bytes


def get_cic(rom_bytes: bytes):
    ipl3_crc = zlib.crc32(rom_bytes[0x40:0x1000])

    return crc_to_cic.get(ipl3_crc, unknown_cic)


def get_entry_point(program_counter: int, cic: CIC):
    return program_counter - cic.offset


def guess_header_encoding(rom_bytes: bytes):
    header = rom_bytes[0x20:0x34]
    encodings = ["ASCII", "shift_jis", "euc-jp"]
    for encoding in encodings:
        try:
            header.decode(encoding)
            return encoding
        except UnicodeDecodeError:
            # we guessed wrong...
            pass

    sys.exit("Unknown header encoding, please raise an Issue with us")


def get_info(
    rom_path: Path, rom_bytes: Optional[bytes] = None, header_encoding=None
) -> N64Rom:
    if rom_bytes is None:
        rom_bytes = read_rom(rom_path)

    if header_encoding is None:
        header_encoding = guess_header_encoding(rom_bytes)

    return get_info_bytes(rom_bytes, header_encoding)


def get_info_bytes(rom_bytes: bytes, header_encoding: str) -> N64Rom:
    (program_counter,) = struct.unpack(">I", rom_bytes[0x8:0xC])
    libultra_version = chr(rom_bytes[0xF])
    checksum = rom_bytes[0x10:0x18].hex().upper()

    try:
        name = rom_bytes[0x20:0x34].decode(header_encoding).rstrip(" \0") or "empty"
    except:
        sys.exit(
            "splat could not decode the game name;"
            " try using a different encoding by passing the --header-encoding argument"
            " (see docs.python.org/3/library/codecs.html#standard-encodings for valid encodings)"
        )

    country_code = rom_bytes[0x3E]

    cic = get_cic(rom_bytes)
    entry_point = get_entry_point(program_counter, cic)

    compiler = get_compiler_info(rom_bytes, entry_point, print_result=False)

    sha1 = hashlib.sha1(rom_bytes).hexdigest()

    entrypoint_info = N64EntrypointInfo.parse_rom_bytes(
        rom_bytes, entry_point, size=0x100
    )

    return N64Rom(
        name,
        header_encoding,
        country_code,
        libultra_version,
        checksum,
        cic,
        entry_point,
        len(rom_bytes),
        compiler,
        sha1,
        entrypoint_info,
    )


def get_compiler_info(rom_bytes, entry_point, print_result=True):
    jumps = 0
    branches = 0

    word_list = spimdisasm.common.Utils.bytesToWords(rom_bytes[0x1000:])
    for word in word_list:
        insn = rabbitizer.Instruction(word)
        if not insn.isImplemented():
            break

        if insn.uniqueId == rabbitizer.InstrId.cpu_j:
            jumps += 1
        elif insn.uniqueId == rabbitizer.InstrId.cpu_b:
            branches += 1

    compiler = "IDO" if branches > jumps else "KMC"
    if print_result:
        print(
            f"{branches} branches and {jumps} jumps detected in the first code segment."
            f" Compiler is most likely {compiler}"
        )
    return compiler


def main():
    rabbitizer.config.pseudos_pseudoB = True

    args = parser.parse_args()
    rom_bytes = read_rom(Path(args.rom))
    rom = get_info(Path(args.rom), rom_bytes, args.header_encoding)

    print("Image name: " + rom.name)
    print("Country code: " + chr(rom.country_code) + " - " + rom.get_country_name())
    print("Libultra version: " + rom.libultra_version)
    print("Checksum: " + rom.checksum)
    print("CIC: " + rom.cic.ntsc_name + " / " + rom.cic.pal_name)
    print("RAM entry point: " + hex(rom.entry_point))
    print("Header encoding: " + rom.header_encoding)
    print("")

    get_compiler_info(rom_bytes, rom.entry_point)


if __name__ == "__main__":
    main()
