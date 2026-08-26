#!/usr/bin/env python3
"""Generate a minimal MSVC6-style PE32 i386 executable for the win32 splat test.

The output is byte-stable so the test can pin expectations. The binary has
three sections — .text, .data, .bss — and a tiny DOS stub. The .text payload
is a hand-rolled x86 program that returns 0x2A from `main`.

Run from the repo root:
    python3 test/win32_app/generate.py
"""

from pathlib import Path
import struct


HERE = Path(__file__).parent
OUT = HERE / "win32_app.exe"

IMAGE_BASE = 0x00400000
SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200
HEADER_SIZE = FILE_ALIGN  # 0x200

# Section layout
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
BSS_RVA = 0x3000
BSS_VIRT_SIZE = 0x100

TEXT_BODY = bytes(
    [
        # main:
        0x55,  # push ebp
        0x89,
        0xE5,  # mov ebp, esp
        0xB8,
        0x2A,
        0x00,
        0x00,
        0x00,  # mov eax, 0x2A
        0x5D,  # pop ebp
        0xC3,  # ret
        # _start: calls main, then halts in a tiny loop.
        0xE8,
        0xF1,
        0xFF,
        0xFF,
        0xFF,  # call main (rel32 = -15)
        0xEB,
        0xFE,  # jmp $ (spin)
    ]
)

DATA_BODY = b"Hello, splat win32!\x00"


def make_section_header(
    name: bytes,
    virt_size: int,
    virt_addr: int,
    raw_size: int,
    raw_ptr: int,
    chars: int,
) -> bytes:
    return struct.pack(
        "<8sIIIIIIHHI",
        name.ljust(8, b"\x00")[:8],
        virt_size,
        virt_addr,
        raw_size,
        raw_ptr,
        0,
        0,
        0,
        0,
        chars,
    )


def pad_to(buf: bytearray, target: int, fill: int = 0x00) -> None:
    if len(buf) > target:
        raise ValueError(f"buffer overrun: {len(buf)} > {target}")
    buf.extend(bytes([fill]) * (target - len(buf)))


def build_pe() -> bytes:
    # --- DOS header + stub ---
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x80)  # e_lfanew → 0x80
    dos_stub = (
        bytes(
            [
                0x0E,
                0x1F,
                0xBA,
                0x0E,
                0x00,
                0xB4,
                0x09,
                0xCD,
                0x21,
                0xB8,
                0x01,
                0x4C,
                0xCD,
                0x21,
            ]
        )
        + b"This program cannot be run in DOS mode.\r\r\n$\x00"
    )
    full_dos = bytes(dos) + dos_stub
    # Pad to 0x80
    full_dos = full_dos.ljust(0x80, b"\x00")

    # --- PE signature + COFF header ---
    pe_sig = b"PE\x00\x00"
    num_sections = 3
    size_of_optional_header = 0xE0  # standard PE32
    characteristics = 0x010F  # EXECUTABLE_IMAGE | RELOCS_STRIPPED | LINE_NUMS_STRIPPED | LOCAL_SYMS_STRIPPED | 32BIT_MACHINE
    coff = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine = i386
        num_sections,
        0x12345678,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        size_of_optional_header,
        characteristics,
    )

    # --- Optional header (PE32) ---
    text_raw_size = (len(TEXT_BODY) + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)
    data_raw_size = (len(DATA_BODY) + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)

    text_raw_ptr = HEADER_SIZE
    data_raw_ptr = text_raw_ptr + text_raw_size
    # .bss is NOLOAD — raw_ptr = 0, raw_size = 0
    size_of_image = (BSS_RVA + BSS_VIRT_SIZE + SECTION_ALIGN - 1) & ~(SECTION_ALIGN - 1)

    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,  # Magic = PE32
        6,  # MajorLinkerVersion (MSVC 6)
        0,  # MinorLinkerVersion
        text_raw_size,  # SizeOfCode
        data_raw_size,  # SizeOfInitializedData
        BSS_VIRT_SIZE,  # SizeOfUninitializedData
        TEXT_RVA + len(TEXT_BODY) - 7,  # AddressOfEntryPoint → _start
        TEXT_RVA,  # BaseOfCode
        DATA_RVA,  # BaseOfData
        IMAGE_BASE,  # ImageBase
        SECTION_ALIGN,  # SectionAlignment
        FILE_ALIGN,  # FileAlignment
        4,  # MajorOSVersion
        0,  # MinorOSVersion
        0,  # MajorImageVersion
        0,  # MinorImageVersion
        4,  # MajorSubsystemVersion
        0,  # MinorSubsystemVersion
        0,  # Win32VersionValue
        size_of_image,
        HEADER_SIZE,  # SizeOfHeaders
        0,  # CheckSum
        3,  # Subsystem (Windows CUI)
        0,  # DllCharacteristics
        0x100000,  # SizeOfStackReserve
        0x1000,  # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,  # SizeOfHeapCommit
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )
    # 16 data directories, each {VirtualAddress, Size} = 8 bytes
    opt += b"\x00" * (16 * 8)
    assert len(opt) == size_of_optional_header, (len(opt), size_of_optional_header)

    # --- Section headers ---
    sections = b""
    sections += make_section_header(
        b".text",
        len(TEXT_BODY),
        TEXT_RVA,
        text_raw_size,
        text_raw_ptr,
        0x60000020,  # CODE | EXEC | READ
    )
    sections += make_section_header(
        b".data",
        len(DATA_BODY),
        DATA_RVA,
        data_raw_size,
        data_raw_ptr,
        0xC0000040,  # INITIALIZED_DATA | READ | WRITE
    )
    sections += make_section_header(
        b".bss",
        BSS_VIRT_SIZE,
        BSS_RVA,
        0,
        0,
        0xC0000080,  # UNINITIALIZED_DATA | READ | WRITE
    )

    # --- Assemble ---
    buf = bytearray()
    buf += full_dos
    assert len(buf) == 0x80
    buf += pe_sig + coff + opt + sections
    pad_to(buf, HEADER_SIZE)

    # .text raw
    buf += TEXT_BODY
    pad_to(buf, text_raw_ptr + text_raw_size)

    # .data raw
    buf += DATA_BODY
    pad_to(buf, data_raw_ptr + data_raw_size)

    return bytes(buf)


def main() -> None:
    pe = build_pe()
    OUT.write_bytes(pe)
    print(f"wrote {OUT} ({len(pe)} bytes)")


if __name__ == "__main__":
    main()
