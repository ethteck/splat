#!/usr/bin/env python3
"""Generate a minimal PE32+ (x86_64) Windows executable.

Mirrors `test/win32_app/generate.py` but emits the 64-bit optional header
and uses an x86_64 instruction stream. Used by the win32 test suite to
exercise the PE32+ code path through `parse_pe`, `CapstoneDisassembler`,
and the win32 segtypes.
"""

from pathlib import Path
import struct


HERE = Path(__file__).parent
OUT = HERE / "win32_app64.exe"

IMAGE_BASE = 0x140000000  # standard PE32+ image base
SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200
HEADER_SIZE = FILE_ALIGN

TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
PDATA_RVA = 0x3000

# A tiny x86_64 program:
#   mov rax, [rip + 0xFF6]   ; load 64-bit value from .rdata (insn at 0x140001000,
#                              next IP 0x140001007, +0xFF6 = 0x140001FFD → not aligned;
#                              we'll target 0x140002000 i.e. .rdata start: disp 0xFF9).
#   mov eax, 0x2a            ; return 42
#   ret
TEXT_BODY = bytes(
    [
        0x48,
        0x8B,
        0x05,
        0xF9,
        0x0F,
        0x00,
        0x00,  # mov rax, [rip + 0xFF9]
        0xB8,
        0x2A,
        0x00,
        0x00,
        0x00,  # mov eax, 0x2A
        0xC3,  # ret
    ]
)

# 8 bytes of constant data the load above targets.
RDATA_BODY = bytes([0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00])

# A single RUNTIME_FUNCTION record covering the body of our tiny text
# routine — (BeginRVA=0x1000, EndRVA=0x100D, UnwindInfoRVA=0x4000).
PDATA_BODY = struct.pack("<III", 0x1000, 0x100D, 0x4000)


def make_section_header(name, virt_size, virt_addr, raw_size, raw_ptr, chars):
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


def build_pe() -> bytes:
    # DOS header + stub
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x80)
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
    full_dos = (bytes(dos) + dos_stub).ljust(0x80, b"\x00")

    # COFF header
    pe_sig = b"PE\x00\x00"
    # PE32+ optional header is 0xF0 bytes (28 standard + 88 windows + 128 directories
    # = 28 + 88 + 128 = 244 = 0xF4 nominal, but standard size is 0xF0).
    size_of_optional_header = 0xF0
    characteristics = 0x0022  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    num_sections = 3
    coff = struct.pack(
        "<HHIIIHH",
        0x8664,  # Machine = x86_64
        num_sections,
        0x12345678,  # TimeDateStamp
        0,
        0,
        size_of_optional_header,
        characteristics,
    )

    text_raw_size = (len(TEXT_BODY) + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)
    text_raw_ptr = HEADER_SIZE
    rdata_raw_size = (len(RDATA_BODY) + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)
    rdata_raw_ptr = text_raw_ptr + text_raw_size
    pdata_raw_size = (len(PDATA_BODY) + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)
    pdata_raw_ptr = rdata_raw_ptr + rdata_raw_size
    size_of_image = ((PDATA_RVA + len(PDATA_BODY)) + SECTION_ALIGN - 1) & ~(
        SECTION_ALIGN - 1
    )

    # PE32+ optional header (note: BaseOfData is omitted, ImageBase is QWORD,
    # SizeOfStack/Heap fields are QWORDs).
    opt = struct.pack(
        "<HBBIIIII"  # Magic..BaseOfCode
        "Q"  # ImageBase
        "II"  # SectionAlignment, FileAlignment
        "HHHHHHI"  # versions + Win32VersionValue
        "IIII"  # SizeOfImage, Headers, CheckSum, Subsystem/DllChars combined
        "QQQQ"  # Stack/Heap reserve/commit
        "II",  # LoaderFlags + NumberOfRvaAndSizes
        0x020B,  # Magic = PE32+
        14,
        0,  # MajorLinkerVersion (MSVC 14)
        text_raw_size,
        0,
        0,
        TEXT_RVA,
        TEXT_RVA,  # BaseOfCode
        IMAGE_BASE,
        SECTION_ALIGN,
        FILE_ALIGN,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        size_of_image,
        HEADER_SIZE,
        0,
        (3) | (0 << 16),  # Subsystem (CUI) lo, DllCharacteristics hi
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    opt += b"\x00" * (16 * 8)  # 16 data directories
    assert len(opt) == size_of_optional_header, (len(opt), size_of_optional_header)

    sec_text = make_section_header(
        b".text",
        len(TEXT_BODY),
        TEXT_RVA,
        text_raw_size,
        text_raw_ptr,
        0x60000020,
    )
    sec_rdata = make_section_header(
        b".rdata",
        len(RDATA_BODY),
        RDATA_RVA,
        rdata_raw_size,
        rdata_raw_ptr,
        0x40000040,
    )
    sec_pdata = make_section_header(
        b".pdata",
        len(PDATA_BODY),
        PDATA_RVA,
        pdata_raw_size,
        pdata_raw_ptr,
        0x40000040,
    )

    buf = bytearray(full_dos + pe_sig + coff + opt + sec_text + sec_rdata + sec_pdata)
    buf = buf.ljust(HEADER_SIZE, b"\x00")
    buf += TEXT_BODY
    buf = buf.ljust(text_raw_ptr + text_raw_size, b"\x00")
    buf += RDATA_BODY
    buf = buf.ljust(rdata_raw_ptr + rdata_raw_size, b"\x00")
    buf += PDATA_BODY
    buf = buf.ljust(pdata_raw_ptr + pdata_raw_size, b"\x00")
    return bytes(buf)


def main() -> None:
    pe = build_pe()
    OUT.write_bytes(pe)
    print(f"wrote {OUT} ({len(pe)} bytes)")


if __name__ == "__main__":
    main()
