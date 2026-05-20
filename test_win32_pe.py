#!/usr/bin/env python3
"""Unit tests for the win32 PE platform.

Builds tiny PE32 / PE32+ byte blobs in memory and asserts the parsed,
labelled, or YAML-emitted output is what the spec dictates. Coverage:

Parsers — every data directory + the structural headers:
  - `parse_pe`              DOS / COFF / optional header / section table,
                            fuzz-cap edge cases (bad e_lfanew, runt opt
                            header, oversize NumberOfRvaAndSizes,
                            machine/magic mismatch, etc.)
  - `parse_exports`         data dir 0 — named / ordinal-only / forwarders
  - `parse_imports`         data dir 1 — eager IAT, PE32+ thunks, hint fallback
  - `parse_resources`       data dir 2 — type/name/lang walk + depth cap
  - `parse_exception_table` data dir 3 — PE32+ RUNTIME_FUNCTION records
  - `parse_relocations`     data dir 5 — HIGHLOW / DIR64
  - `parse_debug`           data dir 6 — RSDS / NB10 CodeView records
  - `parse_tls`             data dir 9 — callback array walk
  - `parse_load_config`     data dir 10 — /GS cookie, SafeSEH, /guard:cf
  - `parse_bound_imports`   data dir 11 — descriptors + forwarder refs
  - `parse_delay_imports`   data dir 13 — v1 / v2 descriptor chains

Label generation helpers (centralised in `platforms.win32`):
  - `sanitize_label`        punctuation / leading-digit handling
  - `compute_iat_labels`    eager + delay IAT slot deduplication
  - `compute_export_labels` named + reserved-set seed collision

YAML emission (`create_win32_config`):
  - section classification (text / data / rodata / bss / pdata / bin)
  - tail-section sort (COFF symtab + Authenticode signature in file order)
  - symbol categories (entrypoint, exports, imports, delay-imports, TLS
    callbacks, SafeSEH, CFG targets, /GS cookie)
  - pathological inputs (BSS-only PEs, resource-only DLLs, all-forwarder
    shims, phantom raw-pointer-zero sections, spaces in filenames)

Detector helpers (`segtypes.win32.data`):
  - `_is_string_byte`, `_scan_string`, `_scan_wide_string`,
    `_escape_string`, `_decode_wide` — narrow + wide ANSI string
    recognition including Latin-1 Supplement.

Header rendering (`segtypes.win32.header`):
  - `_decode_flags` (unknown-bit surfacing), `_dump_optional_header`
    bound checks for runt headers, `_MACHINE_TYPES` / `_SUBSYSTEMS` /
    `_DLL_CHARACTERISTICS` table coverage.
"""

import struct
import unittest

from src.splat.platforms import win32 as win32_platform


IMAGE_BASE = 0x00400000
SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200
DOS_STUB = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)


def _opt_header_pe32_plus(
    entry_rva: int,
    base_of_code: int = 0x1000,
    data_dirs=(),
) -> bytes:
    """PE32+ optional header (240 bytes) — matches the layout
    `Win32SegHeader._dump_optional_header` expects."""
    standard = struct.pack(
        "<HBBIIIII",
        0x020B,
        14,
        0,
        0x200,
        0x200,
        0,
        entry_rva,
        base_of_code,
    )
    windows = struct.pack(
        "<QIIHHHHHHIIIIHHQQQQII",
        0x140000000,  # ImageBase
        0x1000,
        0x200,  # SectionAlignment, FileAlignment
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x4000,  # SizeOfImage
        0x200,  # SizeOfHeaders
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    dirs = b""
    for i in range(16):
        if i < len(data_dirs):
            rva, size = data_dirs[i]
        else:
            rva, size = 0, 0
        dirs += struct.pack("<II", rva, size)
    blob = standard + windows + dirs
    assert len(blob) == 240, len(blob)
    return blob


def _build_pe_plus(
    sections,
    data_dirs=(),
    entry_rva=0x1000,
) -> bytes:
    num_sections = len(sections)
    coff = struct.pack(
        "<HHIIIHH",
        0x8664,
        num_sections,
        0x12345678,
        0,
        0,
        0xF0,
        0x002F,
    )
    opt = _opt_header_pe32_plus(entry_rva, data_dirs=data_dirs)
    sec_headers = b"".join(
        _section_header(
            s["name"], s["vsize"], s["vaddr"], s["rsize"], s["rptr"], s["chars"]
        )
        for s in sections
    )
    header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec_headers
    header = header.ljust(FILE_ALIGN, b"\x00")
    end = max(s["rptr"] + s["rsize"] for s in sections)
    buf = bytearray(header.ljust(end, b"\x00"))
    for s in sections:
        body = s.get("body", b"")
        body = body.ljust(s["rsize"], b"\x00")
        buf[s["rptr"] : s["rptr"] + s["rsize"]] = body[: s["rsize"]]
    return bytes(buf)


def _opt_header_pe32(
    entry_rva: int,
    base_of_code: int = 0x1000,
    base_of_data: int = 0x2000,
    data_dirs=(),
) -> bytes:
    standard = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,  # Magic = PE32
        6,
        0,  # LinkerMajor/Minor
        0x200,  # SizeOfCode
        0x200,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        entry_rva,  # AddressOfEntryPoint
        base_of_code,
        base_of_data,
        IMAGE_BASE,
        SECTION_ALIGN,
        FILE_ALIGN,
        4,
        0,
        0,
        0,
        4,
        0,
        0,  # Win32VersionValue
        0x4000,  # SizeOfImage
        FILE_ALIGN,  # SizeOfHeaders
        0,  # CheckSum
        3,
        0,  # Subsystem, DllChars
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )
    dirs = b""
    for i in range(16):
        if i < len(data_dirs):
            rva, size = data_dirs[i]
        else:
            rva, size = 0, 0
        dirs += struct.pack("<II", rva, size)
    return standard + dirs


def _section_header(
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


def _build_pe(
    sections,
    data_dirs=(),
    entry_rva=0x1000,
) -> bytes:
    num_sections = len(sections)
    coff = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine i386
        num_sections,
        0x12345678,  # TimeDateStamp
        0,
        0,
        0xE0,  # SizeOfOptionalHeader
        0x010F,  # Characteristics
    )
    opt = _opt_header_pe32(entry_rva, data_dirs=data_dirs)
    sec_headers = b"".join(
        _section_header(
            s["name"], s["vsize"], s["vaddr"], s["rsize"], s["rptr"], s["chars"]
        )
        for s in sections
    )

    header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec_headers
    header = header.ljust(FILE_ALIGN, b"\x00")

    end = max(s["rptr"] + s["rsize"] for s in sections)
    buf = bytearray(header.ljust(end, b"\x00"))
    for s in sections:
        body = s.get("body", b"")
        body = body.ljust(s["rsize"], b"\x00")
        buf[s["rptr"] : s["rptr"] + s["rsize"]] = body[: s["rsize"]]
    return bytes(buf)


class PEParseSmoke(unittest.TestCase):
    def test_minimal_pe(self):
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
            ],
            entry_rva=0x1000,
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.machine, 0x014C)
        self.assertEqual(pe.image_base, IMAGE_BASE)
        self.assertEqual(pe.entry_point_va, IMAGE_BASE + 0x1000)
        self.assertEqual(len(pe.sections), 1)
        self.assertEqual(pe.sections[0].name, ".text")
        self.assertTrue(pe.sections[0].is_code)
        # No data dirs populated → no exports/imports/relocs/pointers.
        self.assertFalse(pe.exports)
        self.assertFalse(pe.imports)
        self.assertFalse(pe.pointer_rvas)


class PEExportsTest(unittest.TestCase):
    def test_named_export(self):
        # Place the export directory inside an .rdata section.
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        40 + 4 + 2  # past directory + funcs/names/ordinals arrays
        # Layout inside .rdata:
        #   0x00: IMAGE_EXPORT_DIRECTORY
        #   0x28: function RVA array (one entry)
        #   0x2C: name RVA array (one entry)
        #   0x30: ordinal index array (one WORD)
        #   0x32: function name string
        #   0x40: dll name string
        funcs_rva = rdata_rva + 0x28
        names_rva = rdata_rva + 0x2C
        ords_rva = rdata_rva + 0x30
        func_name_rva = rdata_rva + 0x32
        dll_name_rva = rdata_rva + 0x40
        export_dir = struct.pack(
            "<IIHHIIIIIII",
            0,
            0,
            0,
            0,
            dll_name_rva,
            1,  # ordinal base
            1,
            1,  # num funcs, num names
            funcs_rva,
            names_rva,
            ords_rva,
        )
        body = bytearray(0x60)
        body[: len(export_dir)] = export_dir
        struct.pack_into("<I", body, 0x28, 0x1000)  # func RVA → entry
        struct.pack_into("<I", body, 0x2C, func_name_rva)
        struct.pack_into("<H", body, 0x30, 0)  # ordinal index
        body[0x32 : 0x32 + 5] = b"main\x00"
        body[0x40 : 0x40 + 10] = b"mydll.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x60,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(rdata_rva, 0x60)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.export_dll_name, "mydll.dll")
        self.assertEqual(len(pe.exports), 1)
        self.assertEqual(pe.exports[0].name, "main")
        self.assertEqual(pe.exports[0].ordinal, 1)
        self.assertEqual(pe.exports[0].rva, 0x1000)


class PEOrdinalExportTest(unittest.TestCase):
    def test_ordinal_only_export(self):
        """Exports listed without a name (NumberOfFunctions >
        NumberOfNames) still need a PEExport entry — captured by
        ordinal, with .name == None."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # Layout:
        #   0x00 : IMAGE_EXPORT_DIRECTORY
        #   0x28 : funcs array (2 entries)
        #   0x30 : names array (0 entries → omitted)
        #   0x30 : ordinals array (0 entries → omitted)
        #   0x32 : DLL name
        funcs_rva = rdata_rva + 0x28
        dll_name_rva = rdata_rva + 0x32
        body = bytearray(0x80)
        struct.pack_into(
            "<IIHHIIIIIII",
            body,
            0x00,
            0,
            0,
            0,
            0,
            dll_name_rva,
            5,  # ordinal base
            2,  # num funcs
            0,  # num names
            funcs_rva,
            0,  # names_rva (unused)
            0,  # ords_rva (unused)
        )
        # Two function RVAs.
        struct.pack_into("<II", body, 0x28, 0x1000, 0x1100)
        body[0x32 : 0x32 + 11] = b"OrdLib.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x200,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x200,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(rdata_rva, 0x80)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.export_dll_name, "OrdLib.dll")
        self.assertEqual(len(pe.exports), 2)
        # Ordinal base 5 + function index 0/1 = ordinals 5/6.
        self.assertEqual(
            [(e.name, e.ordinal) for e in pe.exports], [(None, 5), (None, 6)]
        )


class PEForwardedExportTest(unittest.TestCase):
    def test_forwarder_captured(self):
        # Construct an export directory where the single function RVA falls
        # inside the export directory's own range — that flags it as a
        # forwarder. The forwarder string sits at func_rva.
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        export_dir_size = 0x60
        # Layout inside .rdata:
        #   0x00 : IMAGE_EXPORT_DIRECTORY
        #   0x28 : function RVA array (one entry pointing at the forwarder string)
        #   0x2C : name RVA array (one entry)
        #   0x30 : ordinal index
        #   0x32 : forwarder string ("KERNEL32.Sleep")
        #   0x50 : exported name ("MySleep")
        #   0x58 : dll name
        funcs_rva = rdata_rva + 0x28
        names_rva = rdata_rva + 0x2C
        ords_rva = rdata_rva + 0x30
        forwarder_rva = rdata_rva + 0x32
        export_name_rva = rdata_rva + 0x50
        dll_name_rva = rdata_rva + 0x58

        body = bytearray(0x80)
        struct.pack_into(
            "<IIHHIIIIIII",
            body,
            0x00,
            0,
            0,
            0,
            0,
            dll_name_rva,
            1,
            1,
            1,
            funcs_rva,
            names_rva,
            ords_rva,
        )
        struct.pack_into("<I", body, 0x28, forwarder_rva)
        struct.pack_into("<I", body, 0x2C, export_name_rva)
        struct.pack_into("<H", body, 0x30, 0)
        # Forwarder string
        body[0x32 : 0x32 + 15] = b"KERNEL32.Sleep\x00"
        # Export name
        body[0x50 : 0x50 + 8] = b"MySleep\x00"
        # DLL name
        body[0x58 : 0x58 + 9] = b"mydll.dll"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": export_dir_size,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(rdata_rva, export_dir_size)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.exports), 1)
        self.assertEqual(pe.exports[0].name, "MySleep")
        self.assertEqual(pe.exports[0].forwarder, "KERNEL32.Sleep")


class PEImportsTest(unittest.TestCase):
    def test_named_import(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        # Layout inside .rdata:
        #   0x00: IMAGE_IMPORT_DESCRIPTOR (20 bytes)
        #   0x14: IMAGE_IMPORT_DESCRIPTOR null terminator (20 bytes of zero)
        #   0x28: ILT array (one DWORD + null terminator)
        #   0x30: IAT array (mirrors ILT)
        #   0x38: IMAGE_IMPORT_BY_NAME (hint + name)
        #   0x48: DLL name
        ilt_rva = rdata_rva + 0x28
        iat_rva = rdata_rva + 0x30
        ibn_rva = rdata_rva + 0x38
        dll_name_rva = rdata_rva + 0x48

        body = bytearray(0x60)
        struct.pack_into(
            "<IIIII",
            body,
            0x00,
            ilt_rva,
            0,
            0,
            dll_name_rva,
            iat_rva,
        )
        # Descriptor terminator already zeroed.
        struct.pack_into("<I", body, 0x28, ibn_rva)
        struct.pack_into("<I", body, 0x2C, 0)  # ILT terminator
        struct.pack_into("<I", body, 0x30, ibn_rva)
        struct.pack_into("<I", body, 0x34, 0)
        struct.pack_into("<H", body, 0x38, 0)  # hint
        body[0x3A : 0x3A + 10] = b"DoStuff\x00"
        body[0x48 : 0x48 + 11] = b"OTHER.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x60,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 40)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.imports), 1)
        self.assertEqual(pe.imports[0].dll, "OTHER.dll")
        self.assertEqual(pe.imports[0].name, "DoStuff")
        self.assertEqual(pe.imports[0].iat_rva, iat_rva)
        self.assertIsNone(pe.imports[0].ordinal)


class PEDebugTest(unittest.TestCase):
    def test_nb10_pdb_path(self):
        """CodeView 5.0 (NB10) records carry a 4-byte signature + 4-byte
        age + NUL-terminated path. Cover the older format separately
        from RSDS, since legacy MSVC 6 binaries (Europa1400 etc.) use it."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # NB10 layout: 'NB10' + offset(4) + signature(4) + age(4) + name
        cv_record = (
            b"NB10"
            + struct.pack("<I", 0)  # CodeView offset (always 0)
            + struct.pack("<I", 0x3FFD22BC)  # signature (matches Europa1400)
            + struct.pack("<I", 2)  # age
            + b"legacy.pdb\x00"
        )
        entry = struct.pack(
            "<IIHHIIII",
            0,
            0,
            0,
            0,
            2,  # IMAGE_DEBUG_TYPE_CODEVIEW
            len(cv_record),
            rdata_rva + 28,  # AddressOfRawData
            rdata_rptr + 28,  # PointerToRawData
        )
        body = bytearray(0x100)
        body[0:28] = entry
        body[28 : 28 + len(cv_record)] = cv_record

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, 28),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.pdb_path, "legacy.pdb")
        self.assertEqual(pe.pdb_age, 2)
        self.assertEqual(pe.pdb_guid, "3FFD22BC")

    def test_rsds_pdb_path(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # Debug directory: 28 bytes per entry.
        debug_dir_rva = rdata_rva
        cv_rva = rdata_rva + 28  # CodeView record sits right after the entry
        # CodeView RSDS layout: 'RSDS' (4) + GUID (16) + age (4) + name
        # GUID: 11223344-5566-7788-99AA-BBCCDDEEFF00 in mixed endianness
        cv_record = (
            b"RSDS"
            + bytes.fromhex("44332211")  # uint32 LE
            + bytes.fromhex("6655")  # uint16 LE
            + bytes.fromhex("8877")  # uint16 LE
            + bytes.fromhex("99AABBCCDDEEFF00")  # 8 raw bytes
            + struct.pack("<I", 7)  # age
            + b"my.pdb\x00"
        )
        entry = struct.pack(
            "<IIHHIIII",
            0,  # characteristics
            0,  # timestamp
            0,
            0,  # major/minor version
            2,  # IMAGE_DEBUG_TYPE_CODEVIEW
            len(cv_record),  # SizeOfData
            cv_rva,  # AddressOfRawData
            rdata_rptr + 28,  # PointerToRawData
        )
        body = bytearray(0x100)
        body[0:28] = entry
        body[28 : 28 + len(cv_record)] = cv_record

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            # Debug dir is index 6.
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (debug_dir_rva, 28),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.pdb_path, "my.pdb")
        self.assertEqual(pe.pdb_age, 7)
        self.assertEqual(
            pe.pdb_guid,
            "11223344-5566-7788-99-AA-BB-CC-DD-EE-FF-00",
        )


class PETlsTest(unittest.TestCase):
    def test_pe32_plus_tls_callbacks(self):
        """PE32+ IMAGE_TLS_DIRECTORY puts AddressOfCallBacks at +0x18 as
        an 8-byte VA, and each callback slot is a QWORD. Verify the
        64-bit code path (the other test covers the 4-byte PE32 form)."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        callbacks_va = 0x140000000 + rdata_rva + 0x60
        cb_a = 0x140000000 + 0x1000
        cb_b = 0x140000000 + 0x1100

        body = bytearray(0x200)
        # IMAGE_TLS_DIRECTORY64 layout: 5 QWORDs + 2 DWORDs.
        # AddressOfCallBacks is the 4th QWORD at offset 0x18.
        struct.pack_into("<Q", body, 0x18, callbacks_va)
        # Callbacks array (3 QWORDs: two callbacks + NUL).
        struct.pack_into("<QQQ", body, 0x60, cb_a, cb_b, 0)

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x200,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, 0x28),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(pe.tls_callback_vas, [cb_a, cb_b])

    def test_tls_callbacks(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # TLS directory layout (PE32): 24+ bytes; AddressOfCallBacks at +0x0C.
        callbacks_va = IMAGE_BASE + rdata_rva + 0x40
        # Two callbacks then a NULL terminator.
        cb_va_a = IMAGE_BASE + 0x1000
        cb_va_b = IMAGE_BASE + 0x1004
        tls_dir = struct.pack(
            "<IIIIIIII",
            0,  # StartAddressOfRawData
            0,  # EndAddressOfRawData
            0,  # AddressOfIndex
            callbacks_va,  # AddressOfCallBacks
            0,  # SizeOfZeroFill
            0,  # Characteristics
            0,  # padding
            0,  # padding
        )
        body = bytearray(0x100)
        body[0 : len(tls_dir)] = tls_dir
        # Callbacks array
        struct.pack_into("<III", body, 0x40, cb_va_a, cb_va_b, 0)

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            # TLS dir is index 9.
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, len(tls_dir)),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.tls_callback_vas, [cb_va_a, cb_va_b])


class PEResourcesTest(unittest.TestCase):
    def test_named_resource_type(self):
        """Resource directory entries can be keyed by string name as well
        as integer ID. Verify the parser captures the UTF-16 name."""
        rsrc_rva = 0x3000
        rsrc_rptr = FILE_ALIGN * 3

        body = bytearray(0x200)
        # Root (type) dir — 1 named entry, 0 id entries
        struct.pack_into("<IIHHHH", body, 0x000, 0, 0, 0, 0, 1, 0)
        # Named entry: name field has high bit set + offset to name string
        struct.pack_into("<II", body, 0x010, 0x80000000 | 0x080, 0x80000000 | 0x018)
        # Name dir
        struct.pack_into("<IIHHHH", body, 0x018, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x028, 1, 0x80000000 | 0x030)
        # Lang dir
        struct.pack_into("<IIHHHH", body, 0x030, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x040, 0x0409, 0x048)
        # Leaf entry
        struct.pack_into("<IIII", body, 0x048, rsrc_rva + 0x100, 4, 0, 0)
        # IMAGE_RESOURCE_DIR_STRING at offset 0x080: WORD length + UTF-16 chars
        name = "MYTYPE"
        utf16 = name.encode("utf-16-le")
        struct.pack_into("<H", body, 0x080, len(name))
        body[0x082 : 0x082 + len(utf16)] = utf16
        # Leaf bytes
        body[0x100:0x104] = b"DATA"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rsrc",
                    "vsize": 0x200,
                    "vaddr": rsrc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rsrc_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (0, 0), (rsrc_rva, 0x200)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.resources), 1)
        self.assertEqual(pe.resources[0].rtype, "MYTYPE")
        self.assertEqual(pe.resources[0].rid, 1)

    def test_walk_tree(self):
        # Build a minimal 3-level resource tree:
        #   Type 16 (VERSION) → Name 1 → Lang 0x0409 → leaf.
        rsrc_rva = 0x3000
        rsrc_rptr = FILE_ALIGN * 3

        # Layout inside .rsrc (offsets relative to root):
        #   0x000: type dir header + 1 entry
        #   0x018: name dir header + 1 entry
        #   0x030: lang dir header + 1 entry
        #   0x048: leaf IMAGE_RESOURCE_DATA_ENTRY
        #   0x100: actual resource bytes (8 bytes)
        body = bytearray(0x110)
        # Root (type) dir
        struct.pack_into("<IIHHHH", body, 0x000, 0, 0, 0, 0, 0, 1)  # 1 id entry
        struct.pack_into(
            "<II", body, 0x010, 16, 0x80000000 | 0x018
        )  # type=16, subdir at 0x018

        # Name dir
        struct.pack_into("<IIHHHH", body, 0x018, 0, 0, 0, 0, 0, 1)
        struct.pack_into(
            "<II", body, 0x028, 1, 0x80000000 | 0x030
        )  # name=1, subdir at 0x030

        # Lang dir
        struct.pack_into("<IIHHHH", body, 0x030, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x040, 0x0409, 0x048)  # lang, leaf at 0x048

        # Leaf
        struct.pack_into("<IIII", body, 0x048, rsrc_rva + 0x100, 8, 0, 0)
        body[0x100:0x108] = b"\x01\x02\x03\x04\x05\x06\x07\x08"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rsrc",
                    "vsize": 0x110,
                    "vaddr": rsrc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rsrc_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            # Resource dir is index 2.
            data_dirs=[(0, 0), (0, 0), (rsrc_rva, 0x110)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.resources), 1)
        r = pe.resources[0]
        self.assertEqual(r.rtype, 16)
        self.assertEqual(r.rid, 1)
        self.assertEqual(r.language, 0x0409)
        self.assertEqual(r.size, 8)


class PELoadConfigTest(unittest.TestCase):
    def test_pe32_cookie_only_no_safeseh(self):
        """LoadConfig with /GS but without /SAFESEH (SEHandlerTable == 0).
        Verify security_cookie_va is captured and safe_seh_handlers
        stays empty rather than reading garbage."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        body = bytearray(0x80)
        struct.pack_into("<I", body, 0, 0x48)  # Size
        struct.pack_into("<I", body, 0x3C, IMAGE_BASE + rdata_rva + 0x60)  # cookie
        # 0x40 + 0x44 stay zero: no SafeSEH

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, 0x48),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.security_cookie_va, IMAGE_BASE + rdata_rva + 0x60)
        self.assertEqual(pe.safe_seh_handlers, [])

    def test_pe32_security_cookie_and_safeseh(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        # IMAGE_LOAD_CONFIG_DIRECTORY32 minimal layout:
        # Offset 0x3C = SecurityCookie VA, 0x40 = SEHandlerTable VA,
        # 0x44 = SEHandlerCount.
        seh_table_off = rdata_rva + 0x50
        seh_table_va = IMAGE_BASE + seh_table_off
        lc_size = 0x48
        body = bytearray(0x100)
        struct.pack_into("<I", body, 0, lc_size)  # Size
        struct.pack_into(
            "<I", body, 0x3C, IMAGE_BASE + rdata_rva + 0x60
        )  # SecurityCookie
        struct.pack_into("<I", body, 0x40, seh_table_va)  # SEHandlerTable
        struct.pack_into("<I", body, 0x44, 2)  # SEHandlerCount
        # SEH handler RVAs
        struct.pack_into("<II", body, 0x50, 0x1010, 0x1020)

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x100,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, lc_size),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.security_cookie_va, IMAGE_BASE + rdata_rva + 0x60)
        self.assertEqual(pe.safe_seh_handlers, [0x1010, 0x1020])


class PECfgTest(unittest.TestCase):
    def test_pe32_plus_loadconfig_cookie_only(self):
        """An older PE32+ LoadConfig might only span 0x60 bytes
        (covering SecurityCookie) without the +0x80..+0x90 CFG fields.
        Parser must read the cookie and stop, not over-read."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # LoadConfig is exactly 0x60 bytes — cookie at +0x58 is included
        # but CFG fields at +0x80 are not.
        body = bytearray(0x60)
        struct.pack_into("<Q", body, 0x58, 0x140100000)

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x60,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, 0x60),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(pe.security_cookie_va, 0x140100000)
        self.assertEqual(pe.cfg_function_rvas, [])
        self.assertEqual(pe.cfg_flags, 0)

    def test_pe32_cfg_table_with_extra_metadata_bytes(self):
        """The top nibble of GuardFlags encodes how many extra metadata
        bytes follow each CFG RVA in the table. Verify the parser
        strides by `4 + extra` so entries don't shift."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        cfg_table_off = rdata_rva + 0x80
        cfg_table_va = IMAGE_BASE + cfg_table_off
        body = bytearray(0x200)
        struct.pack_into("<I", body, 0x54, cfg_table_va)
        struct.pack_into("<I", body, 0x58, 3)
        # GuardFlags top nibble = 2 → +2 bytes per entry → stride 6.
        struct.pack_into("<I", body, 0x5C, 0x20000000)
        # Three entries at stride 6: RVA + 2 bytes of metadata.
        for i, rva in enumerate([0x1000, 0x1100, 0x1200]):
            off = 0x80 + i * 6
            struct.pack_into("<I", body, off, rva)
            struct.pack_into("<H", body, off + 4, 0xBEEF)  # metadata

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x100,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x200,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, 0x60),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.cfg_function_rvas, [0x1000, 0x1100, 0x1200])
        self.assertEqual(pe.cfg_flags, 0x20000000)

    def test_pe32_plus_guardcf_table(self):
        """PE32+ Load Config places GuardCFFunctionTable at +0x80, count
        at +0x88, flags at +0x90. Verify the 64-bit layout (PE32 fields
        are at +0x54/+0x58/+0x5C in the other test)."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        cfg_table_off = rdata_rva + 0xA0
        cfg_table_va = 0x140000000 + cfg_table_off
        body = bytearray(0x200)
        # SecurityCookie at +0x58 (QWORD)
        struct.pack_into("<Q", body, 0x58, 0x140100000)
        # GuardCF fields
        struct.pack_into("<Q", body, 0x80, cfg_table_va)
        struct.pack_into("<Q", body, 0x88, 2)
        struct.pack_into("<I", body, 0x90, 0)
        # Two CFG RVAs
        struct.pack_into("<II", body, 0xA0, 0x1100, 0x1200)

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x100,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x200,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, 0x98),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(pe.security_cookie_va, 0x140100000)
        self.assertEqual(pe.cfg_function_rvas, [0x1100, 0x1200])

    def test_pe32_guardcf_table(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        cfg_table_off = rdata_rva + 0x80
        cfg_table_va = IMAGE_BASE + cfg_table_off
        body = bytearray(0x100)
        # IMAGE_LOAD_CONFIG_DIRECTORY32: GuardCFFunctionTable +0x54,
        # GuardCFFunctionCount +0x58, GuardFlags +0x5C.
        struct.pack_into("<I", body, 0x54, cfg_table_va)
        struct.pack_into("<I", body, 0x58, 3)
        struct.pack_into("<I", body, 0x5C, 0)
        # Three CFG entries (stride = 4, no metadata bytes).
        struct.pack_into("<III", body, 0x80, 0x1010, 0x1020, 0x1030)

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x100,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, 0x60),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.cfg_function_rvas, [0x1010, 0x1020, 0x1030])


class PEExceptionTableTest(unittest.TestCase):
    def test_runtime_functions(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # Two RUNTIME_FUNCTION entries then a null terminator.
        body = struct.pack("<III", 0x1000, 0x1010, 0x3000)
        body += struct.pack("<III", 0x1020, 0x1040, 0x3010)
        body += b"\x00" * 12  # terminator
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": len(body),
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": body,
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, len(body)),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(
            pe.runtime_functions,
            [(0x1000, 0x1010, 0x3000), (0x1020, 0x1040, 0x3010)],
        )


class PEBoundImportsTest(unittest.TestCase):
    def test_bound_import_with_forwarder_refs(self):
        """Bound-import descriptor lists module forwarder refs after
        itself in the same table. Verify they're collected."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        bi_size = 8 * 4  # main descriptor + 2 forwarders + null
        body = bytearray(0x80)
        # Main descriptor: 2 forwarder refs follow.
        struct.pack_into("<IHH", body, 0, 0xDEADBEEF, bi_size, 2)
        # Two forwarder-ref entries (timestamp/name_off/0).
        struct.pack_into("<IHH", body, 8, 0xCAFEBABE, bi_size + 13, 0)
        struct.pack_into("<IHH", body, 16, 0xBADC0DE5, bi_size + 24, 0)
        # Null-terminator descriptor.
        struct.pack_into("<IHH", body, 24, 0, 0, 0)
        body[bi_size : bi_size + 13] = b"KERNEL32.dll\x00"
        body[bi_size + 13 : bi_size + 24] = b"USER32.dll\x00"
        body[bi_size + 24 : bi_size + 34] = b"GDI32.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, bi_size + 33),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.bound_imports), 1)
        self.assertEqual(pe.bound_imports[0].dll, "KERNEL32.dll")
        self.assertEqual(
            pe.bound_imports[0].forwarder_refs, ["USER32.dll", "GDI32.dll"]
        )

    def test_named_bound_import(self):
        # Bound-import table sits at .rdata RVA 0x2000. DLL name string sits
        # 0x18 bytes after the directory start.
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        bi_size = 8 * 2  # one entry + null terminator
        name_off_in_dir = bi_size  # name starts right after both descriptors
        body = bytearray(0x80)
        # Descriptor: timestamp, name offset, # forwarders
        struct.pack_into("<IHH", body, 0, 0xDEADBEEF, name_off_in_dir, 0)
        # Null terminator descriptor
        struct.pack_into("<IHH", body, 8, 0, 0, 0)
        body[name_off_in_dir : name_off_in_dir + 12] = b"KERNEL32.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, bi_size + 16),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.bound_imports), 1)
        self.assertEqual(pe.bound_imports[0].dll, "KERNEL32.dll")
        self.assertEqual(pe.bound_imports[0].timestamp, 0xDEADBEEF)
        self.assertFalse(pe.bound_imports[0].forwarder_refs)


class PEVersionInfoTest(unittest.TestCase):
    """Build a synthetic VS_VERSIONINFO with one StringTable / one String
    pair and assert it decodes to the expected key/value."""

    def _vs_node(
        self, key: str, value: bytes, w_type: int, children: bytes = b""
    ) -> bytes:
        key_utf16 = key.encode("utf-16-le") + b"\x00\x00"
        header_size = 6
        body_off = header_size + len(key_utf16)
        # Align body offset to dword
        pad_a = (-body_off) & 3
        value_off = body_off + pad_a
        value_padded = value
        pad_b = (-len(value_padded)) & 3
        children_off = value_off + len(value_padded) + pad_b
        total = children_off + len(children)
        # Pad total to dword as well so the next sibling starts aligned.
        pad_c = (-total) & 3
        # w_value_length depends on w_type:
        #   w_type==1 (text) → length in WCHARs (chars including NUL)
        #   w_type==0 (binary) → length in bytes
        if w_type == 1:
            w_value_length = len(value) // 2
        else:
            w_value_length = len(value)
        return (
            struct.pack("<HHH", total + pad_c, w_value_length, w_type)
            + key_utf16
            + b"\x00" * pad_a
            + value_padded
            + b"\x00" * pad_b
            + children
            + b"\x00" * pad_c
        )

    def test_string_table(self):
        # Build inner-most String entry: key "CompanyName", value "Acme Corp"
        company = self._vs_node(
            "CompanyName",
            "Acme Corp\x00".encode("utf-16-le"),
            w_type=1,
        )
        # StringTable wrapping that one String
        string_table = self._vs_node(
            "040904E4",
            b"",
            w_type=1,
            children=company,
        )
        string_file_info = self._vs_node(
            "StringFileInfo", b"", w_type=1, children=string_table
        )
        # Root VS_VERSION_INFO; for this test we keep its Value empty so
        # we don't have to populate the 52-byte VS_FIXEDFILEINFO.
        root = self._vs_node(
            "VS_VERSION_INFO",
            b"",
            w_type=0,
            children=string_file_info,
        )

        # Now wrap in a resource directory pointing at this blob.
        rsrc_rva = 0x3000
        rsrc_rptr = FILE_ALIGN * 3
        body = bytearray(0x600)
        # Root (type) dir
        struct.pack_into("<IIHHHH", body, 0x000, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x010, 16, 0x80000000 | 0x018)
        # Name dir
        struct.pack_into("<IIHHHH", body, 0x018, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x028, 1, 0x80000000 | 0x030)
        # Lang dir
        struct.pack_into("<IIHHHH", body, 0x030, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x040, 0x0409, 0x048)
        # Leaf entry → points at our root blob at +0x100
        struct.pack_into("<IIII", body, 0x048, rsrc_rva + 0x100, len(root), 0, 0)
        body[0x100 : 0x100 + len(root)] = root

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rsrc",
                    "vsize": 0x600,
                    "vaddr": rsrc_rva,
                    "rsize": FILE_ALIGN * 2,
                    "rptr": rsrc_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (0, 0), (rsrc_rva, 0x600)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.version_info.get("CompanyName"), "Acme Corp")


class PEDelayImportsTest(unittest.TestCase):
    def test_v1_va_based_delay_import(self):
        """Pre-VS2008 / legacy MSVC emits IMAGE_DELAYLOAD_DESCRIPTOR with
        attrs=0 — its address fields are VAs (need ImageBase subtraction)
        rather than RVAs. Verify the parser handles both formats."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        dll_name_va = IMAGE_BASE + rdata_rva + 0x60
        iat_va = IMAGE_BASE + rdata_rva + 0x40
        int_va = IMAGE_BASE + rdata_rva + 0x48
        ibn_rva = rdata_rva + 0x50

        body = bytearray(0x100)
        struct.pack_into(
            "<IIIIIIII",
            body,
            0x00,
            0,  # attrs (v1: VA-based)
            dll_name_va,
            0,
            iat_va,
            int_va,
            0,
            0,
            0xCAFE,
        )
        struct.pack_into("<I", body, 0x48, ibn_rva)
        struct.pack_into("<I", body, 0x4C, 0)
        struct.pack_into("<H", body, 0x50, 0)
        body[0x52 : 0x52 + 9] = b"LegacyFn\x00"
        body[0x60 : 0x60 + 10] = b"OLDDLL.dll"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, 0x40),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.delay_imports), 1)
        self.assertEqual(pe.delay_imports[0].dll, "OLDDLL.dll")
        self.assertEqual(pe.delay_imports[0].name, "LegacyFn")

    def test_pe32_plus_delay_import(self):
        """PE32+ delay imports use 8-byte thunks; verify the 64-bit
        path. (The default tests use 4-byte PE32 thunks.)"""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        dll_name_rva = rdata_rva + 0x80
        iat_rva = rdata_rva + 0x40
        int_rva = rdata_rva + 0x50
        ibn_rva = rdata_rva + 0x70

        body = bytearray(0x100)
        struct.pack_into(
            "<IIIIIIII",
            body,
            0x00,
            1,
            dll_name_rva,
            0,
            iat_rva,
            int_rva,
            0,
            0,
            0,
        )
        # ILT: one 8-byte entry pointing at IMAGE_IMPORT_BY_NAME, then NUL.
        struct.pack_into("<Q", body, 0x50, ibn_rva)
        struct.pack_into("<Q", body, 0x58, 0)
        # IMAGE_IMPORT_BY_NAME (hint + name).
        struct.pack_into("<H", body, 0x70, 0)
        body[0x72 : 0x72 + 11] = b"NtCreateFile\x00"[:11]
        body[0x80 : 0x80 + 11] = b"ntdll.dll\x00"

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, 0x40),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(len(pe.delay_imports), 1)
        self.assertEqual(pe.delay_imports[0].dll, "ntdll.dll")
        self.assertEqual(pe.delay_imports[0].iat_rva, iat_rva)

    def test_v2_delay_import(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        # IMAGE_DELAYLOAD_DESCRIPTOR (v2 / RVA-based, attrs = 1):
        #   0x00 = attrs
        #   0x04 = dll name RVA
        #   0x08 = module handle RVA
        #   0x0C = IAT RVA
        #   0x10 = INT RVA
        # Then a NULL terminator (32 bytes of zeros).
        dll_name_rva = rdata_rva + 0x60
        iat_rva = rdata_rva + 0x40
        int_rva = rdata_rva + 0x48
        ibn_rva = rdata_rva + 0x50

        body = bytearray(0x100)
        struct.pack_into(
            "<IIIIIIII",
            body,
            0x00,
            1,
            dll_name_rva,
            0,
            iat_rva,
            int_rva,
            0,
            0,
            0xCAFEBABE,
        )
        # INT table — one entry (named) + NULL terminator
        struct.pack_into("<I", body, 0x48, ibn_rva)
        struct.pack_into("<I", body, 0x4C, 0)
        # IMAGE_IMPORT_BY_NAME: hint + name
        struct.pack_into("<H", body, 0x50, 0)
        body[0x52 : 0x52 + 9] = b"D3DXLoad\x00"
        # DLL name
        body[0x60 : 0x60 + 10] = b"d3d8.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            # Delay-import dir is index 13.
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (rdata_rva, 0x40),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.delay_imports), 1)
        self.assertEqual(pe.delay_imports[0].dll, "d3d8.dll")
        self.assertEqual(pe.delay_imports[0].name, "D3DXLoad")
        self.assertEqual(pe.delay_imports[0].iat_rva, iat_rva)


class PEPlusImportTest(unittest.TestCase):
    def test_pe32_plus_imports(self):
        """PE32+ imports walk 8-byte thunks; the ordinal flag sits in the
        high bit of a QWORD, not a DWORD. Verify the 64-bit path."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        ilt_rva = rdata_rva + 0x28
        iat_rva = rdata_rva + 0x40
        dll_name_rva = rdata_rva + 0x70
        ibn_rva = rdata_rva + 0x60

        body = bytearray(0x100)
        struct.pack_into(
            "<IIIII",
            body,
            0x00,
            ilt_rva,
            0,
            0,
            dll_name_rva,
            iat_rva,
        )
        # ILT: 8-byte entry pointing at IMAGE_IMPORT_BY_NAME, then NUL.
        struct.pack_into("<Q", body, 0x28, ibn_rva)
        struct.pack_into("<Q", body, 0x30, 0)
        # IAT mirrors ILT
        struct.pack_into("<Q", body, 0x40, ibn_rva)
        struct.pack_into("<Q", body, 0x48, 0)
        # IMAGE_IMPORT_BY_NAME at 0x60: hint + name
        struct.pack_into("<H", body, 0x60, 0)
        body[0x62 : 0x62 + 11] = b"NtReadFile\x00"
        # DLL name at 0x70 (no overlap with IBN)
        body[0x70 : 0x70 + 10] = b"ntdll.dll\x00"

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 0x28)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(len(pe.imports), 1)
        self.assertEqual(pe.imports[0].dll, "ntdll.dll")
        self.assertEqual(pe.imports[0].name, "NtReadFile")
        self.assertEqual(pe.imports[0].iat_rva, iat_rva)


class PEPlusOrdinalImportTest(unittest.TestCase):
    def test_pe32_plus_ordinal_import(self):
        """PE32+ ordinal-only imports set bit 63 of the 8-byte thunk
        (vs bit 31 on PE32). Verify the 64-bit ordinal-flag path."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        ilt_rva = rdata_rva + 0x28
        iat_rva = rdata_rva + 0x40
        dll_name_rva = rdata_rva + 0x60

        body = bytearray(0x80)
        struct.pack_into(
            "<IIIII",
            body,
            0x00,
            ilt_rva,
            0,
            0,
            dll_name_rva,
            iat_rva,
        )
        # ILT: 8-byte ordinal-only entry (bit 63 set, low 16 = ordinal 42)
        struct.pack_into("<Q", body, 0x28, (1 << 63) | 42)
        struct.pack_into("<Q", body, 0x30, 0)
        # IAT mirrors
        struct.pack_into("<Q", body, 0x40, (1 << 63) | 42)
        struct.pack_into("<Q", body, 0x48, 0)
        body[0x60 : 0x60 + 10] = b"WS2_32.dll"

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 0x28)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(len(pe.imports), 1)
        self.assertEqual(pe.imports[0].dll, "WS2_32.dll")
        self.assertIsNone(pe.imports[0].name)
        self.assertEqual(pe.imports[0].ordinal, 42)


class PEImportIatZeroSkipTest(unittest.TestCase):
    def test_descriptor_with_zero_iat_is_skipped(self):
        """An IMAGE_IMPORT_DESCRIPTOR with iat_rva == 0 has no IAT slot
        VA to attach thunks to. parse_imports must skip such descriptors
        rather than emit bogus PEImport entries pointing at slot 0."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        ilt_rva = rdata_rva + 0x28
        dll_name_rva = rdata_rva + 0x40

        body = bytearray(0x60)
        # Descriptor with iat_rva = 0 (malformed but encountered in
        # corrupt binaries).
        struct.pack_into(
            "<IIIII",
            body,
            0x00,
            ilt_rva,
            0,
            0,
            dll_name_rva,
            0,
        )
        struct.pack_into("<I", body, 0x28, 0)  # ILT terminator
        body[0x40 : 0x40 + 11] = b"BadDll.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x60,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 20)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        # The descriptor is parsed (DLL name known) but no PEImport
        # entries are recorded since slot VAs would be meaningless.
        self.assertEqual(pe.imports, [])


class PEOrdinalImportTest(unittest.TestCase):
    def test_ordinal_import(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        ilt_rva = rdata_rva + 0x28
        iat_rva = rdata_rva + 0x30
        dll_name_rva = rdata_rva + 0x40

        body = bytearray(0x60)
        struct.pack_into(
            "<IIIII",
            body,
            0x00,
            ilt_rva,
            0,
            0,
            dll_name_rva,
            iat_rva,
        )
        # Ordinal-only entry: high bit set, low 16 bits hold the ordinal.
        struct.pack_into("<I", body, 0x28, 0x80000000 | 17)
        struct.pack_into("<I", body, 0x2C, 0)  # ILT terminator
        struct.pack_into("<I", body, 0x30, 0x80000000 | 17)
        struct.pack_into("<I", body, 0x34, 0)
        body[0x40 : 0x40 + 11] = b"OTHER.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x60,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 40)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.imports), 1)
        self.assertIsNone(pe.imports[0].name)
        self.assertEqual(pe.imports[0].ordinal, 17)
        self.assertEqual(pe.imports[0].dll, "OTHER.dll")


class PERelocsTest(unittest.TestCase):
    def test_non_pointer_reloc_types_skipped(self):
        """Reloc types other than HIGHLOW (3) and DIR64 (10) — LOW (1),
        HIGH (2), HIGHADJ (4), and ABSOLUTE (0) padding — must NOT
        populate pe.pointer_rvas. They describe partial relocations or
        padding, not full pointers."""
        reloc_rva = 0x4000
        reloc_rptr = FILE_ALIGN * 3
        block = struct.pack("<II", 0x6000, 20) + struct.pack(
            "<HHHHHH",
            (1 << 12) | 0x010,  # LOW — skip
            (2 << 12) | 0x020,  # HIGH — skip
            (4 << 12) | 0x030,  # HIGHADJ — skip
            (0 << 12) | 0x040,  # ABSOLUTE padding — skip
            (3 << 12) | 0x050,  # HIGHLOW — accept
            0,  # padding
        )

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".reloc",
                    "vsize": len(block),
                    "vaddr": reloc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": reloc_rptr,
                    "chars": 0x42000040,
                    "body": block,
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (reloc_rva, len(block)),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        # Only the HIGHLOW entry should land in pointer_rvas.
        self.assertEqual(pe.pointer_rvas, {0x6050})

    def test_dir64_relocs(self):
        """PE32+ binaries emit IMAGE_REL_BASED_DIR64 (type 10) entries.
        Verify the parser accepts both HIGHLOW (type 3) and DIR64 (type 10)
        in the same block — both flag the same `pointer_rvas` set."""
        reloc_rva = 0x4000
        reloc_rptr = FILE_ALIGN * 3
        block = struct.pack("<II", 0x5000, 16) + struct.pack(
            "<HHHH",
            (10 << 12) | 0x008,  # DIR64
            (10 << 12) | 0x020,  # DIR64
            (3 << 12) | 0x040,  # HIGHLOW
            0,  # padding entry — must be ignored
        )

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".reloc",
                    "vsize": len(block),
                    "vaddr": reloc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": reloc_rptr,
                    "chars": 0x42000040,
                    "body": block,
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (reloc_rva, len(block)),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.pointer_rvas, {0x5008, 0x5020, 0x5040})

    def test_multi_block_relocs(self):
        """Two reloc blocks across different 4 KB pages should both be
        captured, with type-0 padding skipped."""
        reloc_rva = 0x4000
        reloc_rptr = FILE_ALIGN * 3
        block_a = struct.pack("<II", 0x3000, 16) + struct.pack(
            "<HHHH",
            (3 << 12) | 0x040,
            (3 << 12) | 0x050,
            (3 << 12) | 0x060,
            0,  # padding
        )
        block_b = struct.pack("<II", 0x5000, 12) + struct.pack(
            "<HH",
            (3 << 12) | 0x100,
            (3 << 12) | 0x200,
        )
        body = block_a + block_b

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".reloc",
                    "vsize": len(body),
                    "vaddr": reloc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": reloc_rptr,
                    "chars": 0x42000040,
                    "body": body,
                },
            ],
            data_dirs=[(0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (reloc_rva, len(body))],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(
            pe.pointer_rvas,
            {0x3040, 0x3050, 0x3060, 0x5100, 0x5200},
        )

    def test_highlow_relocs(self):
        # Place a small .reloc block describing two HIGHLOW relocs on page
        # 0x3000, at offsets 0x010 and 0x020.
        reloc_rva = 0x4000
        reloc_rptr = FILE_ALIGN * 3
        block_size = 8 + 2 + 2 + 2 + 2  # header + 4 WORD entries
        block = struct.pack("<II", 0x3000, block_size) + struct.pack(
            "<HHHH",
            (3 << 12) | 0x010,
            (3 << 12) | 0x020,
            0,  # padding entry (skipped)
            0,  # padding entry (skipped)
        )
        body = block

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".reloc",
                    "vsize": len(body),
                    "vaddr": reloc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": reloc_rptr,
                    "chars": 0x42000040,
                    "body": body,
                },
            ],
            data_dirs=[(0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (reloc_rva, len(body))],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.pointer_rvas, {0x3010, 0x3020})


class CreateConfigTailSegmentSortTest(unittest.TestCase):
    def test_coff_symtab_and_signature_emit_in_file_order(self):
        """When both a COFF symbol table and an Authenticode signature
        are present, their YAML segments must appear in file-offset
        order — splat rejects non-monotonic rom_start values."""
        body = b"\x90" * FILE_ALIGN
        # Lay out: header(0x200) + .text(0x200) + symtab(0x40) + sig(0x40)
        symtab_off = FILE_ALIGN * 2
        symtab_size = 0x40
        sig_off = symtab_off + symtab_size
        sig_size = 0x40

        data_dirs = [(0, 0)] * 4 + [(sig_off, sig_size)] + [(0, 0)] * 11
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            symtab_off,
            4,
            0xE0,
            0x010F,
        )
        opt = bytearray(_opt_header_pe32(entry_rva=0x1000))
        for i, (rva, size) in enumerate(data_dirs):
            struct.pack_into("<II", opt, 96 + i * 8, rva, size)
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt) + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + body + b"\x00" * symtab_size + b"\x00" * sig_size

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-sort-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "both.exe"
            exe.write_bytes(bytes(buf))
            create_win32_config(exe, bytes(buf))
            yaml_txt = (tmpdir / "both.exe.yaml").read_text()
            # coff_symtab must appear before signature (file order).
            symtab_idx = yaml_txt.index("name: coff_symtab")
            sig_idx = yaml_txt.index("name: signature")
            self.assertLess(symtab_idx, sig_idx)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigAuthenticodeSegmentTest(unittest.TestCase):
    def test_certificate_table_emits_bin_segment(self):
        """An Authenticode-signed PE has data directory 4 set to the
        signature blob's FILE offset (unlike the RVA-based directories).
        Auto-config should emit a `signature` bin segment so the bytes
        are split into a known file."""
        body = b"\x90" * FILE_ALIGN
        sig_data = b"\x00" * 0x40  # placeholder signature blob
        sig_off = FILE_ALIGN * 2
        sig_size = len(sig_data)

        # Data directory 4 = (FILE offset, size).
        data_dirs = [(0, 0)] * 4 + [(sig_off, sig_size)] + [(0, 0)] * 11

        sec_text = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F,
        )
        opt = bytearray(_opt_header_pe32(entry_rva=0x1000))
        # Patch in the data directories starting at offset 96.
        for i, (rva, size) in enumerate(data_dirs):
            struct.pack_into("<II", opt, 96 + i * 8, rva, size)
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt) + sec_text
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + body + sig_data

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-sig-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "signed.exe"
            exe.write_bytes(bytes(buf))
            create_win32_config(exe, bytes(buf))
            yaml_txt = (tmpdir / "signed.exe.yaml").read_text()
            self.assertIn("name: signature", yaml_txt)
            self.assertIn(f"start: 0x{sig_off:X}", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigCoffSymtabSegmentTest(unittest.TestCase):
    def test_coff_symtab_pointer_emits_bin_segment(self):
        """Vintage MSVC 4-6 binaries can embed a deprecated COFF symbol
        table past the last section. Modern MSVC uses PDB instead and
        leaves PointerToSymbolTable / NumberOfSymbols zero. Emit a
        `bin` segment for the legacy case so its bytes are extracted
        rather than swept into the unknown-tail."""
        body = b"\x90" * FILE_ALIGN
        symtab_data = b"\x00" * 0x40  # 4 dummy COFF symbols
        # PointerToSymbolTable will sit just after the .text raw bytes.
        symtab_off = FILE_ALIGN * 2
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            symtab_off,  # PointerToSymbolTable
            4,  # NumberOfSymbols
            0xE0,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + body + symtab_data

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-coff-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "vintage.exe"
            exe.write_bytes(bytes(buf))
            create_win32_config(exe, bytes(buf))
            yaml_txt = (tmpdir / "vintage.exe.yaml").read_text()
            self.assertIn("name: coff_symtab", yaml_txt)
            self.assertIn(f"start: 0x{symtab_off:X}", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigAllForwardersTest(unittest.TestCase):
    def test_dll_with_only_forwarder_exports_skips_exports_header(self):
        """A DLL whose every export is a forwarder (e.g. apisetschema,
        downlevel shims) should not emit a '// Exports from X' header
        followed by zero rows. Only the '// Forwarded exports' block
        below it should appear."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        funcs_rva = rdata_rva + 0x28
        names_rva = funcs_rva + 0x4
        ords_rva = names_rva + 0x4
        name_str_rva = rdata_rva + 0x40
        dll_name_rva = rdata_rva + 0x50
        # The forwarder RVA must point INSIDE the export directory range
        # for it to be classified as a forwarder. Export dir is at
        # rdata_rva..rdata_rva+0x80; put the forwarder string there.
        fwd_rva = rdata_rva + 0x60
        body = bytearray(0x80)
        struct.pack_into(
            "<IIHHIIIIIII",
            body,
            0x00,
            0,
            0,
            0,
            0,
            dll_name_rva,
            1,
            1,
            1,
            funcs_rva,
            names_rva,
            ords_rva,
        )
        struct.pack_into("<I", body, 0x28, fwd_rva)  # forwarder RVA
        struct.pack_into("<I", body, 0x2C, name_str_rva)
        struct.pack_into("<H", body, 0x30, 0)
        body[0x40 : 0x40 + 8] = b"OldFunc\x00"
        body[0x50 : 0x50 + 11] = b"shim.dll\x00\x00\x00"
        body[0x60 : 0x60 + 16] = b"KERNEL32.NewName"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x20,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x20,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(rdata_rva, 0x80)],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-shim-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            dll = tmpdir / "shim.dll"
            dll.write_bytes(pe_bytes)
            create_win32_config(dll, pe_bytes)
            txt = (tmpdir / "symbol_addrs.txt").read_text()
            # No "// Exports from" header since no named non-forwarder exports.
            self.assertNotIn("// Exports from", txt)
            # Forwarder block should still appear.
            self.assertIn("// Forwarded exports", txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class RvaToFileOffsetVirtualTailTest(unittest.TestCase):
    def test_rva_in_virtual_only_tail_returns_none(self):
        """A section with VirtualSize > SizeOfRawData has a virtual-only
        tail that the loader zero-fills. RVAs in that range have no
        backing bytes — `rva_to_file_offset` must return None instead
        of mapping into the next section's raw bytes."""
        # Two sections. .text: raw 0x200, virt 0x400 (0x200 tail).
        # .rdata: raw 0x200, virt 0x10.
        text_body = b"\x90" * FILE_ALIGN
        rdata_body = b"\x11" * 0x10
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            2,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        # .text: virtual_size 0x400, raw_size FILE_ALIGN (0x200), raw_ptr 0x200.
        sec_text = _section_header(
            b".text", 0x400, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        sec_rdata = _section_header(
            b".rdata", 0x10, 0x2000, FILE_ALIGN, FILE_ALIGN * 2, 0x40000040
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec_text + sec_rdata
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + text_body + rdata_body.ljust(FILE_ALIGN, b"\x00")

        pe = win32_platform.parse_pe(bytes(buf))
        # RVA 0x1100 — past .text raw_size (0x200) but within
        # virtual_size (0x400). Should return None.
        self.assertIsNone(pe.rva_to_file_offset(0x1100 + 0x100))
        # RVA 0x1100 itself — still inside raw bytes (0x100 < 0x200) — valid.
        self.assertEqual(pe.rva_to_file_offset(0x1100), FILE_ALIGN + 0x100)


class Win32PublicSurfaceTest(unittest.TestCase):
    """Smoke-test the public symbols of the win32 platform module so
    refactors that accidentally make a constant private (`_NAME`) or
    rename a dataclass break loudly instead of silently downstream."""

    def test_public_names_present(self):
        from src.splat.platforms import win32

        expected = {
            # Dataclasses
            "PEInfo",
            "PESection",
            "PEExport",
            "PEImport",
            "PEBoundImport",
            "PEResource",
            "COFFSymbol",
            "UnwindInfo",
            "CLRHeader",
            # Top-level entry points
            "parse_pe",
            "init",
            "info",
            "raw_image",
            # Helpers used by segtypes + create_config
            "sanitize_label",
            "compute_iat_labels",
            "compute_export_labels",
            "ptr_layout",
            "resolve_exact_encoding",
            # Machine codes
            "MACHINE_I386",
            "MACHINE_AMD64",
            "MACHINE_ARM32",
            "MACHINE_ARM64",
            # Magic values
            "OPT_MAGIC_PE32",
            "OPT_MAGIC_PE32_PLUS",
            # Data directory indices
            "DIR_EXPORT",
            "DIR_IMPORT",
            "DIR_RESOURCE",
            "DIR_EXCEPTION",
            "DIR_CERTIFICATE",
            "DIR_BASERELOC",
            "DIR_DEBUG",
            "DIR_TLS",
            "DIR_LOAD_CONFIG",
            "DIR_BOUND_IMPORT",
            "DIR_DELAY_IMPORT",
        }
        for name in expected:
            self.assertTrue(
                hasattr(win32, name),
                f"public win32 platform surface missing '{name}'",
            )


class CreateConfigCLRSymbolsTest(unittest.TestCase):
    def test_dotnet_binary_emits_clr_metadata_symbols(self):
        """A .NET PE (data dir 14 populated) should emit `clr_metadata`,
        `clr_strong_name_signature`, `clr_resources` symbols in
        symbol_addrs.txt so disasm cross-references resolve."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        cor20 = struct.pack(
            "<IHHIIIIIIII",
            72,
            2,
            5,
            0x2100,
            0x400,
            0x00000001,
            0x06000001,
            0x2500,
            0x100,
            0x4000,
            0x80,
        )
        body = bytearray(cor20 + b"\x00" * (FILE_ALIGN - len(cor20)))
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x400,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0)] * 14 + [(rdata_rva, 72), (0, 0)],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-clr-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "clr.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            txt = (tmpdir / "symbol_addrs.txt").read_text()
            self.assertIn("clr_metadata = 0x", txt)
            self.assertIn("clr_strong_name_signature = 0x", txt)
            self.assertIn("clr_resources = 0x", txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class ParseCLRHeaderTest(unittest.TestCase):
    def test_dotnet_cor20_header_decoded(self):
        """A PE with data dir 14 (CLR Runtime Header) populated has
        an IMAGE_COR20_HEADER record that pe.clr_header decodes:
        runtime version, metadata RVA/size, entry-point token,
        strong-name signature pointer."""
        # COR20 header lives in .rdata; data dir 14 RVA points at it.
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        cor20 = struct.pack(
            "<IHHIIIIIIII",
            72,  # cb (always 72)
            2,
            5,  # runtime major/minor (CLR 2.5)
            0x2100,
            0x400,  # metadata RVA/size
            0x00000001,  # flags (COMIMAGE_FLAGS_ILONLY)
            0x06000001,  # entry point token (MethodDef 0x1)
            0,
            0,  # resources RVA/size
            0x4000,
            0x80,  # strong name sig RVA/size
        )
        body = bytearray(cor20 + b"\x00" * (FILE_ALIGN - len(cor20)))

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x400,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0)] * 14 + [(rdata_rva, 72), (0, 0)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        assert pe.clr_header is not None
        self.assertEqual(pe.clr_header.cb_size, 72)
        self.assertEqual(pe.clr_header.runtime_major, 2)
        self.assertEqual(pe.clr_header.runtime_minor, 5)
        self.assertEqual(pe.clr_header.metadata_rva, 0x2100)
        self.assertEqual(pe.clr_header.metadata_size, 0x400)
        self.assertEqual(pe.clr_header.flags, 1)
        self.assertEqual(pe.clr_header.entry_point_token_or_rva, 0x06000001)
        self.assertEqual(pe.clr_header.strong_name_signature_rva, 0x4000)


class ParseVersionTranslationTest(unittest.TestCase):
    def test_var_file_info_translation_block_surfaced(self):
        """The VarFileInfo 'Translation' child of a VERSION resource
        carries an array of (LANGID, codepage) pairs as binary data.
        Verify _walk_versioninfo_node decodes it into a comma-separated
        '0xLLLL/0xCCCC' string stored under 'Translation'."""
        from src.splat.platforms.win32 import _walk_versioninfo_node

        # Build a synthetic VarFileInfo > Translation node with two
        # locale pairs: en-US (0x0409, 0x04E4) and de-DE (0x0407, 0x04E4).
        # Node layout:
        #   wLength + wValueLength(8) + wType(0=binary) + key + value
        def _wstr(s: str) -> bytes:
            return (s + "\x00").encode("utf-16-le")

        def _align4(off: int) -> int:
            return (off + 3) & ~3

        key = _wstr("Translation")
        value = struct.pack("<HHHH", 0x0409, 0x04E4, 0x0407, 0x04E4)
        header_size = 6  # wLength + wValueLength + wType
        body_off = _align4(header_size + len(key))
        total_size = body_off + len(value)
        node = (
            struct.pack("<HHH", total_size, len(value), 0)
            + key
            + b"\x00" * (body_off - header_size - len(key))
            + value
        )

        out: dict = {}
        _walk_versioninfo_node(node, 0, out, 0)
        self.assertIn("Translation", out)
        self.assertEqual(out["Translation"], "0x0409/0x04E4, 0x0407/0x04E4")


class ParseUnwindInfoTest(unittest.TestCase):
    def test_unwind_codes_decoded_from_runtime_function(self):
        """A PE32+ binary with one RUNTIME_FUNCTION pointing at an
        IMAGE_UNWIND_INFO record encoding a simple prologue
        (`push rbp; sub rsp, 0x20`) must decode the codes."""
        # Layout: text(0x1000) + pdata(0x2000, single RUNTIME_FUNCTION
        # pointing at unwind at rdata 0x3000) + rdata(0x3000, unwind info).
        text_body = b"\x90" * FILE_ALIGN
        pdata_body = struct.pack("<III", 0x1000, 0x1010, 0x3000)
        pdata_body = pdata_body.ljust(FILE_ALIGN, b"\x00")

        # UNWIND_INFO:
        #   version=1, flags=0, prolog_size=5, count=2, frame_reg=0/0
        #   code[0]: offset=5,  op=ALLOC_SMALL(2) info=3 (3*8+8 = 32 bytes)
        #   code[1]: offset=1,  op=PUSH_NONVOL(0) info=5 (RBP=reg 5)
        unwind = struct.pack(
            "<BBBB" + "BB" * 2,
            0x01,  # version 1, flags 0
            5,  # SizeOfProlog
            2,  # CountOfUnwindCodes
            0,  # FrameRegister 0
            5,
            0x32,  # code 0: offset 5, op ALLOC_SMALL (2), info 3
            1,
            0x50,  # code 1: offset 1, op PUSH_NONVOL (0), info 5 (RBP)
        )
        rdata_body = unwind + b"\x00" * (FILE_ALIGN - len(unwind))

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": text_body,
                },
                {
                    "name": b".pdata",
                    "vsize": 0x10,
                    "vaddr": 0x2000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN * 2,
                    "chars": 0x40000040,
                    "body": pdata_body,
                },
                {
                    "name": b".rdata",
                    "vsize": len(unwind),
                    "vaddr": 0x3000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN * 3,
                    "chars": 0x40000040,
                    "body": rdata_body,
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0x2000, 12),
            ],
        )

        pe = win32_platform.parse_pe(pe_bytes)
        self.assertIn(0x3000, pe.unwind_info)
        uw = pe.unwind_info[0x3000]
        self.assertEqual(uw.version, 1)
        self.assertEqual(uw.prolog_size, 5)
        self.assertEqual(len(uw.codes), 2)
        # First code: ALLOC_SMALL with info 3.
        self.assertEqual(uw.codes[0][1], "ALLOC_SMALL")
        self.assertEqual(uw.codes[0][2], 3)
        # Second code: PUSH_NONVOL with info 5 (RBP).
        self.assertEqual(uw.codes[1][1], "PUSH_NONVOL")
        self.assertEqual(uw.codes[1][2], 5)


class ParseCoffSymtabTest(unittest.TestCase):
    def test_vintage_coff_symbols_decoded(self):
        """A vintage MSVC 4-6 PE shipping an embedded COFF symbol table:
        each 18-byte IMAGE_SYMBOL record decodes to a COFFSymbol entry
        on pe.coff_symbols with name / value / section / class."""
        # Build a tiny PE with PointerToSymbolTable + NumberOfSymbols
        # populated. Two symbols:
        #   "main"     value=0x401000, section=1, type=0x20, class=2
        #   ".text"    value=0,        section=1, type=0x00, class=3
        sym_a = b"main\x00\x00\x00\x00" + struct.pack(
            "<IhHBB", 0x00401000, 1, 0x20, 2, 0
        )
        sym_b = b".text\x00\x00\x00" + struct.pack("<IhHBB", 0, 1, 0x00, 3, 0)
        symtab = sym_a + sym_b
        # Empty string table = just a 4-byte length field of value 4.
        str_table = struct.pack("<I", 4)
        # Place symtab at FILE_ALIGN * 2.
        symtab_off = FILE_ALIGN * 2

        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            symtab_off,
            2,
            0xE0,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN + symtab + str_table

        pe = win32_platform.parse_pe(bytes(buf))
        self.assertEqual(len(pe.coff_symbols), 2)
        self.assertEqual(pe.coff_symbols[0].name, "main")
        self.assertEqual(pe.coff_symbols[0].value, 0x00401000)
        self.assertEqual(pe.coff_symbols[0].section_number, 1)
        self.assertEqual(pe.coff_symbols[0].storage_class, 2)
        self.assertEqual(pe.coff_symbols[1].name, ".text")
        self.assertEqual(pe.coff_symbols[1].section_number, 1)


class Win32MachineTypeTableTest(unittest.TestCase):
    def test_machine_types_cover_arch_id_landscape(self):
        from src.splat.segtypes.win32.header import _MACHINE_TYPES

        # x86/x86_64 — the ones splat actually disassembles.
        self.assertEqual(_MACHINE_TYPES[0x014C], "i386")
        self.assertEqual(_MACHINE_TYPES[0x8664], "amd64")
        # ARM family — splat rejects but the header dump should still
        # name them so the user understands why.
        self.assertEqual(_MACHINE_TYPES[0xAA64], "ARM64")
        self.assertEqual(_MACHINE_TYPES[0x01C4], "ARMNT (Thumb-2)")
        # Modern architectures (RISC-V, LoongArch) for forward-compat.
        self.assertEqual(_MACHINE_TYPES[0x5064], "RISC-V 64-bit")
        self.assertEqual(_MACHINE_TYPES[0x6264], "LoongArch 64-bit")
        # Vintage architectures occasionally seen in CE / NT-RISC builds.
        self.assertEqual(_MACHINE_TYPES[0x0184], "Alpha AXP")
        self.assertEqual(_MACHINE_TYPES[0x0200], "Itanium (IA-64)")


class ParsePEFarPeOffsetTest(unittest.TestCase):
    def test_e_lfanew_pointing_past_file_end_rejected(self):
        """A fuzzed MZ header with e_lfanew = 0xFFFFFFFF (or any value
        pointing past end-of-file) must reject cleanly rather than
        crash on the slice read. parse_pe calls log.error which is
        NoReturn (SystemExit)."""
        buf = bytearray(0x40)
        buf[0:2] = b"MZ"
        # Set e_lfanew (file offset 0x3C) to a huge value.
        struct.pack_into("<I", buf, 0x3C, 0xFFFFFFFF)
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(bytes(buf))


class EscapeStringTest(unittest.TestCase):
    """`_escape_string` produces the same GAS-compatible escape forms
    consistently across the data segment's `.asciz` emission and the
    wide-string `/* L"..." */` preview comments."""

    def test_quote_and_backslash_escaped(self):
        from src.splat.segtypes.win32.data import _escape_string

        self.assertEqual(_escape_string(b'"\\'), r"\"\\")

    def test_tab_newline_return_use_short_forms(self):
        from src.splat.segtypes.win32.data import _escape_string

        self.assertEqual(_escape_string(b"\t\n\r"), r"\t\n\r")

    def test_non_printable_uses_hex_escape(self):
        from src.splat.segtypes.win32.data import _escape_string

        # 0x01 (SOH) — out of printable range, fall back to \xNN form.
        self.assertEqual(_escape_string(b"\x01"), r"\x01")

    def test_latin1_supplement_uses_hex_escape(self):
        from src.splat.segtypes.win32.data import _escape_string

        # 0xFC (ü) — _is_string_byte now accepts it for scanning, but
        # _escape_string still emits it as \xfc so GAS interprets the
        # byte literally instead of relying on locale codepage decoding.
        self.assertEqual(_escape_string(b"\xfc"), r"\xfc")

    def test_decode_wide_round_trips_basic_latin(self):
        from src.splat.segtypes.win32.data import _decode_wide

        # UTF-16LE bytes for "AB" → "AB" passthrough.
        self.assertEqual(_decode_wide(b"A\x00B\x00"), "AB")

    def test_decode_wide_uses_unicode_escape_for_non_ascii(self):
        from src.splat.segtypes.win32.data import _decode_wide

        # Polish 'ł' is U+0142 — outside the 0x20-0x7E printable subset
        # used for the preview, so the comment falls back to \uNNNN
        # form rather than the literal codepoint (keeps the generated
        # .s ASCII-only).
        self.assertEqual(_decode_wide(b"\x42\x01"), "\\u0142")


class NarrowStringDetectionTest(unittest.TestCase):
    """Narrow ANSI string scanner: NUL-terminated runs of printable bytes."""

    def test_basic_ascii_run(self):
        from src.splat.segtypes.win32.data import _scan_string

        blob = b"hello\x00"
        end = _scan_string(blob, 0)
        self.assertEqual(end, 6)

    def test_run_below_minimum_rejected(self):
        from src.splat.segtypes.win32.data import _scan_string

        # 3 chars + NUL < STRING_MIN_LEN (4).
        self.assertIsNone(_scan_string(b"hi\x00\x00", 0))

    def test_missing_terminator_rejected(self):
        from src.splat.segtypes.win32.data import _scan_string

        # Printable run with no NUL terminator before EOF.
        self.assertIsNone(_scan_string(b"hello", 0))

    def test_latin1_supplement_accepted(self):
        from src.splat.segtypes.win32.data import _scan_string

        # 'Müller' in Latin-1: M ü l l e r \0 — middle byte 0xFC is in
        # the Latin-1 Supplement printable range (0xA0-0xFF). The
        # scanner accepts it (symmetric with the wide-string scanner).
        blob = b"M\xfcller\x00"
        end = _scan_string(blob, 0)
        self.assertEqual(end, 7)

    def test_non_printable_byte_terminates(self):
        from src.splat.segtypes.win32.data import _scan_string

        # 0x01 (SOH) isn't in our printable set — scanner short-circuits
        # without finding a NUL terminator.
        self.assertIsNone(_scan_string(b"ab\x01cd\x00", 0))


class WideStringDetectionTest(unittest.TestCase):
    """Wide-string scanner returns the byte range past the WCHAR NUL."""

    def test_simple_utf16_string(self):
        from src.splat.segtypes.win32.data import _scan_wide_string, _decode_wide

        # "Hello\0" in UTF-16LE
        blob = b"H\x00e\x00l\x00l\x00o\x00\x00\x00"
        end = _scan_wide_string(blob, 0)
        self.assertEqual(end, 12)
        assert end is not None
        self.assertEqual(_decode_wide(blob[: end - 2]), "Hello")

    def test_too_short_rejected(self):
        from src.splat.segtypes.win32.data import _scan_wide_string

        # "Hi\0" — only 2 WCHARs, below WIDE_STRING_MIN_LEN=4.
        self.assertIsNone(_scan_wide_string(b"H\x00i\x00\x00\x00", 0))

    def test_misaligned_offset(self):
        from src.splat.segtypes.win32.data import _scan_wide_string

        # Odd start offsets aren't valid WCHAR positions.
        blob = b"\x00H\x00e\x00l\x00l\x00o\x00\x00\x00"
        self.assertIsNone(_scan_wide_string(blob, 1))

    def test_high_byte_nonzero_rejected(self):
        from src.splat.segtypes.win32.data import _scan_wide_string

        # If the WCHAR's high byte is nonzero (codepoint > U+00FF — i.e.
        # outside Basic Latin + Latin-1 Supplement, the conservative
        # Western-language coverage zone), our cautious detector skips
        # the run to avoid false positives.
        # Polish 'ł' is U+0142 -> UTF-16LE bytes 0x42 0x01.
        blob = b"\x42\x01\x42\x01\x42\x01\x42\x01\x00\x00"
        self.assertIsNone(_scan_wide_string(blob, 0))

    def test_latin1_supplement_accepted(self):
        from src.splat.segtypes.win32.data import _scan_wide_string

        # Latin-1 Supplement (U+00A0 .. U+00FF) covers German umlauts,
        # French accents, Spanish ñ — common in localised resources.
        # 'Müller' is M ü l l e r -> 4D 00 FC 00 6C 00 6C 00 65 00 72 00.
        blob = b"\x4d\x00\xfc\x00\x6c\x00\x6c\x00\x65\x00\x72\x00\x00\x00"
        end = _scan_wide_string(blob, 0)
        self.assertEqual(end, len(blob))


class Win32SegBssTest(unittest.TestCase):
    def test_reserved_size_resolution(self):
        """Win32SegBss.reserved_size resolves: explicit yaml bss_size
        wins over vram-end - vram-start arithmetic; zero when neither
        is available."""
        from src.splat.segtypes.win32.bss import Win32SegBss

        obj = Win32SegBss.__new__(Win32SegBss)
        # Upstream's bss_size rework requires every Segment to have a
        # bss_size attribute. Provide it for the bypass-init path.
        obj.bss_size = 0

        # 1) Explicit bss_size in yaml wins.
        obj.yaml = {"bss_size": 0x1000}
        obj.vram_start = 0x10000000
        # vram_end is a @property derived from vram_start + size; ignore
        # via direct attribute override.
        self.assertEqual(obj.reserved_size, 0x1000)

        # 2) Without bss_size, fall back to vram_end - vram_start.
        # vram_end on the Segment base is a property — emulate by giving
        # obj.rom_start / rom_end so size resolves to a known value.
        obj.yaml = {}
        obj.rom_start = 0
        obj.rom_end = 0x500
        # vram_end = vram_start + (rom_end - rom_start) = 0x10000500
        self.assertEqual(obj.reserved_size, 0x500)

        # 3) Neither yaml nor a derivable vram_end → 0.
        obj.yaml = {}
        obj.rom_start = None
        obj.rom_end = None
        obj.vram_start = None
        self.assertEqual(obj.reserved_size, 0)


class ResolveExactEncodingTest(unittest.TestCase):
    """Direct tests for the shared helper, complementing the segtype-
    level inheritance test."""

    def test_per_subsegment_yaml_wins(self):
        self.assertTrue(
            win32_platform.resolve_exact_encoding({"exact_encoding": True}, None)
        )
        self.assertFalse(
            win32_platform.resolve_exact_encoding({"exact_encoding": False}, None)
        )

    def test_parent_yaml_used_when_subsegment_silent(self):
        import types

        parent = types.SimpleNamespace(yaml={"exact_encoding": True})
        self.assertTrue(win32_platform.resolve_exact_encoding({}, parent))
        # Subsegment 'False' beats parent 'True'.
        self.assertFalse(
            win32_platform.resolve_exact_encoding({"exact_encoding": False}, parent)
        )

    def test_default_returned_when_neither_speaks_up(self):
        self.assertFalse(win32_platform.resolve_exact_encoding({}, None))
        self.assertTrue(win32_platform.resolve_exact_encoding({}, None, default=True))

    def test_non_dict_yaml_is_silent(self):
        # If the subsegment YAML is a list (the bare-tuple shorthand
        # form), `isinstance(yaml, dict)` falls through; helper must
        # not crash, just return the default.
        self.assertFalse(
            win32_platform.resolve_exact_encoding([0x200, "text", "main"], None)
        )

    def test_parent_without_yaml_attribute_handled(self):
        # The parent argument is sometimes None at runtime; sometimes
        # a Segment-shaped object whose `.yaml` is a list. Both must
        # fall through to the default cleanly.
        import types

        no_yaml = types.SimpleNamespace()
        list_yaml = types.SimpleNamespace(yaml=[])
        self.assertFalse(win32_platform.resolve_exact_encoding({}, no_yaml))
        self.assertFalse(win32_platform.resolve_exact_encoding({}, list_yaml))


class Win32ExactEncodingInheritanceTest(unittest.TestCase):
    def test_inheritance_chain(self):
        """exact_encoding resolves in priority order:
        subsegment YAML > parent code-group YAML > class default."""
        from src.splat.segtypes.win32.text import Win32SegText
        from src.splat.segtypes.win32.data import Win32SegData
        from src.splat.segtypes.win32.pdata import Win32SegPdata

        for cls in (Win32SegText, Win32SegData, Win32SegPdata):
            # Instantiate manually (bypass splat's segment factory).
            obj = cls.__new__(cls)
            obj.yaml = {}
            obj.parent = None
            self.assertFalse(obj.exact_encoding)  # type: ignore[attr-defined]

            obj.yaml = {"exact_encoding": True}
            self.assertTrue(obj.exact_encoding)  # type: ignore[attr-defined]

            obj.yaml = {}
            # Use a simple namespace as parent — it just needs a .yaml attr.
            import types

            obj.parent = types.SimpleNamespace(yaml={"exact_encoding": True})  # type: ignore[assignment]
            self.assertTrue(obj.exact_encoding)  # type: ignore[attr-defined]

            obj.yaml = {"exact_encoding": False}
            self.assertFalse(obj.exact_encoding)  # type: ignore[attr-defined]


class CreateConfigRejectionTest(unittest.TestCase):
    def test_non_pe_file_falls_through_to_error(self):
        """create_config.main() with a file that's neither N64 / PSX /
        ELF / PE bytes must log.error → SystemExit, not crash silently
        partway through."""
        import tempfile
        from src.splat.scripts.create_config import main as create_config_main
        from pathlib import Path as _P

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"random non-PE garbage data, neither MZ nor ELF")
            tmp = _P(f.name)
        try:
            with self.assertRaises(SystemExit):
                create_config_main(tmp, None)
        finally:
            tmp.unlink()


class CreateConfigExportLabelDedupTest(unittest.TestCase):
    def test_clashing_sanitized_labels_get_ordinal_suffix(self):
        """Two C++ exports with distinct mangled names that sanitize to the
        same identifier (e.g. 'foo@bar' and 'foo$bar' both -> 'foo_bar')
        must produce unique symbol_addrs labels — splat rejects
        duplicates."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        funcs_rva = rdata_rva + 0x28
        names_rva = funcs_rva + 0x8  # 2 funcs * 4
        ords_rva = names_rva + 0x8  # 2 names * 4
        # Strings laid out at +0x40, +0x48, +0x50.
        s1_rva = rdata_rva + 0x40
        s2_rva = rdata_rva + 0x48
        dll_name_rva = rdata_rva + 0x50
        body = bytearray(0x80)
        struct.pack_into(
            "<IIHHIIIIIII",
            body,
            0x00,
            0,
            0,
            0,
            0,
            dll_name_rva,
            1,  # ordinal base
            2,  # num funcs
            2,  # num names
            funcs_rva,
            names_rva,
            ords_rva,
        )
        struct.pack_into("<II", body, 0x28, 0x1000, 0x1010)  # funcs
        struct.pack_into("<II", body, 0x30, s1_rva, s2_rva)  # name ptrs
        struct.pack_into("<HH", body, 0x38, 0, 1)  # ordinal idxs
        body[0x40 : 0x40 + 8] = b"foo@bar\x00"
        body[0x48 : 0x48 + 8] = b"foo$bar\x00"
        body[0x50 : 0x50 + 11] = b"clash.dll\x00\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x20,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x20,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(rdata_rva, 0x80)],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-dedup-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            dll = tmpdir / "clash.dll"
            dll.write_bytes(pe_bytes)
            create_win32_config(dll, pe_bytes)
            txt = (tmpdir / "symbol_addrs.txt").read_text()
            # Both clash to 'foo_bar' after sanitize. First wins as-is;
            # second gets ordinal suffix.
            self.assertIn("foo_bar = 0x", txt)
            self.assertIn("foo_bar__ord2", txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigEntrypointExportCollisionTest(unittest.TestCase):
    def test_export_named_entrypoint_does_not_collide_with_entrypoint_symbol(self):
        """A DLL whose entry point exists AND whose export table contains
        a function literally named 'entrypoint' would otherwise emit two
        symbol_addrs rows with the same label, which splat rejects.
        Second occurrence must get the ordinal suffix."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        funcs_rva = rdata_rva + 0x28
        names_rva = funcs_rva + 0x4
        ords_rva = names_rva + 0x4
        name_str_rva = rdata_rva + 0x40
        dll_name_rva = rdata_rva + 0x50
        body = bytearray(0x80)
        struct.pack_into(
            "<IIHHIIIIIII",
            body,
            0x00,
            0,
            0,
            0,
            0,
            dll_name_rva,
            1,
            1,
            1,
            funcs_rva,
            names_rva,
            ords_rva,
        )
        struct.pack_into("<I", body, 0x28, 0x1010)
        struct.pack_into("<I", body, 0x2C, name_str_rva)
        struct.pack_into("<H", body, 0x30, 0)
        body[0x40 : 0x40 + 11] = b"entrypoint\x00"
        body[0x50 : 0x50 + 11] = b"collide.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x20,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x20,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(rdata_rva, 0x80)],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-collide-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            dll = tmpdir / "collide.dll"
            dll.write_bytes(pe_bytes)
            create_win32_config(dll, pe_bytes)
            txt = (tmpdir / "symbol_addrs.txt").read_text()
            # Built-in entrypoint kept; conflicting export suffixed.
            self.assertIn("entrypoint = 0x", txt)
            self.assertIn("entrypoint__ord1", txt)
            # No duplicate bare "entrypoint =" lines.
            label_count = sum(
                1
                for line in txt.splitlines()
                if line.lstrip().startswith("entrypoint =")
            )
            self.assertEqual(label_count, 1)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigZeroSizeBssTest(unittest.TestCase):
    def test_zero_virtual_size_bss_section_is_skipped(self):
        """A section flagged as UNINITIALIZED_DATA with VirtualSize = 0
        has no runtime footprint. Emitting `bss_size: 0x0` would create
        a malformed splat segment — skip such sections in YAML
        generation."""
        # Build PE with .text + a degenerate empty .bss-flagged section.
        text_body = b"\x90" * FILE_ALIGN
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": text_body,
                },
                # raw_size=0, virtual_size=0, characteristics has
                # SCN_CNT_UNINITIALIZED_DATA (0x00000080).
                {
                    "name": b".bss",
                    "vsize": 0,
                    "vaddr": 0x2000,
                    "rsize": 0,
                    "rptr": 0,
                    "chars": 0xC0000080,
                    "body": b"",
                },
            ],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-emptybss-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "emptybss.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            yaml_txt = (tmpdir / "emptybss.exe.yaml").read_text()
            self.assertNotIn("bss_size: 0x0", yaml_txt)
            # Empty .bss section should not produce a segment line at all.
            self.assertNotIn("name: bss,", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigSectionNameDedupTest(unittest.TestCase):
    def test_duplicate_section_names_disambiguated_in_yaml(self):
        """PE format doesn't require unique section names. A packed or
        hand-crafted image with two '.text' sections must still produce
        a valid splat YAML (no duplicate segment names)."""
        # Two .text-named sections.
        sec_body = b"\x90" * FILE_ALIGN
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": sec_body,
                },
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x2000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN * 2,
                    "chars": 0x60000020,
                    "body": sec_body,
                },
            ],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-dupesec-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "dupe.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            yaml_path = tmpdir / "dupe.exe.yaml"
            yaml_txt = yaml_path.read_text()
            # First occurrence keeps the bare name; second gets a "_1" suffix.
            self.assertIn("name: text", yaml_txt)
            self.assertIn("name: text_1", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigLeadingDigitSanitizeTest(unittest.TestCase):
    def test_export_starting_with_digit_gets_underscore_prefix(self):
        """Exports named with a leading digit (legacy D3D / some Delphi
        outputs) must not produce GAS-invalid labels like '7ZipOpen = ...'.
        Prefix with underscore to keep the identifier valid."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        funcs_rva = rdata_rva + 0x28
        names_rva = funcs_rva + 0x4
        ords_rva = names_rva + 0x4
        name_str_rva = rdata_rva + 0x40
        dll_name_rva = rdata_rva + 0x50
        body = bytearray(0x80)
        struct.pack_into(
            "<IIHHIIIIIII",
            body,
            0x00,
            0,
            0,
            0,
            0,
            dll_name_rva,
            1,
            1,
            1,
            funcs_rva,
            names_rva,
            ords_rva,
        )
        struct.pack_into("<I", body, 0x28, 0x1000)
        struct.pack_into("<I", body, 0x2C, name_str_rva)
        struct.pack_into("<H", body, 0x30, 0)
        body[0x40 : 0x40 + 9] = b"7ZipOpen\x00"
        body[0x50 : 0x50 + 7] = b"7z.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x20,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x20,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(rdata_rva, 0x80)],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-digit-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            dll = tmpdir / "digit.dll"
            dll.write_bytes(pe_bytes)
            create_win32_config(dll, pe_bytes)
            txt = (tmpdir / "symbol_addrs.txt").read_text()
            self.assertIn("_7ZipOpen = 0x", txt)
            # No bare-digit-leading labels.
            for line in txt.splitlines():
                if "=" in line and "0x" in line:
                    label = line.split("=")[0].strip()
                    if label:
                        self.assertFalse(
                            label[0].isdigit(),
                            f"label starts with digit: {label!r}",
                        )
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigImportDllSanitizeTest(unittest.TestCase):
    def test_dll_name_with_hyphen_is_fully_sanitized(self):
        """A DLL name like 'api-ms-win-core-com-l1-1-0.dll' would, with
        bare `.replace('.', '_')`, leave hyphens in the label — invalid
        GAS identifiers. Sanitize the whole stem."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        body = bytearray(0x100)
        ilt_rva = rdata_rva + 0x50
        iat_rva = rdata_rva + 0x60
        dll_rva = rdata_rva + 0x30
        hn_rva = rdata_rva + 0x70
        # Descriptor 1 + null terminator.
        struct.pack_into("<IIIII", body, 0x00, ilt_rva, 0, 0, dll_rva, iat_rva)
        struct.pack_into("<IIIII", body, 0x14, 0, 0, 0, 0, 0)
        # Hyphenated DLL name.
        dll_name = b"api-ms-win-core-com-l1-1-0.dll\x00"
        body[0x30 : 0x30 + len(dll_name)] = dll_name
        # Single thunk + NUL.
        struct.pack_into("<II", body, 0x50, hn_rva, 0)
        struct.pack_into("<II", body, 0x60, hn_rva, 0)
        # Hint/name.
        body[0x70 : 0x70 + 2] = b"\x00\x00"
        body[0x72 : 0x72 + 9] = b"CoCreate\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x20,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x20,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 0x100)],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-dllname-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "hyphen.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            txt = (tmpdir / "symbol_addrs.txt").read_text()
            self.assertIn("imp_api_ms_win_core_com_l1_1_0_dll_CoCreate", txt)
            # No raw hyphens in any emitted symbol label (label part only,
            # not the comment tail).
            for line in txt.splitlines():
                if "=" in line and "0x" in line:
                    label = line.split("=")[0].strip()
                    self.assertNotIn("-", label, f"hyphen leaked into label: {line}")
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigImportLabelDedupTest(unittest.TestCase):
    def test_clashing_sanitized_import_labels_get_rva_suffix(self):
        """Two imports from the same DLL with distinct mangled names
        that sanitize to the same identifier must produce unique
        symbol_addrs labels — splat rejects duplicates."""
        # Layout: .text + .rdata where .rdata holds the import table:
        #   0x00..0x28 : two IMAGE_IMPORT_DESCRIPTOR + null terminator
        #   0x40..0x4F : DLL name "kernel32.dll\x00"
        #   0x50..0x57 : ILT (two thunks + NUL)
        #   0x60..0x67 : IAT  (two thunks + NUL, mirrors ILT)
        #   0x70..    : hint/name records and the function names
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        body = bytearray(0x100)

        ilt_rva = rdata_rva + 0x50
        iat_rva = rdata_rva + 0x60
        dll_rva = rdata_rva + 0x40
        # Hint/name records.
        hn1_rva = rdata_rva + 0x70
        hn2_rva = rdata_rva + 0x80

        # Descriptor 1: kernel32.dll with our two imports.
        struct.pack_into(
            "<IIIII",
            body,
            0x00,
            ilt_rva,
            0,
            0,
            dll_rva,
            iat_rva,
        )
        # NULL terminator descriptor.
        struct.pack_into("<IIIII", body, 0x14, 0, 0, 0, 0, 0)

        body[0x40 : 0x40 + 13] = b"kernel32.dll\x00"

        # ILT entries (32-bit thunks since this is PE32).
        struct.pack_into("<III", body, 0x50, hn1_rva, hn2_rva, 0)
        struct.pack_into("<III", body, 0x60, hn1_rva, hn2_rva, 0)

        # Hint/name records: each is WORD hint + NUL-terminated name.
        body[0x70 : 0x70 + 2] = b"\x00\x00"
        body[0x72 : 0x72 + 8] = b"foo@bar\x00"
        body[0x80 : 0x80 + 2] = b"\x00\x00"
        body[0x82 : 0x82 + 8] = b"foo$bar\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x20,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x20,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 0x100)],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-imp-dedup-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "imp_clash.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            txt = (tmpdir / "symbol_addrs.txt").read_text()
            # First import wins as-is; second collides and gets RVA suffix.
            self.assertIn("imp_kernel32_dll_foo_bar = 0x", txt)
            self.assertIn("imp_kernel32_dll_foo_bar__rva", txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigEntrypointOmissionTest(unittest.TestCase):
    def test_dll_with_no_entrypoint_omits_entrypoint_symbol(self):
        """A DLL built without DllMain has AddressOfEntryPoint = 0. The
        generated symbol_addrs file must NOT include an 'entrypoint = ...'
        line in that case, otherwise we'd label the PE header as a
        function."""
        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        # PE32 DLL with entry_point_rva = 0.
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        body = b"\x00" * 0x10
        size_of_opt = 0xE0
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            2,
            0x12345678,
            0,
            0,
            size_of_opt,
            0x010F | 0x2000,  # IMAGE_FILE_DLL
        )
        opt = bytearray(_opt_header_pe32(entry_rva=0))
        sec1 = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        sec2 = _section_header(
            b".rdata", 0x10, rdata_rva, FILE_ALIGN, rdata_rptr, 0x40000040
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt) + sec1 + sec2
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN + body.ljust(FILE_ALIGN, b"\x00")
        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-noentry-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            dll_path = tmpdir / "no_entry.dll"
            dll_path.write_bytes(bytes(buf))
            create_win32_config(dll_path, bytes(buf))
            sym_path = tmpdir / "symbol_addrs.txt"
            self.assertTrue(sym_path.exists(), "symbols file should be written")
            self.assertNotIn(
                "entrypoint =",
                sym_path.read_text(),
                "entrypoint must be omitted when AddressOfEntryPoint = 0",
            )
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class Win32SegtypeAliasTest(unittest.TestCase):
    def test_asm_resolves_to_text(self):
        """`type: asm` in YAML must resolve to Win32SegAsm which inherits
        from Win32SegText — same behaviour as `type: text`, matching the
        conventional segtype name used by the other splat platforms."""
        from src.splat.segtypes.win32.asm import Win32SegAsm
        from src.splat.segtypes.win32.text import Win32SegText

        self.assertTrue(issubclass(Win32SegAsm, Win32SegText))
        # No fields overridden — pure alias.
        self.assertEqual(Win32SegAsm.__bases__, (Win32SegText,))


class Win32SanitizeLabelHelpersTest(unittest.TestCase):
    def test_sanitize_label_passthrough_for_clean_id(self):
        self.assertEqual(win32_platform.sanitize_label("CreateThread"), "CreateThread")

    def test_sanitize_label_replaces_punctuation(self):
        self.assertEqual(win32_platform.sanitize_label("foo@bar-baz?"), "foo_bar_baz_")

    def test_sanitize_label_prefixes_leading_digit(self):
        self.assertEqual(win32_platform.sanitize_label("7zopen"), "_7zopen")

    def test_sanitize_label_leaves_underscore_leading_alone(self):
        self.assertEqual(win32_platform.sanitize_label("_main"), "_main")

    def test_sanitize_label_empty_string(self):
        self.assertEqual(win32_platform.sanitize_label(""), "")

    def test_compute_iat_labels_collision_dedup(self):
        """Two imports from the same DLL that sanitize to the same label
        get the second occurrence suffixed with the slot RVA."""
        pe = win32_platform.PEInfo(image_base=0x400000)
        pe.imports.append(
            win32_platform.PEImport(
                dll="user32.dll", name="foo@x", ordinal=None, iat_rva=0x2000
            )
        )
        pe.imports.append(
            win32_platform.PEImport(
                dll="user32.dll", name="foo$x", ordinal=None, iat_rva=0x2004
            )
        )
        labels = win32_platform.compute_iat_labels(pe)
        # Two distinct VAs, two distinct labels — first bare, second suffixed.
        self.assertEqual(labels[0x400000 + 0x2000], "imp_user32_dll_foo_x")
        self.assertEqual(labels[0x400000 + 0x2004], "imp_user32_dll_foo_x__rva2004")

    def test_compute_export_labels_reserves_seed_set(self):
        """An export literally named 'entrypoint' must NOT clobber the
        synthesized entry-point symbol — dedup adds the ordinal suffix."""
        pe = win32_platform.PEInfo(image_base=0x10000000)
        pe.exports.append(
            win32_platform.PEExport(
                name="entrypoint", ordinal=7, rva=0x1234, forwarder=None
            )
        )
        labels = win32_platform.compute_export_labels(pe, reserved={"entrypoint"})
        self.assertEqual(labels[0x10000000 + 0x1234], "entrypoint__ord7")

    def test_compute_export_labels_skips_forwarders(self):
        pe = win32_platform.PEInfo(image_base=0x10000000)
        pe.exports.append(
            win32_platform.PEExport(
                name="GoesElsewhere",
                ordinal=1,
                rva=0x100,
                forwarder="OTHER.dll.DoThing",
            )
        )
        labels = win32_platform.compute_export_labels(pe)
        self.assertEqual(labels, {})


class ParseImportsHintFallbackTest(unittest.TestCase):
    def test_empty_name_falls_back_to_hint_as_ordinal(self):
        """When a hint/name record has a zero-byte name string (malformed
        or stripped), parse_imports must capture the 16-bit hint as the
        import's ordinal so the IAT slot still gets a meaningful
        `imp_X_ordinal_N` label instead of `imp_X_ordinal_None`."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        body = bytearray(0x100)
        ilt_rva = rdata_rva + 0x50
        iat_rva = rdata_rva + 0x60
        dll_rva = rdata_rva + 0x30
        hn_rva = rdata_rva + 0x70
        # Descriptor 1 + null terminator.
        struct.pack_into("<IIIII", body, 0x00, ilt_rva, 0, 0, dll_rva, iat_rva)
        struct.pack_into("<IIIII", body, 0x14, 0, 0, 0, 0, 0)
        body[0x30 : 0x30 + 9] = b"empty.dll"
        # ILT/IAT: single thunk → hint/name record at hn_rva, then NUL.
        struct.pack_into("<II", body, 0x50, hn_rva, 0)
        struct.pack_into("<II", body, 0x60, hn_rva, 0)
        # Hint/name: hint = 0x1234, name string = "" (just a NUL).
        struct.pack_into("<H", body, 0x70, 0x1234)
        body[0x72] = 0  # name terminator

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x20,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x20,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 0x100)],
        )

        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.imports), 1)
        self.assertIsNone(pe.imports[0].name)
        self.assertEqual(pe.imports[0].ordinal, 0x1234)


class CreateConfigSecurityCookieTest(unittest.TestCase):
    def test_security_cookie_va_emits_symbol(self):
        """A binary with /GS enabled has a SecurityCookie VA in its
        LoadConfig directory. Promote it as a `security_cookie` data
        symbol so disasm cross-references to the cookie's storage slot
        resolve to a meaningful label."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        lc_size = 0x48
        body = bytearray(0x80)
        struct.pack_into("<I", body, 0, lc_size)
        struct.pack_into("<I", body, 0x3C, IMAGE_BASE + rdata_rva + 0x50)
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0)] * 10 + [(rdata_rva, lc_size)],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-gs-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "gs.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            txt = (tmpdir / "symbol_addrs.txt").read_text()
            self.assertIn("security_cookie = 0x", txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigUnwindSymbolsTest(unittest.TestCase):
    def test_runtime_function_unwind_rvas_emit_symbols(self):
        """Each PE32+ RUNTIME_FUNCTION entry's UnwindInfoAddress should
        produce an `unwind_<va>` symbol in symbol_addrs.txt so the
        pdata `.long` rows can reference unwind info by label."""
        # Build a PE32+ binary with .pdata containing 2 RUNTIME_FUNCTION
        # entries: (1000, 100D, 4000) and (1100, 110D, 4020).
        text_body = b"\x90" * FILE_ALIGN
        # .pdata layout (PE32+): 12 bytes per record + 12-byte null terminator
        pdata_body = struct.pack(
            "<IIIIIIIII",
            0x1000,
            0x100D,
            0x4000,
            0x1100,
            0x110D,
            0x4020,
            0,
            0,
            0,
        )
        pdata_body = pdata_body.ljust(FILE_ALIGN, b"\x00")

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x200,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": text_body,
                },
                {
                    "name": b".pdata",
                    "vsize": 0x100,
                    "vaddr": 0x3000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN * 2,
                    "chars": 0x40000040,
                    "body": pdata_body,
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0x3000, 24),  # Exception Table → .pdata
            ],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-unwind-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "uw.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            txt = (tmpdir / "symbol_addrs.txt").read_text()
            # Unwind RVAs 0x4000 / 0x4020 → VAs 0x140004000 / 0x140004020.
            self.assertIn("unwind_140004000 = 0x", txt)
            self.assertIn("unwind_140004020 = 0x", txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigMingwClangDetectionTest(unittest.TestCase):
    def test_mingw_imports_trigger_mingw_compiler_tag(self):
        """A PE importing libgcc_s / libstdc++ / libwinpthread is GCC-
        linked MinGW. Generated YAML should say `compiler: MINGW`."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        body = bytearray(0x100)
        ilt_rva = rdata_rva + 0x50
        iat_rva = rdata_rva + 0x60
        dll_rva = rdata_rva + 0x30
        hn_rva = rdata_rva + 0x70
        struct.pack_into("<IIIII", body, 0x00, ilt_rva, 0, 0, dll_rva, iat_rva)
        struct.pack_into("<IIIII", body, 0x14, 0, 0, 0, 0, 0)
        body[0x30 : 0x30 + 23] = b"libgcc_s_dw2-1.dll\x00\x00\x00\x00\x00"
        struct.pack_into("<II", body, 0x50, hn_rva, 0)
        struct.pack_into("<II", body, 0x60, hn_rva, 0)
        body[0x70 : 0x70 + 14] = b"\x00\x00__main\x00\x00\x00\x00\x00\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x20,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x20,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 0x100)],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-mingw-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "mingw.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            yaml_txt = (tmpdir / "mingw.exe.yaml").read_text()
            self.assertIn("compiler: MINGW", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigCfgSymbolsTest(unittest.TestCase):
    def test_cfg_function_rvas_emit_cfg_target_rows(self):
        """A /guard:cf-enabled PE lists every valid indirect-call target
        in the GuardCFFunctionTable. Promote each to a `cfg_target_N`
        symbol so the disassembly references them by label."""
        # PE32 with LoadConfig pointing to a small CFG function table.
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # LoadConfig at +0x00 (size 0x60), CFG table at +0x70.
        cfg_table_off = 0x70
        cfg_table_va = IMAGE_BASE + rdata_rva + cfg_table_off
        lc_size = 0x60
        body = bytearray(0x100)
        struct.pack_into("<I", body, 0, lc_size)
        struct.pack_into("<I", body, 0x54, cfg_table_va)  # GuardCFFunctionTable
        struct.pack_into("<I", body, 0x58, 3)  # GuardCFFunctionCount
        struct.pack_into("<I", body, 0x5C, 0)  # GuardFlags = 0 (no extra bytes)
        struct.pack_into("<III", body, cfg_table_off, 0x1000, 0x1010, 0x1020)

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x100,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0)] * 10 + [(rdata_rva, lc_size)],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-cfg-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "cfg.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            txt = (tmpdir / "symbol_addrs.txt").read_text()
            self.assertIn("cfg_target_0 = 0x", txt)
            self.assertIn("cfg_target_1 = 0x", txt)
            self.assertIn("cfg_target_2 = 0x", txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigReadOnlyTailBssTest(unittest.TestCase):
    def test_readonly_section_with_tail_gets_bss_subsegment(self):
        """A .rdata section with VirtualSize > SizeOfRawData has a tail
        that the loader zero-fills at map time. Even though it's not
        writable, we still need a BSS subsegment so splat models the
        linker layout correctly."""
        text_body = b"\x90" * FILE_ALIGN
        rdata_body = b"\x11" * 0x10  # only 0x10 raw bytes
        sec_text = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        # .rdata with virtual_size = 0x100 but raw_size = 0x200 (FILE_ALIGN).
        # Actually rdata raw is FILE_ALIGN (0x200 bytes), virtual = 0x400 →
        # tail = 0x200 zero-fill.
        sec_rdata = _section_header(
            b".rdata", 0x400, 0x2000, FILE_ALIGN, FILE_ALIGN * 2, 0x40000040
        )
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            2,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec_text + sec_rdata
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + text_body + rdata_body.ljust(FILE_ALIGN, b"\x00")

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-rotail-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "rotail.exe"
            exe.write_bytes(bytes(buf))
            create_win32_config(exe, bytes(buf))
            yaml_txt = (tmpdir / "rotail.exe.yaml").read_text()
            # rdata's tail section should be BSS.
            self.assertIn("rdata_bss", yaml_txt)
            self.assertIn("bss_size: 0x200", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigTlsAndSafeSehSymbolsTest(unittest.TestCase):
    def test_tls_callbacks_and_safeseh_emit_symbol_addrs_rows(self):
        """The PE optional header's TLS directory enumerates callbacks
        run by the loader before DllMain. SafeSEH handlers (from the
        Load Config directory) name every legal exception filter. Both
        should appear in the generated symbol_addrs.txt so the analyst
        can navigate to them by label."""
        # Build a PE32 with TLS directory + LoadConfig + SafeSEH table.
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # TLS directory layout: StartAddrOfRawData(4) + EndAddr(4) +
        # AddressOfIndex(4) + AddressOfCallBacks(4) + SizeOfZeroFill(4)
        # + Characteristics(4) = 0x18 bytes.
        tls_dir_rva = rdata_rva + 0x00
        cb_array_rva = rdata_rva + 0x18
        # LoadConfig at rdata + 0x40 (size 0x48), SEH table at rdata + 0x90.
        lc_off = 0x40
        lc_rva = rdata_rva + lc_off
        seh_table_off = 0x90
        seh_table_va = IMAGE_BASE + rdata_rva + seh_table_off

        body = bytearray(0x100)
        # TLS dir.
        struct.pack_into(
            "<IIIIII",
            body,
            0,
            0,
            0,
            0,  # raw start/end/index VAs
            IMAGE_BASE + cb_array_rva,  # AddressOfCallBacks
            0,
            0,
        )
        # Callback array: two VAs then NUL.
        struct.pack_into(
            "<III",
            body,
            0x18,
            IMAGE_BASE + 0x1010,
            IMAGE_BASE + 0x1020,
            0,
        )
        # LoadConfig (size 0x48).
        struct.pack_into("<I", body, lc_off + 0x00, 0x48)
        struct.pack_into("<I", body, lc_off + 0x3C, IMAGE_BASE + 0x2400)  # cookie
        struct.pack_into("<I", body, lc_off + 0x40, seh_table_va)
        struct.pack_into("<I", body, lc_off + 0x44, 2)
        # SEH handler RVAs.
        struct.pack_into("<II", body, seh_table_off, 0x1010, 0x1020)

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x100,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (tls_dir_rva, 0x18),
                (lc_rva, 0x48),
            ],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-tls-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "tls.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            txt = (tmpdir / "symbol_addrs.txt").read_text()
            self.assertIn("tls_callback_0 = 0x", txt)
            self.assertIn("tls_callback_1 = 0x", txt)
            self.assertIn("safeseh_0 = 0x", txt)
            self.assertIn("safeseh_1 = 0x", txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigNoFileBackedSectionsTest(unittest.TestCase):
    def test_pe_with_only_bss_sections_still_produces_valid_yaml(self):
        """A PE with no file-backed sections (pure BSS, e.g. some
        kernel-mode stubs or hand-crafted images) must still produce a
        valid splat YAML — the header segment + a footer offset for
        the file's total size is the only well-formed minimum."""
        # Build PE with header + a single BSS section (no raw bytes).
        sec_bss = struct.pack(
            "<8sIIIIIIHHI",
            b".bss\x00\x00\x00\x00",
            0x100,  # VirtualSize
            0x1000,  # VirtualAddress
            0,  # SizeOfRawData
            0,  # PointerToRawData
            0,
            0,
            0,
            0,
            0xC0000080,  # READ | WRITE | UNINITIALIZED_DATA
        )
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F | 0x2000,  # IMAGE_FILE_DLL
        )
        opt = _opt_header_pe32(entry_rva=0)
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec_bss
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header)

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P
        import yaml

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-bssonly-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            dll = tmpdir / "bssonly.dll"
            dll.write_bytes(bytes(buf))
            create_win32_config(dll, bytes(buf))
            doc = yaml.safe_load((tmpdir / "bssonly.dll.yaml").read_text())
            # Should have a header segment and the BSS segment.
            segs = doc["segments"]
            self.assertTrue(
                any(isinstance(s, dict) and s.get("type") == "header" for s in segs)
            )
            self.assertTrue(
                any(isinstance(s, dict) and s.get("type") == "bss" for s in segs)
            )
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigPhantomSectionTest(unittest.TestCase):
    def test_section_with_zero_raw_pointer_treated_as_bss(self):
        """A section whose SizeOfRawData > 0 but PointerToRawData == 0
        is loader-classified as uninitialised data — the file simply
        doesn't back its bytes. Auto-config must not emit a file-backed
        segment pointing at offset 0 (which is the DOS header) for it."""
        text_body = b"\x90" * FILE_ALIGN
        # Build PE with .text + a "phantom" section claiming raw_size
        # but raw_pointer = 0.
        sec_text = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        # Hand-craft .bss: raw_size=0x40, raw_pointer=0, virtual_size=0x80.
        sec_bss = struct.pack(
            "<8sIIIIIIHHI",
            b".bss\x00\x00\x00\x00",
            0x80,  # VirtualSize
            0x2000,  # VirtualAddress
            0x40,  # SizeOfRawData (nonzero!)
            0,  # PointerToRawData (zero — phantom)
            0,
            0,
            0,
            0,
            0xC0000040,  # READ | WRITE | INITIALIZED_DATA (no UNINIT flag)
        )
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            2,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec_text + sec_bss
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + text_body

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-phantom-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "phantom.exe"
            exe.write_bytes(bytes(buf))
            create_win32_config(exe, bytes(buf))
            yaml_txt = (tmpdir / "phantom.exe.yaml").read_text()
            # The phantom .bss should NOT be emitted as a file-backed
            # `type: code` subsegment (which would point at offset 0).
            self.assertNotIn("[0x0, ", yaml_txt)
            # It SHOULD appear as a bss segment.
            self.assertIn("name: bss,", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigResourceOnlyDllTest(unittest.TestCase):
    def test_pure_resource_dll_produces_loadable_yaml(self):
        """A resource-only DLL has no entrypoint, no exports, no imports
        — just a .rsrc section. create_win32_config should produce a
        symbol_addrs.txt that contains no broken symbol entries (could
        be empty) and a YAML that splat can load without errors."""
        rsrc_body = b"\x00" * 0x40  # placeholder; not a real .rsrc tree
        body = b"\x90" * FILE_ALIGN
        # PE32 DLL: no exports/imports/relocs/etc., one .rsrc section.
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F | 0x2000,  # IMAGE_FILE_DLL
        )
        opt = bytearray(_opt_header_pe32(entry_rva=0))
        sec_rsrc = _section_header(
            b".rsrc", 0x40, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x40000040
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt) + sec_rsrc
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + body[: len(rsrc_body)].ljust(FILE_ALIGN, b"\x00")

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P
        import yaml

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-rsrc-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            dll = tmpdir / "resonly.dll"
            dll.write_bytes(bytes(buf))
            create_win32_config(dll, bytes(buf))
            sym = (tmpdir / "symbol_addrs.txt").read_text()
            # No entrypoint = (entry was 0); no exports / imports.
            self.assertNotIn("entrypoint =", sym)
            # symbol_addrs has the splat preamble comment but no actual
            # symbol bindings (no `name = 0x... ;` lines).
            content_lines = [
                ln
                for ln in sym.splitlines()
                if ln.strip() and not ln.lstrip().startswith("//")
            ]
            self.assertEqual(content_lines, [])
            # YAML must be loadable.
            yaml_doc = yaml.safe_load((tmpdir / "resonly.dll.yaml").read_text())
            self.assertEqual(yaml_doc["options"]["platform"], "win32")
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigBinClassificationTest(unittest.TestCase):
    def test_reloc_and_rsrc_sections_classified_as_bin(self):
        """`.reloc` and `.rsrc` are structured loader-time data — their
        bytes aren't meaningful as pointers / strings to disassembly.
        Auto-config should mark them as opaque `bin` subsegments to
        skip the string/pointer heuristics that would otherwise emit
        misleading `.long`/`.asciz` directives over their content."""
        body = b"\x90" * FILE_ALIGN
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": body,
                },
                {
                    "name": b".rsrc",
                    "vsize": 0x10,
                    "vaddr": 0x2000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN * 2,
                    "chars": 0x40000040,
                    "body": body,
                },
                {
                    "name": b".reloc",
                    "vsize": 0x10,
                    "vaddr": 0x3000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN * 3,
                    "chars": 0x42000040,
                    "body": body,
                },
            ],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-bin-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "bn.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            yaml_txt = (tmpdir / "bn.exe.yaml").read_text()
            self.assertIn(", bin, rsrc_main", yaml_txt)
            self.assertIn(", bin, reloc_main", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigPdataDetectTest(unittest.TestCase):
    def test_pe32_plus_pdata_section_gets_pdata_subtype(self):
        """A PE32+ `.pdata` section should produce a `type: pdata`
        subsegment so RUNTIME_FUNCTION rows render structured by
        Win32SegPdata instead of as opaque bytes."""
        # Minimal PE32+ with .text + .pdata.
        body = b"\x90" * FILE_ALIGN
        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": body,
                },
                {
                    "name": b".pdata",
                    "vsize": 0x10,
                    "vaddr": 0x2000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN * 2,
                    "chars": 0x40000040,
                    "body": body,
                },
            ],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-pdata-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "pd.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            yaml_txt = (tmpdir / "pd.exe.yaml").read_text()
            # The .pdata section's subsegment should be type pdata.
            self.assertIn(", pdata,", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_pe32_pdata_section_not_recognised(self):
        """PE32 doesn't have a meaningful .pdata (RUNTIME_FUNCTION layout
        only exists for x64 SEH). Even a section named .pdata in PE32
        should fall through to rodata classification."""
        body = b"\x00" * FILE_ALIGN
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * FILE_ALIGN,
                },
                {
                    "name": b".pdata",
                    "vsize": 0x10,
                    "vaddr": 0x2000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN * 2,
                    "chars": 0x40000040,
                    "body": body,
                },
            ],
        )

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-pdata32-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "pd32.exe"
            exe.write_bytes(pe_bytes)
            create_win32_config(exe, pe_bytes)
            yaml_txt = (tmpdir / "pd32.exe.yaml").read_text()
            self.assertNotIn(", pdata,", yaml_txt)
            self.assertIn(", rodata,", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigMsvcAutoDetectTest(unittest.TestCase):
    def test_linker_major_picks_matching_compiler_tag(self):
        """The PE optional header's MajorLinkerVersion identifies which
        MSVC linker produced the binary. The generated YAML's `compiler:`
        line should reflect that so consumers don't have to override."""
        # Force linker_major = 14 (MSVC14, VS 2015-2022).
        size_of_opt = 0xE0
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            size_of_opt,
            0x010F,
        )
        opt = bytearray(_opt_header_pe32(entry_rva=0x1000))
        # MajorLinkerVersion at offset 2, MinorLinkerVersion at 3.
        struct.pack_into("<BB", opt, 2, 14, 30)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt) + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-msvc-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "vs2019.exe"
            exe.write_bytes(bytes(buf))
            create_win32_config(exe, bytes(buf))
            yaml_txt = (tmpdir / "vs2019.exe.yaml").read_text()
            self.assertIn("compiler: MSVC14", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_unknown_linker_major_falls_back_to_msvc6(self):
        """A binary whose linker version isn't in the lookup table (e.g.
        a custom packer's value) should still produce a valid splat
        config — default to MSVC6 since it's the lowest registered."""
        size_of_opt = 0xE0
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            size_of_opt,
            0x010F,
        )
        opt = bytearray(_opt_header_pe32(entry_rva=0x1000))
        struct.pack_into("<BB", opt, 2, 99, 0)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt) + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-msvc-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            exe = tmpdir / "weird.exe"
            exe.write_bytes(bytes(buf))
            create_win32_config(exe, bytes(buf))
            yaml_txt = (tmpdir / "weird.exe.yaml").read_text()
            self.assertIn("compiler: MSVC6", yaml_txt)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigPathologicalBasenameTest(unittest.TestCase):
    def test_empty_basename_after_sanitization_falls_back(self):
        """A filename composed entirely of characters that
        remove_invalid_path_characters strips would otherwise produce a
        bare '.yaml' / '.ld' output. Fall back to a synthetic basename."""
        # Build a minimal PE.
        size_of_opt = 0xE0
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            size_of_opt,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-empty-"))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            # All-spaces filename — `basename.replace(" ", "")` returns ''
            # (Path treats the path as a child of tmpdir even when the
            # name is whitespace).
            sp_path = tmpdir / "  "
            sp_path.write_bytes(bytes(buf))
            create_win32_config(sp_path, bytes(buf))
            # Synthetic fallback basename used since cleaned_basename = ''.
            self.assertTrue((tmpdir / "pe_target.yaml").exists())
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class CreateConfigYamlQuotedPathTest(unittest.TestCase):
    def test_target_path_with_spaces_is_quoted_in_yaml(self):
        """A binary located at a path with spaces (or colons / hashes —
        all YAML-significant unquoted) must not corrupt the generated
        splat YAML. The header writes `target_path` as a quoted string."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        body = b"\x00" * 0x10
        size_of_opt = 0xE0
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            2,
            0x12345678,
            0,
            0,
            size_of_opt,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        sec1 = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        sec2 = _section_header(
            b".rdata", 0x10, rdata_rva, FILE_ALIGN, rdata_rptr, 0x40000040
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec1 + sec2
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN + body.ljust(FILE_ALIGN, b"\x00")

        import os
        import tempfile
        import shutil
        from src.splat.scripts.create_config import create_win32_config
        from pathlib import Path as _P
        import yaml

        tmpdir = _P(tempfile.mkdtemp(prefix="splat-create-spaces "))
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            sp_path = tmpdir / "exe with spaces.dll"
            sp_path.write_bytes(bytes(buf))
            create_win32_config(sp_path, bytes(buf))
            yaml_path = tmpdir / "exewithspaces.dll.yaml"
            text = yaml_path.read_text()
            # Quoted: surrounded by double quotes.
            self.assertRegex(text, r'target_path:\s*"[^"]+exe with spaces\.dll"')
            # And the YAML must still parse cleanly.
            doc = yaml.safe_load(text)
            self.assertIn("exe with spaces.dll", doc["options"]["target_path"])
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class Win32DecodeFlagsLeftoverTest(unittest.TestCase):
    def test_unknown_bits_surface_in_decoded_flags(self):
        """When a binary sets a Characteristics or DllCharacteristics
        bit that isn't in our static lookup table, the decoder must
        surface it rather than dropping it silently (which would hide
        a feature flag the analyst needs to know about)."""
        from src.splat.segtypes.win32.header import _decode_flags

        table = [
            (0x0001, "EXECUTABLE_IMAGE"),
            (0x2000, "DLL"),
        ]
        # Mixed: one known bit + one unknown bit (0x4000).
        decoded = _decode_flags(0x6001, table)
        self.assertIn("EXECUTABLE_IMAGE", decoded)
        self.assertIn("DLL", decoded)
        self.assertIn("unknown 0x4000", decoded)

    def test_no_leftover_when_all_bits_known(self):
        from src.splat.segtypes.win32.header import _decode_flags

        table = [(0x0001, "A"), (0x0002, "B")]
        self.assertEqual(_decode_flags(0x0003, table), "A | B")

    def test_none_when_value_is_zero(self):
        from src.splat.segtypes.win32.header import _decode_flags

        table = [(0x0001, "A")]
        self.assertEqual(_decode_flags(0, table), "(none)")


class Win32HeaderTruncatedOptionalHeaderTest(unittest.TestCase):
    def test_truncated_optional_header_falls_back_to_byte_block(self):
        """A malformed PE with SizeOfOptionalHeader smaller than the
        standard 0xE0 layout used to emit zero-width
        `.short ''`/`.long ''` directives that GAS rejects.
        After truncation is detected the remainder is dumped as a raw
        byte block once — subsequent emit_* calls return silently."""
        from src.splat.segtypes.win32.header import Win32SegHeader

        # Declare a runt optional header — fits Magic + linker bytes +
        # SizeOfCode + SizeOfInitData (16 bytes total), then truncated
        # mid-SizeOfUninitData. The bounds check fires there.
        size_of_opt = 0x10
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            size_of_opt,
            0x010F,
        )
        opt_runt = bytearray(size_of_opt)
        opt_runt[0:2] = struct.pack("<H", 0x010B)  # Magic = PE32
        opt_runt[2] = 6  # MajorLinkerVersion
        # Fields past offset 4 are unspecified zeros — that's the runt.
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt_runt) + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN

        seg = object.__new__(Win32SegHeader)
        # opt_off = DOS(0x40) + PE\0\0(4) + COFF(0x14) = 0x58
        opt_off = 0x40 + 4 + 0x14
        opt_end = opt_off + size_of_opt
        lines = seg._dump_optional_header(bytes(buf), opt_off, opt_end)
        # No empty `.short`/`.long` directives.
        for ln in lines:
            self.assertNotRegex(ln, r'\.(short|long|quad)\s+""\s*$')
        # Truncation must short-circuit subsequent emits — fields past
        # SizeOfUninitializedData (i.e. AddressOfEntryPoint onward)
        # should NOT appear in output.
        joined = "\n".join(lines)
        self.assertNotIn("AddressOfEntryPoint", joined)
        self.assertNotIn("ImageBase", joined)


class Win32HeaderDataDirCountCapTest(unittest.TestCase):
    def test_oversize_num_dirs_in_header_dump_is_capped(self):
        """The structured header dump iterates NumberOfRvaAndSizes
        directory entries. A fuzzed value (e.g. 0xFFFFFFFF) must not
        trigger a 4-billion-iteration loop in `_dump_optional_header`.
        Real iteration is bounded by both the declared count cap (256)
        and the per-iteration opt_end check."""
        from src.splat.segtypes.win32.header import Win32SegHeader

        # Minimal PE32 buffer where SizeOfOptionalHeader covers exactly
        # the standard header + 16 data directories. Force NumberOfRvaAndSizes
        # to 0xFFFFFFFF.
        size_of_opt = 0xE0
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            size_of_opt,
            0x010F,
        )
        opt = bytearray(_opt_header_pe32(entry_rva=0x1000))
        # NumberOfRvaAndSizes field at offset 92.
        struct.pack_into("<I", opt, 92, 0xFFFFFFFF)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt) + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN

        seg = object.__new__(Win32SegHeader)
        opt_off = 0x40 + 4 + 0x14  # DOS+PE+sig+COFF header
        opt_end = opt_off + size_of_opt
        # No exception, no infinite loop. Returns within milliseconds.
        lines = seg._dump_optional_header(bytes(buf), opt_off, opt_end)
        # Should have emitted at most opt_end // 8 directory entries,
        # well below 256, and definitely below 4 billion.
        self.assertLess(len(lines), 256)


class Win32HeaderWidthTest(unittest.TestCase):
    def test_pe32_plus_imagebase_padded_to_16_hex(self):
        """For PE32+ the ImageBase is 64-bit (e.g. 0x140000000 — 9 hex
        digits). The header summary should pad to 16 hex digits so VAs
        line up consistently with EntryPoint and section VA columns."""
        from src.splat.segtypes.win32.header import Win32SegHeader
        from src.splat.platforms import win32 as win32_platform

        old_info = win32_platform.info
        try:
            pe = win32_platform.PEInfo(
                is_pe32_plus=True,
                image_base=0x140000000,
                entry_point_rva=0x1000,
                machine=0x8664,
                subsystem=3,
            )
            win32_platform.info = pe
            seg = object.__new__(Win32SegHeader)
            lines = seg._summary_block(pe)
            block = "\n".join(lines)
            self.assertIn("0x0000000140000000", block)
            self.assertIn("0x0000000140001000", block)
        finally:
            win32_platform.info = old_info

    def test_pe32_imagebase_padded_to_8_hex(self):
        """PE32 keeps the legacy 8-digit width since ImageBase fits in 32
        bits — verifies we didn't regress the common case while adding
        PE32+ support."""
        from src.splat.segtypes.win32.header import Win32SegHeader
        from src.splat.platforms import win32 as win32_platform

        old_info = win32_platform.info
        try:
            pe = win32_platform.PEInfo(
                is_pe32_plus=False,
                image_base=0x00400000,
                entry_point_rva=0x1000,
                machine=0x014C,
                subsystem=3,
            )
            win32_platform.info = pe
            seg = object.__new__(Win32SegHeader)
            lines = seg._summary_block(pe)
            block = "\n".join(lines)
            self.assertIn("0x00400000", block)
            self.assertIn("0x00401000", block)
            self.assertNotIn("0x0000000000400000", block)
        finally:
            win32_platform.info = old_info


class CapstoneDisassemblerTest(unittest.TestCase):
    def test_known_types_includes_primitive_set(self):
        """CapstoneDisassembler.known_types returns the spimdisasm-mirror
        primitive vocabulary so symbol_addrs.txt `type:u32` /
        `type:asciz` entries get accepted by splat's check_valid_type."""
        from src.splat.disassembler.capstone_disassembler import (
            CapstoneDisassembler,
        )

        d = CapstoneDisassembler()
        kt = d.known_types()
        for t in ("u8", "u32", "s32", "f32", "char", "asciz"):
            self.assertIn(t, kt)

    def test_engine_lazy_creation_uses_pe_bitness(self):
        """get_engine() picks CS_MODE_32 / CS_MODE_64 from the parsed
        PE's is_pe32_plus flag — checks deferred-init path."""
        import capstone
        from src.splat.disassembler.capstone_disassembler import (
            CapstoneDisassembler,
        )

        d = CapstoneDisassembler()

        # Save / restore the global PE info so we don't bleed state.
        old_info = win32_platform.info
        try:
            # PE32 — should get 32-bit mode.
            win32_platform.info = win32_platform.PEInfo(is_pe32_plus=False)
            d._md = None  # force recreation
            md = d.get_engine()
            self.assertEqual(md.mode, capstone.CS_MODE_32)

            # PE32+ — should get 64-bit mode.
            win32_platform.info = win32_platform.PEInfo(is_pe32_plus=True)
            d._md = None
            md = d.get_engine()
            self.assertEqual(md.mode, capstone.CS_MODE_64)
        finally:
            win32_platform.info = old_info


class Win32SubsystemNamesTest(unittest.TestCase):
    def test_subsystem_table_coverage(self):
        """Subsystem ID → name mapping must cover the common values
        emitted by Windows linkers."""
        from src.splat.segtypes.win32.header import _SUBSYSTEMS

        expected = {
            1: "NATIVE",
            2: "WINDOWS_GUI",
            3: "WINDOWS_CUI",
            5: "OS2_CUI",
            7: "POSIX_CUI",
            10: "EFI_APPLICATION",
            14: "XBOX",
        }
        for sid, name in expected.items():
            self.assertEqual(_SUBSYSTEMS.get(sid), name, f"Subsystem {sid}")


class Win32ResourceTypeNamesTest(unittest.TestCase):
    def test_standard_resource_type_names(self):
        """RESOURCE_TYPE_NAMES covers all standard Win32 resource IDs
        (winuser.h RT_*) so the header summary renders them by name
        instead of as `TYPE_<n>`."""
        from src.splat.platforms.win32 import RESOURCE_TYPE_NAMES

        # Spot-check a representative slice from the standard set.
        expected = {
            1: "CURSOR",
            2: "BITMAP",
            3: "ICON",
            4: "MENU",
            5: "DIALOG",
            6: "STRING",
            14: "GROUP_ICON",
            16: "VERSION",
            24: "MANIFEST",
        }
        for rid, name in expected.items():
            self.assertEqual(RESOURCE_TYPE_NAMES.get(rid), name, f"RT id {rid}")


class Win32LinkerVersionTest(unittest.TestCase):
    def test_linker_version_label_known_majors(self):
        """linker_version_label maps each MSVC major version to a
        recognizable product name; unknown majors fall back to a
        plain `linker vN.NN` rendering."""
        from src.splat.platforms.win32 import linker_version_label

        self.assertEqual(linker_version_label(6, 0), "MSVC 6.0")
        self.assertEqual(linker_version_label(14, 34), "MSVC 14.x / VS 2015-2022")
        self.assertEqual(linker_version_label(99, 5), "linker v99.05")


class Win32SegHeaderUtilsTest(unittest.TestCase):
    """Targeted tests for the small helpers in header.py — these wrap
    `_decode_flags` and the Subsystem table."""

    def test_decode_characteristics_flags(self):
        from src.splat.segtypes.win32.header import (
            _decode_flags,
            _FILE_CHARACTERISTICS,
            _DLL_CHARACTERISTICS,
        )

        self.assertEqual(_decode_flags(0, _FILE_CHARACTERISTICS), "(none)")
        # DLL | EXECUTABLE_IMAGE | 32BIT_MACHINE
        out = _decode_flags(0x2102, _FILE_CHARACTERISTICS)
        self.assertIn("EXECUTABLE_IMAGE", out)
        self.assertIn("32BIT_MACHINE", out)
        self.assertIn("DLL", out)
        # DllCharacteristics
        out = _decode_flags(0x0140, _DLL_CHARACTERISTICS)
        self.assertIn("DYNAMIC_BASE", out)
        self.assertIn("NX_COMPAT", out)


class PEEdgeCasesTest(unittest.TestCase):
    """Defensive parse tests for malformed inputs and unusual but valid PEs."""

    def test_read_cstr_truncation(self):
        """Strings with no NUL terminator get capped at _MAX_CSTR_LEN."""
        big_blob = b"A" * (win32_platform._MAX_CSTR_LEN + 100)
        result = win32_platform._read_cstr(big_blob, 0)
        self.assertEqual(len(result), win32_platform._MAX_CSTR_LEN)

    def test_read_cstr_past_end(self):
        """Out-of-bounds offsets return an empty string, not a crash."""
        self.assertEqual(win32_platform._read_cstr(b"", 0), "")
        self.assertEqual(win32_platform._read_cstr(b"ABC", 99), "")
        self.assertEqual(win32_platform._read_cstr(b"ABC", -1), "")

    def test_resolve_va_to_file_offset_out_of_range(self):
        """VA outside any section returns None."""
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        # VA way outside the loaded image.
        self.assertIsNone(pe.va_to_file_offset(0x7FFFFFFF))
        self.assertIsNone(pe.rva_to_file_offset(0x7FFFFFFF))

    def test_truncated_dos_header(self):
        """File shorter than the 64-byte DOS header must be rejected
        explicitly (not raise a struct.error in the parser)."""
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(b"MZ" + b"\x00" * 10)

    def test_generic_unsupported_machine_rejected(self):
        """Non-x86 / non-ARM machine codes (MIPS, PowerPC, Alpha, etc.)
        also hit the win32 init() rejection — generic message rather
        than the ARM-specific one."""
        # Machine = 0x0166 (R3000-LE) → not i386/amd64/arm64/arm32.
        coff = struct.pack(
            "<HHIIIHH",
            0x0166,
            1,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        blob = bytes(header).ljust(FILE_ALIGN * 2, b"\x00")
        # parse_pe still works (architecture-neutral).
        pe = win32_platform.parse_pe(blob)
        self.assertEqual(pe.machine, 0x0166)
        with self.assertRaises(SystemExit):
            win32_platform.init(blob)

    def test_arm64_machine_rejected_at_init(self):
        """ARM64 PE binaries parse cleanly through parse_pe (structures
        are architecture-neutral) but init() must reject them with an
        explicit message — the disassembler is x86-only."""
        # Hand-build a tiny PE32+ with Machine = 0xAA64 (ARM64).
        coff = struct.pack(
            "<HHIIIHH",
            0xAA64,
            1,
            0x12345678,
            0,
            0,
            0xF0,
            0x002F,
        )
        opt = _opt_header_pe32_plus(entry_rva=0x1000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        blob = bytes(header).ljust(FILE_ALIGN * 2, b"\x00")
        # parse_pe alone is OK — structures are arch-neutral.
        pe = win32_platform.parse_pe(blob)
        self.assertEqual(pe.machine, 0xAA64)
        # init() escalates to log.error → SystemExit because the
        # downstream x86 capstone backend can't disassemble ARM64.
        with self.assertRaises(SystemExit):
            win32_platform.init(blob)

    def test_section_table_truncated(self):
        """NumberOfSections * 40 must fit between the end of the optional
        header and EOF. Declaring 10 sections but only providing 2 must
        be caught explicitly."""
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            10,  # claim 10 sections
            0x12345678,
            0,
            0,
            0xE0,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        # Only enough space for 2 section headers — half of the declared.
        sec = b"\x00" * (40 * 2)
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        # Truncate so the remaining 8 sections can't fit.
        header = header[: 0x40 + 4 + 20 + 0xE0 + 40 * 2]
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(header)

    def test_zero_optional_header_size(self):
        """SizeOfOptionalHeader == 0 means there's no optional header
        at all (technically valid only for COFF object files, not PE
        images). Parser must reject before attempting to read the
        2-byte magic field."""
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            0,
            0x12345678,
            0,
            0,
            0,
            0x010F,
        )
        header = DOS_STUB + b"PE\x00\x00" + coff
        header = header.ljust(FILE_ALIGN, b"\x00")
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(bytes(header))

    def test_sub_minimum_optional_header_size(self):
        """Optional header smaller than the per-format minimum (96 for
        PE32, 112 for PE32+) can't fit the data-directory offsets we
        expect to read. Parser must reject."""
        # PE32 optional header but declared size 32 (less than the 96
        # required for windows-specific + data-directories).
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            0,
            0x12345678,
            0,
            0,
            32,
            0x010F,
        )
        # First 32 bytes of a PE32 optional header (just standard fields).
        opt = struct.pack(
            "<HBBIIIIIII",
            0x010B,
            6,
            0,
            0x200,
            0x200,
            0,
            0x1000,
            0x1000,
            0x2000,
            0x400000,
        )
        assert len(opt) == 32
        header = DOS_STUB + b"PE\x00\x00" + coff + opt
        header = header.ljust(FILE_ALIGN, b"\x00")
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(bytes(header))

    def test_unknown_optional_header_magic(self):
        """Optional header magic must be 0x10B (PE32) or 0x20B (PE32+).
        Older formats like ROM image (0x107) or future values must be
        rejected before we try to read PE32-specific offsets."""
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F,
        )
        # Build a valid-looking PE32 optional header then overwrite the
        # magic to 0x107 (ROM image, unsupported).
        opt = bytearray(_opt_header_pe32(entry_rva=0x1000))
        struct.pack_into("<H", opt, 0, 0x0107)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt) + sec
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(bytes(header).ljust(FILE_ALIGN * 2, b"\x00"))

    def test_truncated_after_pe_signature(self):
        """File large enough to hold MZ + e_lfanew + 'PE\\0\\0' but not
        the trailing 20-byte COFF file header must be rejected before
        struct.unpack_from would walk past EOF."""
        dos = bytearray(64)
        dos[0:2] = b"MZ"
        dos[0x3C:0x40] = struct.pack("<I", 0x40)
        # 'PE\0\0' present but only ~8 trailing bytes — not enough for the
        # 20-byte IMAGE_FILE_HEADER that follows.
        blob = bytes(dos) + b"PE\x00\x00" + b"\x00" * 8
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(blob)

    def test_pe32_plus_amd64_magic_combination_accepted(self):
        """AMD64 Machine + PE32+ Magic 0x20B must be accepted. Pairs
        with the mismatch test — confirms the cross-validation only
        rejects genuine mismatches, not all PE32+ pairings."""
        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.machine, 0x8664)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(pe.image_base, 0x140000000)

    def test_machine_magic_mismatch(self):
        """A PE file with i386 Machine but PE32+ optional header magic
        (or vice-versa) must be rejected — both fields encode pointer
        size and they must agree."""
        # i386 Machine + PE32+ magic.
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            0xF0,
            0x010F,
        )
        # PE32+ optional header (240 bytes) but Machine claims i386.
        opt = _opt_header_pe32_plus(entry_rva=0x1000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(bytes(header).ljust(FILE_ALIGN * 2, b"\x00"))

    def test_missing_pe_signature(self):
        """An MZ header pointing at non-PE bytes must be rejected."""
        # Valid DOS header pointing e_lfanew at 0x40, but the bytes there
        # are not "PE\0\0".
        dos = bytearray(64)
        dos[0:2] = b"MZ"
        dos[0x3C:0x40] = struct.pack("<I", 0x40)
        blob = bytes(dos) + b"NE\x00\x00" + b"\x00" * 100
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(blob)

    def test_coff_symbol_table_recorded(self):
        """PE binaries essentially never set PointerToSymbolTable
        + NumberOfSymbols (debug info goes in the external .pdb), but
        when they do, those fields surface on PEInfo for the header
        summary to flag."""
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0x12345,
            42,  # PointerToSymbolTable + NumberOfSymbols
            0xE0,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN
        pe = win32_platform.parse_pe(bytes(buf))
        self.assertEqual(pe.coff_symtab_ptr, 0x12345)
        self.assertEqual(pe.coff_num_symbols, 42)

    def test_zero_sections(self):
        """Synthetic PE with NumberOfSections=0 — parser should accept
        and downstream rva_to_file_offset should return None for any
        non-trivial RVA without crashing."""
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            0,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0, data_dirs=())
        header = DOS_STUB + b"PE\x00\x00" + coff + opt
        header = header.ljust(FILE_ALIGN, b"\x00")
        pe = win32_platform.parse_pe(bytes(header))
        self.assertEqual(pe.num_sections, 0)
        self.assertEqual(len(pe.sections), 0)
        self.assertIsNone(pe.rva_to_file_offset(0x1000))

    def test_no_entrypoint(self):
        """Resource-only DLL has entry_point_rva == 0."""
        # We need to override the standard `_build_pe` entry_rva=0x1000
        # default. Bypass by constructing fields directly.
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F | 0x2000,  # add DLL flag
        )
        opt = _opt_header_pe32(entry_rva=0, data_dirs=())
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN
        pe = win32_platform.parse_pe(bytes(buf))
        self.assertEqual(pe.entry_point_rva, 0)
        # Should not crash later when consumers check entry_point_va.

    def test_safeseh_count_capped(self):
        """Fuzzed LoadConfig with SEHandlerCount = 0xFFFFFFFF must not
        loop 4 billion times. Parser caps at 1M; loop body's per-entry
        bounds check then terminates early on EOF."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        seh_table_va = IMAGE_BASE + rdata_rva + 0x50
        lc_size = 0x48
        body = bytearray(0x100)
        struct.pack_into("<I", body, 0, lc_size)
        struct.pack_into("<I", body, 0x3C, IMAGE_BASE + rdata_rva + 0x60)
        struct.pack_into("<I", body, 0x40, seh_table_va)
        struct.pack_into("<I", body, 0x44, 0xFFFFFFFF)
        # Two real RVAs followed by garbage / unmapped territory.
        struct.pack_into("<II", body, 0x50, 0x1010, 0x1020)
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x100,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0)] * 10 + [(rdata_rva, lc_size)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        # Bounded reads stop once EOF is hit; we still cap iteration.
        self.assertLessEqual(len(pe.safe_seh_handlers), 1_000_000)
        # First two genuine RVAs survive.
        self.assertEqual(pe.safe_seh_handlers[:2], [0x1010, 0x1020])

    def test_export_count_capped(self):
        """Fuzzed export directory with NumberOfFunctions = 0xFFFFFFFF.
        Parser must cap iteration to a sane limit so it doesn't scan
        gigabytes of file looking for non-existent function RVAs."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        funcs_rva = rdata_rva + 0x28
        dll_name_rva = rdata_rva + 0x30
        body = bytearray(0x80)
        struct.pack_into(
            "<IIHHIIIIIII",
            body,
            0x00,
            0,
            0,
            0,
            0,
            dll_name_rva,
            1,
            0xFFFFFFFF,  # num funcs — absurd
            0,
            funcs_rva,
            0,
            0,
        )
        struct.pack_into("<I", body, 0x28, 0x1000)
        body[0x30 : 0x30 + 11] = b"FuzzDll\x00\x00\x00\x00"
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(rdata_rva, 0x80)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        # Cap = 65536. Loop exits early once funcs_off + i*4 + 4 > len(data).
        # Should not loop 4 billion times.
        self.assertLessEqual(len(pe.exports), 65536)

    def test_number_of_sections_capped_at_96(self):
        """PE spec caps NumberOfSections at 96. Parser must not iterate
        a fuzzed huge value (e.g. 0xFFFF) past the cap. Provide enough
        bytes for the cap (96 * 40 = 3840) but declare 0xFFFF sections."""
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            0xFFFF,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        # Exactly 96 zeroed section headers — enough to hit the cap
        # without going past EOF.
        sec = b"\x00" * (40 * 96)
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        pe = win32_platform.parse_pe(bytes(header))
        # Capped at 96 even though field claimed 65535.
        self.assertEqual(len(pe.sections), 96)
        self.assertEqual(pe.num_sections, 0xFFFF)  # raw field preserved

    def test_small_image_base(self):
        """Some embedded/specialty PEs use a tiny ImageBase (e.g. 0x10000
        for early drivers) instead of the standard 0x400000. Parser must
        not assume any specific value, and entry_point_va must compose
        correctly."""
        # Standard PE32 with ImageBase overridden to 0x10000.
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            0xE0,
            0x010F,
        )
        opt = bytearray(_opt_header_pe32(entry_rva=0x1000))
        # ImageBase field is at offset 28 in PE32 optional header.
        struct.pack_into("<I", opt, 28, 0x10000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt) + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN
        pe = win32_platform.parse_pe(bytes(buf))
        self.assertEqual(pe.image_base, 0x10000)
        self.assertEqual(pe.entry_point_va, 0x11000)  # base + entry RVA

    def test_excessive_data_directory_count_capped(self):
        """Some malformed/fuzzed PEs declare NumberOfRvaAndSizes far
        beyond the canonical 16. Parser must cap iteration at 16 rather
        than walking past the optional header into section territory."""
        # Standard PE32 optional header (96 bytes) plus 16 data dir
        # slots — total 224 = 0xE0 — but NumberOfRvaAndSizes claims 9999.
        size_of_opt = 0xE0
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            size_of_opt,
            0x010F,
        )
        opt = bytearray(_opt_header_pe32(entry_rva=0x1000))
        # NumberOfRvaAndSizes is the LAST DWORD before the data
        # directory array — at offset 92 within the optional header.
        struct.pack_into("<I", opt, 92, 9999)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt) + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN
        pe = win32_platform.parse_pe(bytes(buf))
        # Iteration capped at 16 even though field says 9999.
        self.assertEqual(len(pe.data_directories), 16)

    def test_sparse_data_directory_count(self):
        """An optional header can declare NumberOfRvaAndSizes < 16
        (rare, older MSVC). Parser should walk only the declared count
        and leave higher-index lookups defensive."""
        # We construct an optional header by hand with NumberOfRvaAndSizes=2
        # — only Export + Import slots are real; the parser must not try
        # to read Resource / Exception / etc.
        size_of_opt_hdr = 96 + 16  # standard PE32 fields + 2 data dirs
        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0x12345678,
            0,
            0,
            size_of_opt_hdr,
            0x010F,
        )
        # Standard fields (28) + windows (68) — last field is
        # NumberOfRvaAndSizes which we set to 2.
        opt = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x010B,
            6,
            0,
            0x200,
            0x200,
            0,
            0x1000,
            0x1000,
            0x2000,
            0x400000,
            0x1000,
            0x200,
            4,
            0,
            0,
            0,
            4,
            0,
            0,
            0x4000,
            0x200,
            0,
            3,
            0,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            2,  # NumberOfRvaAndSizes = 2
        )
        # Just two directory entries (Export + Import, both empty).
        opt += struct.pack("<IIII", 0, 0, 0, 0)
        assert len(opt) == size_of_opt_hdr, (len(opt), size_of_opt_hdr)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN
        pe = win32_platform.parse_pe(bytes(buf))
        # Only 2 data directories populated.
        self.assertEqual(len(pe.data_directories), 2)
        # All sub-parsers that need higher indices should no-op.
        self.assertFalse(pe.resources)
        self.assertFalse(pe.runtime_functions)
        self.assertFalse(pe.safe_seh_handlers)
        self.assertFalse(pe.cfg_function_rvas)
        self.assertFalse(pe.bound_imports)
        self.assertFalse(pe.delay_imports)

    def test_empty_data_directory_index(self):
        """Optional header listing fewer than 16 data dirs still parses."""
        # _build_pe always provides space for 16 entries; pass only one
        # (zeros) and verify the others come out empty.
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
            ],
            data_dirs=[(0, 0)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertFalse(pe.exports)
        self.assertFalse(pe.imports)
        self.assertFalse(pe.resources)
        self.assertFalse(pe.runtime_functions)


if __name__ == "__main__":
    unittest.main()
