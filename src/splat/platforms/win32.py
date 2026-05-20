"""Win32 PE platform support.

Parses the PE/COFF header of the target binary at `init()` time and exposes
the result via module-level globals that win32 segtypes can consult.

The parser intentionally implements only what splat needs (DOS stub, file
header, optional header, section table). It accepts both PE32 (i386, what
MSVC6 emits) and PE32+ (x86_64) optional headers but the rest of the win32
support is geared at PE32 / i386.
"""

from dataclasses import dataclass, field
import struct
from typing import Dict, List, Optional, Set, Tuple

from ..util import log


DOS_MAGIC = b"MZ"
PE_MAGIC = b"PE\x00\x00"

MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664
MACHINE_ARM32 = 0x01C4  # ARMv7 Thumb-2 (Windows on ARM 32-bit)
MACHINE_ARM64 = 0xAA64  # AArch64 (Windows on ARM 64-bit)

# IMAGE_OPTIONAL_HEADER.Magic — identifies which optional-header
# layout follows (PE32 has 32-bit fields for ImageBase etc., PE32+
# has 64-bit equivalents).
OPT_MAGIC_PE32 = 0x10B
OPT_MAGIC_PE32_PLUS = 0x20B

# IMAGE_DIRECTORY_ENTRY_* indices into pe.data_directories.
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_EXCEPTION = 3
DIR_CERTIFICATE = 4
DIR_BASERELOC = 5
DIR_DEBUG = 6
DIR_ARCHITECTURE = 7
DIR_GLOBALPTR = 8
DIR_TLS = 9
DIR_LOAD_CONFIG = 10
DIR_BOUND_IMPORT = 11
DIR_IAT = 12
DIR_DELAY_IMPORT = 13
DIR_COM_DESCRIPTOR = 14

# Section header flags (IMAGE_SCN_*)
SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED_DATA = 0x00000040
SCN_CNT_UNINITIALIZED_DATA = 0x00000080
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000
SCN_MEM_EXECUTE = 0x20000000


@dataclass
class PESection:
    """One IMAGE_SECTION_HEADER entry from the PE section table.

    `virtual_address` is the section's RVA — its load-time location
    relative to ImageBase. `raw_pointer` is the on-disk offset. The
    section spans [virtual_address, virtual_address + virtual_size)
    in memory and [raw_pointer, raw_pointer + raw_size) in the file;
    when virtual_size > raw_size the loader zero-fills the tail."""

    name: str
    virtual_size: int
    virtual_address: int  # RVA
    raw_size: int
    raw_pointer: int  # file offset
    characteristics: int

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & (SCN_CNT_CODE | SCN_MEM_EXECUTE))

    @property
    def is_bss(self) -> bool:
        return bool(self.characteristics & SCN_CNT_UNINITIALIZED_DATA)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_WRITE)

    @property
    def is_readonly_data(self) -> bool:
        return (
            bool(self.characteristics & SCN_CNT_INITIALIZED_DATA)
            and not self.is_writable
            and not self.is_code
        )


@dataclass
class PEExport:
    """One entry in the export table (data dir 0).

    `name` is None for ordinal-only exports (the DLL exposes the
    function by number rather than symbolic name). `rva` is the
    in-image RVA the export points at — UNLESS `forwarder` is set,
    in which case the export forwards to another DLL and rva is
    interpreted by the loader as a pointer to the forwarder string."""

    name: Optional[str]
    ordinal: int
    rva: int
    forwarder: Optional[str] = None


@dataclass
class PEImport:
    """One imported symbol — either eager (data dir 1, IMAGE_IMPORT_*)
    or delay-loaded (data dir 13, IMAGE_DELAYLOAD_*).

    `dll` is the import source's DLL filename. Exactly one of `name`
    or `ordinal` is set: `name` for the typical hint/name import,
    `ordinal` (`name` is None) when the import is by ordinal index.
    `iat_rva` is the in-image RVA of the IAT slot the loader writes
    the resolved function pointer into — call sites read through it
    via `call qword ptr [<iat_va>]` style indirect calls."""

    dll: str
    name: Optional[str]
    ordinal: Optional[int]
    iat_rva: int


@dataclass
class PEBoundImport:
    """IMAGE_BOUND_IMPORT_DESCRIPTOR entry.

    `timestamp` is the DLL build timestamp the binary was bound against;
    `forwarder_refs` are 0-N additional DLLs the bound-import chain
    transitively pre-resolved through."""

    dll: str
    timestamp: int
    forwarder_refs: List[str] = field(default_factory=list)


@dataclass
class CLRHeader:
    """Decoded IMAGE_COR20_HEADER (data dir 14 — `.NET CLR Runtime
    Header`). Identifies the binary as a .NET assembly and points at
    the CLR metadata + entry-point token.

    Splat doesn't decode the metadata tables themselves (would need
    the full ECMA-335 reader); this just surfaces the header fields
    so the analyst sees the assembly is .NET-native and can fetch
    the metadata blob from its RVA."""

    cb_size: int  # always 72
    runtime_major: int
    runtime_minor: int
    metadata_rva: int
    metadata_size: int
    flags: int
    entry_point_token_or_rva: int
    resources_rva: int
    resources_size: int
    strong_name_signature_rva: int
    strong_name_signature_size: int


@dataclass
class UnwindInfo:
    """Decoded x64 SEH IMAGE_UNWIND_INFO record (PE32+ only).

    `prolog_size` is the number of bytes the prologue occupies; codes
    are a flattened list of `(offset_in_prolog, op_name, info_nibble)`
    triples describing the prolog ops the unwinder will replay. The
    `chained_function_rva` is set when the chain-info flag is on and
    a subsequent RUNTIME_FUNCTION's begin/end/unwind triple follows
    the codes."""

    version: int
    flags: int
    prolog_size: int
    frame_register: int  # 0 = none; otherwise the x86_64 register index
    frame_register_offset: int  # nibble × 16
    codes: List[Tuple[int, str, int]] = field(default_factory=list)
    chained_function_rva: Optional[int] = None


@dataclass
class COFFSymbol:
    """One IMAGE_SYMBOL record (18 bytes) from the deprecated COFF
    symbol table that vintage MSVC linkers wrote past the last raw
    section. Modern toolchains rely on .pdb instead and leave the
    optional header's PointerToSymbolTable zero, so this list is
    typically empty on Windows 7+ era binaries."""

    name: str
    value: int  # VA or RVA depending on storage class
    section_number: int  # 1-based, 0 = undefined, -1 = absolute, -2 = debug
    sym_type: int  # combined base + complex type
    storage_class: int
    aux_records: int  # number of trailing IMAGE_AUX_SYMBOL entries


@dataclass
class PEResource:
    """One leaf in the .rsrc tree.

    `rtype` is the resource-type ID (or a UTF-16 name for custom types).
    `rid` is the per-type identifier or name. `language` is the locale id.
    `rva` / `size` point at the resource's raw bytes inside the image.
    """

    rtype: object  # int (standard) or str (custom-named type)
    rid: object  # int or str
    language: int
    rva: int
    size: int


@dataclass
class PEInfo:
    """Result of parsing a Win32 PE32 / PE32+ image.

    Carries every field splat needs from the DOS stub, COFF file
    header, optional header, section table, and all 16 data
    directories. Populated by `parse_pe(target_bytes)` and exposed
    via the module-level `info` global so segtypes and the
    disassembler can consult it without threading it through every
    call. Empty / zero defaults mean 'directory not present' — there
    is no separate Optional[List] for directory-derived fields."""

    machine: int = 0
    num_sections: int = 0
    timestamp: int = 0
    characteristics: int = 0

    is_pe32_plus: bool = False
    image_base: int = 0
    entry_point_rva: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    subsystem: int = 0
    dll_characteristics: int = 0
    size_of_stack_reserve: int = 0
    size_of_stack_commit: int = 0
    size_of_heap_reserve: int = 0
    size_of_heap_commit: int = 0
    linker_major: int = 0
    linker_minor: int = 0

    pe_header_offset: int = 0
    sections: List[PESection] = field(default_factory=list)

    # 16 (rva, size) entries from the optional header. Populated only when
    # NumberOfRvaAndSizes is large enough.
    data_directories: List[Tuple[int, int]] = field(default_factory=list)
    exports: List[PEExport] = field(default_factory=list)
    export_dll_name: Optional[str] = None
    imports: List[PEImport] = field(default_factory=list)
    bound_imports: List[PEBoundImport] = field(default_factory=list)
    delay_imports: List[PEImport] = field(default_factory=list)
    # PE32+ / ARM: array of (begin_rva, end_rva, unwind_rva) describing
    # function bounds for SEH unwinding. Empty for PE32.
    runtime_functions: List[Tuple[int, int, int]] = field(default_factory=list)
    # /GS security cookie VA (data dir 10 → IMAGE_LOAD_CONFIG_DIRECTORY).
    security_cookie_va: int = 0
    # /SAFESEH handler RVAs (PE32 only).
    safe_seh_handlers: List[int] = field(default_factory=list)
    # /guard:cf — array of valid indirect-call target RVAs.
    cfg_function_rvas: List[int] = field(default_factory=list)
    cfg_flags: int = 0
    # RVAs the loader's base-relocation logic identifies as absolute
    # pointers (HIGHLOW for PE32, DIR64 for PE32+). Useful for emitting
    # data-section .long/.quad entries with symbolic targets.
    pointer_rvas: Set[int] = field(default_factory=set)
    # Deprecated COFF symbol table at the end of the file (PE binaries
    # essentially never have these populated — debug info lives in the
    # external .pdb instead — but a non-zero value is informative.)
    coff_symtab_ptr: int = 0
    coff_num_symbols: int = 0
    # Parsed IMAGE_SYMBOL records when coff_symtab_ptr/coff_num_symbols
    # are non-zero. Empty on modern PEs.
    coff_symbols: List["COFFSymbol"] = field(default_factory=list)
    # PDB filename embedded in the Debug directory's CodeView record, when
    # present.
    pdb_path: Optional[str] = None
    # GUID (RSDS) or 32-bit signature (NB10) identifying the matching PDB.
    pdb_guid: Optional[str] = None
    # Build age — incremented every time the PDB is updated.
    pdb_age: Optional[int] = None
    # TLS callback VAs gathered from data directory 9.
    tls_callback_vas: List[int] = field(default_factory=list)
    # Decoded IMAGE_UNWIND_INFO records, keyed by unwind RVA.
    # PE32+ only; remains empty for PE32 binaries.
    unwind_info: Dict[int, UnwindInfo] = field(default_factory=dict)
    # Decoded IMAGE_COR20_HEADER when data dir 14 is populated (.NET).
    clr_header: Optional[CLRHeader] = None
    # Resources enumerated from data directory 2 (.rsrc).
    resources: List[PEResource] = field(default_factory=list)
    # Decoded VS_VERSIONINFO key/value pairs (CompanyName, FileVersion,
    # ProductName, OriginalFilename, etc.).
    version_info: dict = field(default_factory=dict)

    @property
    def entry_point_va(self) -> int:
        return self.image_base + self.entry_point_rva

    def section_by_name(self, name: str) -> Optional[PESection]:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def rva_to_file_offset(self, rva: int) -> Optional[int]:
        """Translate an RVA to its on-disk file offset, or None when
        the RVA isn't backed by file bytes — either because it falls
        outside every section's virtual range or because it sits in
        the virtual-only tail of a section whose VirtualSize exceeds
        SizeOfRawData (loader zero-fills that range; no file bytes
        back it). Callers must handle None to avoid reading into a
        neighbouring section's data."""
        for s in self.sections:
            sec_end = s.virtual_address + max(s.virtual_size, s.raw_size)
            if not (s.virtual_address <= rva < sec_end):
                continue
            # In a section whose VirtualSize > SizeOfRawData (MSVC zero-init
            # tail or read-only constants past the file boundary), RVAs
            # within the trailing virtual-only range have NO backing
            # bytes — the loader zero-fills them at map time. Returning
            # raw_pointer + offset for those RVAs would land in the
            # next section's raw bytes. Reject instead.
            offset_in_section = rva - s.virtual_address
            if offset_in_section >= s.raw_size:
                return None
            return s.raw_pointer + offset_in_section
        return None

    def va_to_file_offset(self, va: int) -> Optional[int]:
        """Translate an image-base-relative virtual address to a file
        offset. Convenience wrapper that subtracts `image_base` and
        delegates to `rva_to_file_offset`; same None semantics."""
        return self.rva_to_file_offset(va - self.image_base)


# Populated by `init`, consulted by segtypes/disassembler.
info: PEInfo = PEInfo()
# Full file bytes — kept on the side so heuristics in segtypes can peek
# at arbitrary section content (e.g. validate a candidate function start
# byte) without threading rom_bytes through every call.
raw_image: bytes = b""


def resolve_exact_encoding(
    yaml: object, parent: "Optional[object]", default: bool = False
) -> bool:
    """Shared `exact_encoding` flag resolution used by Win32SegText /
    Win32SegData / Win32SegPdata. Priority order matches what users
    expect: per-subsegment YAML setting wins; if absent, fall back to
    the parent code-group YAML; finally fall back to `default`. The
    flag toggles label-substitution off so emitted bytes match the
    original file verbatim (needed for byte-identical reassembly)."""
    if isinstance(yaml, dict):
        v = yaml.get("exact_encoding")
        if v is not None:
            return bool(v)
    if parent is not None:
        parent_yaml = getattr(parent, "yaml", None)
        if isinstance(parent_yaml, dict):
            v = parent_yaml.get("exact_encoding")
            if v is not None:
                return bool(v)
    return default


def sanitize_label(s: str) -> str:
    """Canonical GAS-label sanitization shared by every site that emits
    labels derived from PE strings. Non-alphanumeric chars become '_';
    leading-digit identifiers (GAS-invalid) are prefixed with '_'."""
    out = "".join(c if c.isalnum() or c == "_" else "_" for c in s)
    if out and out[0].isdigit():
        out = "_" + out
    return out


def compute_iat_labels(pe: PEInfo) -> Dict[int, str]:
    """Return a {slot_va: label} mapping for every IAT (eager + delay)
    slot. Labels match what `create_win32_config` writes to
    symbol_addrs.txt — including dedup-on-collision behaviour — so
    disassembly references resolve to the same identifiers."""
    out: Dict[int, str] = {}

    def populate(items: List[PEImport], prefix: str) -> None:
        seen: Set[str] = set()
        for imp in items:
            slot_va = pe.image_base + imp.iat_rva
            nm = imp.name or f"ordinal_{imp.ordinal}"
            safe = sanitize_label(nm)
            # Empty DLL stem after sanitisation (corrupted descriptor
            # with missing name) — substitute a recognisable
            # placeholder so the label doesn't collapse to `imp__foo`
            # for every unknown-DLL import.
            dll_safe = sanitize_label(imp.dll) or "unknown"
            full = f"{prefix}_{dll_safe}_{safe}"
            if full in seen:
                full = f"{full}__rva{imp.iat_rva:X}"
            seen.add(full)
            out[slot_va] = full

    populate(pe.imports, "imp")
    populate(pe.delay_imports, "dimp")
    return out


def compute_export_labels(
    pe: PEInfo, reserved: Optional[Set[str]] = None
) -> Dict[int, str]:
    """Return a {export_va: label} mapping for every non-forwarder
    export. `reserved` is a pre-seeded set of labels already in use
    (e.g. {'entrypoint'}); colliding exports get an ordinal suffix.
    Matches create_win32_config's symbol_addrs emission."""
    out: Dict[int, str] = {}
    seen: Set[str] = set(reserved or set())
    for exp in pe.exports:
        if exp.forwarder is not None:
            continue
        nm = exp.name or f"export_{exp.ordinal}"
        safe = sanitize_label(nm)
        if safe in seen:
            safe = f"{safe}__ord{exp.ordinal}"
        seen.add(safe)
        out[pe.image_base + exp.rva] = safe
    return out


def parse_pe(data: bytes) -> PEInfo:
    """Parse `data` as a Win32 PE32 or PE32+ image and return a populated
    `PEInfo`. Walks the DOS stub, COFF file header, optional header, and
    every populated data directory:

      0  Export Table          → `exports`, `export_dll_name`
      1  Import Table          → `imports` (+ IAT slot RVAs)
      2  Resource Table        → `resources`, `version_info`
      3  Exception Table       → `runtime_functions` + `unwind_info`
      5  Base Relocation Table → `pointer_rvas`
      6  Debug                 → `pdb_path`, `pdb_guid`, `pdb_age`
      9  TLS Table             → `tls_callback_vas`
      10 Load Config           → `security_cookie_va`, `safe_seh_handlers`,
                                 `cfg_function_rvas`, `cfg_flags`
      11 Bound Import          → `bound_imports`
      13 Delay Import          → `delay_imports`
      14 CLR Runtime Header    → `clr_header` (.NET assemblies)

    Plus the deprecated COFF symbol table when the optional header
    points at one (`coff_symbols`).

    Logs a fatal error and exits on structural malformations: missing
    MZ/PE magics, mismatched machine/magic combinations, optional
    header below the per-format minimum size, or sections that run
    past EOF. Every iteration loop has a defensive cap so a fuzzed PE
    can't make the parser scan past realistic bounds. Safe to call on
    hand-crafted byte buffers."""
    if len(data) < 0x40 or data[:2] != DOS_MAGIC:
        log.error("win32 target does not start with an MZ DOS header")

    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != PE_MAGIC:
        log.error(f"win32 target does not contain a PE header at 0x{pe_off:X}")

    # COFF file header (20 bytes) follows the 4-byte PE signature.
    coff_off = pe_off + 4
    (
        machine,
        num_sections,
        timestamp,
        coff_symtab_ptr,
        coff_num_symbols,
        size_of_optional_header,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, coff_off)

    opt_off = coff_off + 20
    if size_of_optional_header < 2:
        log.error("win32 target has no PE optional header")
    if opt_off + size_of_optional_header > len(data):
        log.error("win32 optional header runs past end of file")

    magic = struct.unpack_from("<H", data, opt_off)[0]
    is_pe32_plus = magic == OPT_MAGIC_PE32_PLUS
    if magic not in (OPT_MAGIC_PE32, OPT_MAGIC_PE32_PLUS):
        log.error(f"win32 target has unknown optional header magic 0x{magic:04X}")

    # Cross-validate Machine vs Optional Header magic: i386 / ARM32 are
    # always PE32 (magic 0x10B); AMD64 / ARM64 are always PE32+ (magic
    # 0x20B). A mismatch indicates a corrupt or fabricated PE.
    _M32 = {MACHINE_I386, MACHINE_ARM32}
    _M64 = {MACHINE_AMD64, MACHINE_ARM64}
    if machine in _M64 and not is_pe32_plus:
        log.error(
            f"win32 target's Machine (0x{machine:04X}) is 64-bit but the "
            f"optional header magic (0x{magic:04X}) says PE32 — corrupt PE"
        )
    if machine in _M32 and is_pe32_plus:
        log.error(
            f"win32 target's Machine (0x{machine:04X}) is 32-bit but the "
            f"optional header magic (0x{magic:04X}) says PE32+ — corrupt PE"
        )

    # Reject truncated optional headers: PE32 needs 96 bytes (standard +
    # windows-specific); PE32+ needs 112. Anything smaller can't carry the
    # data-directory offsets we expect.
    min_opt = 112 if is_pe32_plus else 96
    if size_of_optional_header < min_opt:
        log.error(
            f"win32 optional header is {size_of_optional_header} bytes; "
            f"need at least {min_opt} for the data directories"
        )

    pe = PEInfo(
        machine=machine,
        num_sections=num_sections,
        timestamp=timestamp,
        characteristics=characteristics,
        is_pe32_plus=is_pe32_plus,
        pe_header_offset=pe_off,
        coff_symtab_ptr=coff_symtab_ptr,
        coff_num_symbols=coff_num_symbols,
    )

    # MajorLinkerVersion + MinorLinkerVersion (BYTE BYTE) at opt_off + 2.
    pe.linker_major = data[opt_off + 2] if opt_off + 2 < len(data) else 0
    pe.linker_minor = data[opt_off + 3] if opt_off + 3 < len(data) else 0

    if not is_pe32_plus:
        # PE32 optional header layout (offsets relative to opt_off).
        pe.entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        pe.image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
        pe.section_alignment = struct.unpack_from("<I", data, opt_off + 32)[0]
        pe.file_alignment = struct.unpack_from("<I", data, opt_off + 36)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]
        pe.size_of_headers = struct.unpack_from("<I", data, opt_off + 60)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
        pe.dll_characteristics = struct.unpack_from("<H", data, opt_off + 70)[0]
        pe.size_of_stack_reserve = struct.unpack_from("<I", data, opt_off + 72)[0]
        pe.size_of_stack_commit = struct.unpack_from("<I", data, opt_off + 76)[0]
        pe.size_of_heap_reserve = struct.unpack_from("<I", data, opt_off + 80)[0]
        pe.size_of_heap_commit = struct.unpack_from("<I", data, opt_off + 84)[0]
        num_rva = struct.unpack_from("<I", data, opt_off + 92)[0]
        dd_off = opt_off + 96
    else:
        pe.entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        pe.section_alignment = struct.unpack_from("<I", data, opt_off + 32)[0]
        pe.file_alignment = struct.unpack_from("<I", data, opt_off + 36)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]
        pe.size_of_headers = struct.unpack_from("<I", data, opt_off + 60)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
        pe.dll_characteristics = struct.unpack_from("<H", data, opt_off + 70)[0]
        pe.size_of_stack_reserve = struct.unpack_from("<Q", data, opt_off + 72)[0]
        pe.size_of_stack_commit = struct.unpack_from("<Q", data, opt_off + 80)[0]
        pe.size_of_heap_reserve = struct.unpack_from("<Q", data, opt_off + 88)[0]
        pe.size_of_heap_commit = struct.unpack_from("<Q", data, opt_off + 96)[0]
        num_rva = struct.unpack_from("<I", data, opt_off + 108)[0]
        dd_off = opt_off + 112

    for i in range(min(num_rva, 16)):
        if dd_off + 8 > opt_off + size_of_optional_header:
            break
        rva = struct.unpack_from("<I", data, dd_off + i * 8)[0]
        size = struct.unpack_from("<I", data, dd_off + i * 8 + 4)[0]
        pe.data_directories.append((rva, size))

    section_off = opt_off + size_of_optional_header
    # PE spec caps NumberOfSections at 96. Anything higher is malformed —
    # cap defensively so we don't iterate a fuzzed huge value.
    capped_num_sections = min(num_sections, 96)
    for i in range(capped_num_sections):
        sh = section_off + i * 40
        if sh + 40 > len(data):
            log.error(f"win32 section header {i} runs past end of file")
        raw_name = data[sh : sh + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        (
            virt_size,
            virt_addr,
            raw_size,
            raw_ptr,
            _ptr_relocs,
            _ptr_linenums,
            _num_relocs,
            _num_linenums,
            scn_chars,
        ) = struct.unpack_from("<IIIIIIHHI", data, sh + 8)
        pe.sections.append(
            PESection(
                name=name,
                virtual_size=virt_size,
                virtual_address=virt_addr,
                raw_size=raw_size,
                raw_pointer=raw_ptr,
                characteristics=scn_chars,
            )
        )

    parse_exports(data, pe)
    parse_imports(data, pe)
    parse_bound_imports(data, pe)
    parse_delay_imports(data, pe)
    parse_relocations(data, pe)
    parse_exception_table(data, pe)
    parse_load_config(data, pe)
    parse_debug(data, pe)
    parse_tls(data, pe)
    parse_resources(data, pe)
    parse_version_info(data, pe)
    parse_coff_symtab(data, pe)
    parse_unwind_info(data, pe)
    parse_clr_header(data, pe)
    return pe


_MAX_CSTR_LEN = 4096


def _read_cstr(data: bytes, off: int) -> str:
    """Read a NUL-terminated ASCII string. Truncates at `_MAX_CSTR_LEN`
    to bound parse-time cost on malformed or non-NUL-terminated input."""
    if off < 0 or off >= len(data):
        return ""
    cap = min(off + _MAX_CSTR_LEN, len(data))
    end = data.find(b"\x00", off, cap)
    if end < 0:
        end = cap
    return data[off:end].decode("ascii", errors="replace")


def parse_exports(data: bytes, pe: PEInfo) -> None:
    """Populate `pe.exports` and `pe.export_dll_name` from data directory 0."""
    if not pe.data_directories:
        return
    exp_rva, exp_size = pe.data_directories[DIR_EXPORT]
    if exp_rva == 0 or exp_size == 0:
        return
    exp_off = pe.rva_to_file_offset(exp_rva)
    if exp_off is None or exp_off + 40 > len(data):
        return

    (
        _flags,
        _ts,
        _vmaj,
        _vmin,
        name_rva,
        ord_base,
        num_funcs,
        num_names,
        funcs_rva,
        names_rva,
        ordinals_rva,
    ) = struct.unpack_from("<IIHHIIIIIII", data, exp_off)

    if name_rva:
        name_off = pe.rva_to_file_offset(name_rva)
        if name_off is not None:
            pe.export_dll_name = _read_cstr(data, name_off)

    funcs_off = pe.rva_to_file_offset(funcs_rva) if funcs_rva else None
    names_off = pe.rva_to_file_offset(names_rva) if names_rva else None
    ordinals_off = pe.rva_to_file_offset(ordinals_rva) if ordinals_rva else None

    if funcs_off is None:
        return

    # Defensive caps. Real-world DLLs export a few thousand symbols at most
    # (e.g. ntdll.dll ≈ 2000). A fuzzed export directory could declare
    # millions of entries, causing the parser to scan gigabytes of data.
    EXPORT_LIMIT = 65536
    num_funcs = min(num_funcs, EXPORT_LIMIT)
    num_names = min(num_names, EXPORT_LIMIT)

    # Map ordinal-index → name (some functions are export-by-ordinal only).
    name_for_ordinal: Dict[int, str] = {}
    if names_off is not None and ordinals_off is not None:
        for i in range(num_names):
            if names_off + i * 4 + 4 > len(data):
                break
            if ordinals_off + i * 2 + 2 > len(data):
                break
            name_ptr_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
            ordinal_idx = struct.unpack_from("<H", data, ordinals_off + i * 2)[0]
            name_off = pe.rva_to_file_offset(name_ptr_rva)
            if name_off is None:
                continue
            name_for_ordinal[ordinal_idx] = _read_cstr(data, name_off)

    for i in range(num_funcs):
        if funcs_off + i * 4 + 4 > len(data):
            break
        func_rva = struct.unpack_from("<I", data, funcs_off + i * 4)[0]
        if func_rva == 0:
            continue
        forwarder: Optional[str] = None
        # When the function RVA falls inside the export directory itself,
        # it's a forwarder string (DLL.Func or DLL.#ord) rather than code.
        if exp_rva <= func_rva < exp_rva + exp_size:
            f_off = pe.rva_to_file_offset(func_rva)
            if f_off is not None:
                forwarder = _read_cstr(data, f_off)
        pe.exports.append(
            PEExport(
                name=name_for_ordinal.get(i),
                ordinal=i + ord_base,
                rva=func_rva,
                forwarder=forwarder,
            )
        )


def ptr_layout(is_pe32_plus: bool) -> Tuple[int, str, str, int]:
    """Per-bitness pointer-slot constants used by data + text segments:
    (size_bytes, struct_fmt, asm_directive, hex_print_width).

    PE32 uses 4-byte slots emitted as `.long 0xXXXXXXXX`; PE32+ uses
    8-byte slots emitted as `.quad 0xXXXXXXXXXXXXXXXX`."""
    if is_pe32_plus:
        return 8, "<Q", ".quad", 16
    return 4, "<I", ".long", 8


def _thunk_layout(is_pe32_plus: bool) -> Tuple[int, int, str]:
    """Per-bitness thunk-array constants: (size_bytes, ordinal_flag, struct_fmt).
    PE32 thunks are 32-bit DWORDs with the ordinal flag at bit 31;
    PE32+ thunks are 64-bit QWORDs with the ordinal flag at bit 63.
    Signature matches `ptr_layout` for symmetry — both take a bool
    rather than a full PEInfo object."""
    if is_pe32_plus:
        return 8, 1 << 63, "<Q"
    return 4, 1 << 31, "<I"


def _walk_thunk_array(
    data: bytes,
    pe: PEInfo,
    thunk_off: int,
    slot_rva: int,
    thunk_size: int,
    thunk_fmt: str,
    ordinal_flag: int,
    dll_name: str,
    dest: List[PEImport],
) -> None:
    """Walk a NULL-terminated array of import thunks (used by both
    eager and delay-load import descriptors). Each thunk is either an
    ordinal value (high-bit set) or an RVA pointing at a hint/name
    record. Resolved entries are appended to `dest` as PEImport
    records keyed by the corresponding IAT slot RVA."""
    for _ in range(65536):
        if thunk_off + thunk_size > len(data):
            break
        thunk = struct.unpack_from(thunk_fmt, data, thunk_off)[0]
        if thunk == 0:
            break
        name: Optional[str] = None
        ordinal: Optional[int] = None
        if thunk & ordinal_flag:
            ordinal = thunk & 0xFFFF
        else:
            hint_off = pe.rva_to_file_offset(thunk & 0x7FFFFFFF)
            if hint_off is not None and hint_off + 2 < len(data):
                # Capture the 16-bit hint as a fallback ordinal when
                # the name string at hint+2 is empty (stripped binary
                # or hand-crafted IAT).
                hint = struct.unpack_from("<H", data, hint_off)[0]
                raw = _read_cstr(data, hint_off + 2)
                if raw:
                    name = raw
                elif hint:
                    ordinal = hint
        dest.append(
            PEImport(dll=dll_name, name=name, ordinal=ordinal, iat_rva=slot_rva)
        )
        thunk_off += thunk_size
        slot_rva += thunk_size


def parse_imports(data: bytes, pe: PEInfo) -> None:
    """Populate `pe.imports` from data directory 1 (the Import Table).

    Reads IMAGE_IMPORT_DESCRIPTOR entries until the null terminator. For
    each DLL walks the Import Lookup Table (OriginalFirstThunk) — falling
    back to the IAT (FirstThunk) when the ILT is absent — and records the
    DLL name, imported symbol, and the IAT slot RVA so call sites that
    reach the IAT can be tagged with the imported name.
    """
    if len(pe.data_directories) <= DIR_IMPORT:
        return
    imp_rva, imp_size = pe.data_directories[DIR_IMPORT]
    if imp_rva == 0 or imp_size == 0:
        return
    imp_off = pe.rva_to_file_offset(imp_rva)
    if imp_off is None:
        return

    thunk_size, ordinal_flag, thunk_fmt = _thunk_layout(pe.is_pe32_plus)

    desc_off = imp_off
    # Cap descriptor count at a sane maximum to bound parse cost on
    # malformed binaries.
    for _desc_i in range(4096):
        if desc_off + 20 > len(data):
            break
        ilt_rva, _ts, _fwd, dll_name_rva, iat_rva = struct.unpack_from(
            "<IIIII", data, desc_off
        )
        if ilt_rva == 0 and dll_name_rva == 0 and iat_rva == 0:
            break
        desc_off += 20

        dll_off = pe.rva_to_file_offset(dll_name_rva)
        dll_name = _read_cstr(data, dll_off) if dll_off is not None else "?"

        # Prefer the Import Lookup Table; fall back to the IAT if absent.
        thunk_array_rva = ilt_rva if ilt_rva else iat_rva
        thunk_off = pe.rva_to_file_offset(thunk_array_rva)
        if thunk_off is None or iat_rva == 0:
            # Without an IAT RVA we can't compute meaningful slot VAs for
            # the entries we discover; skip the descriptor.
            continue

        _walk_thunk_array(
            data,
            pe,
            thunk_off,
            iat_rva,
            thunk_size,
            thunk_fmt,
            ordinal_flag,
            dll_name,
            pe.imports,
        )


def parse_delay_imports(data: bytes, pe: PEInfo) -> None:
    """Parse data directory 13 (Delay Import). MSVC `__declspec(dllimport)`
    with `/DELAYLOAD` produces a separate import table for lazy resolution.

    Each IMAGE_DELAYLOAD_DESCRIPTOR is 32 bytes; entries are NULL-terminated.
    `Attributes` flag bit 0 indicates RVA-based fields (v2); else they're
    VAs that need ImageBase subtraction (v1, legacy)."""
    if len(pe.data_directories) <= DIR_DELAY_IMPORT:
        return
    di_rva, di_size = pe.data_directories[DIR_DELAY_IMPORT]
    if di_rva == 0 or di_size == 0:
        return
    di_off = pe.rva_to_file_offset(di_rva)
    if di_off is None:
        return

    thunk_size, ordinal_flag, thunk_fmt = _thunk_layout(pe.is_pe32_plus)

    desc_off = di_off
    end = di_off + di_size
    for _desc_i in range(4096):
        if desc_off + 32 > end or desc_off + 32 > len(data):
            break
        (
            attrs,
            dll_name_field,
            _module_handle,
            iat_field,
            int_field,
            _bound_iat,
            _unload_iat,
            _ts,
        ) = struct.unpack_from("<IIIIIIII", data, desc_off)
        if attrs == 0 and dll_name_field == 0 and iat_field == 0 and int_field == 0:
            break
        desc_off += 32

        # Translate fields (RVAs for v2, VAs for v1).
        def to_rva(field: int) -> int:
            if attrs & 1:
                return field
            return field - pe.image_base if field >= pe.image_base else field

        dll_name_rva = to_rva(dll_name_field)
        iat_rva = to_rva(iat_field)
        int_rva = to_rva(int_field) if int_field else iat_rva

        dll_off = pe.rva_to_file_offset(dll_name_rva)
        dll_name = _read_cstr(data, dll_off) if dll_off is not None else "?"

        int_off = pe.rva_to_file_offset(int_rva)
        if int_off is None or iat_rva == 0:
            continue

        _walk_thunk_array(
            data,
            pe,
            int_off,
            iat_rva,
            thunk_size,
            thunk_fmt,
            ordinal_flag,
            dll_name,
            pe.delay_imports,
        )


def parse_bound_imports(data: bytes, pe: PEInfo) -> None:
    """Parse data directory 11 (Bound Import Table).

    Unlike the regular import table, bound-import entries reference DLL
    names by an offset relative to the start of the bound-import directory
    itself (NOT an RVA). Entries are 8-byte IMAGE_BOUND_IMPORT_DESCRIPTOR
    structs terminated by an all-zero entry, optionally followed by
    forwarder-ref descriptors."""
    if len(pe.data_directories) <= DIR_BOUND_IMPORT:
        return
    bi_rva, bi_size = pe.data_directories[DIR_BOUND_IMPORT]
    if bi_rva == 0 or bi_size == 0:
        return
    bi_off = pe.rva_to_file_offset(bi_rva)
    if bi_off is None:
        return
    end = bi_off + bi_size

    cur = bi_off
    for _bi_i in range(4096):
        if cur + 8 > end or cur + 8 > len(data):
            break
        ts, name_off, n_fwd = struct.unpack_from("<IHH", data, cur)
        if ts == 0 and name_off == 0 and n_fwd == 0:
            break
        name_abs = bi_off + name_off
        dll_name = _read_cstr(data, name_abs) if name_abs < len(data) else "?"
        cur += 8
        fwds: List[str] = []
        # Per spec, NumberOfModuleForwarderRefs fits in a WORD — bound by
        # 0xFFFF entries.
        for _ in range(min(n_fwd, 0xFFFF)):
            if cur + 8 > len(data) or cur + 8 > end:
                break
            _ts, fname_off, _rsv = struct.unpack_from("<IHH", data, cur)
            fname_abs = bi_off + fname_off
            if fname_abs < len(data):
                fwds.append(_read_cstr(data, fname_abs))
            cur += 8
        pe.bound_imports.append(
            PEBoundImport(dll=dll_name, timestamp=ts, forwarder_refs=fwds)
        )


def parse_load_config(data: bytes, pe: PEInfo) -> None:
    """Parse data directory 10 (Load Config). Extracts:

    - SecurityCookie VA (`/GS` cookie used to detect stack-buffer overruns)
    - SEHandlerTable RVA + count: array of valid SEH handler RVAs the
      MSVC `/SAFESEH` linker switch produced for PE32 binaries.
    """
    if len(pe.data_directories) <= DIR_LOAD_CONFIG:
        return
    lc_rva, lc_size = pe.data_directories[DIR_LOAD_CONFIG]
    if lc_rva == 0 or lc_size == 0:
        return
    lc_off = pe.rva_to_file_offset(lc_rva)
    if lc_off is None:
        return

    if pe.is_pe32_plus:
        # PE32+ layout: SecurityCookie at +0x58 (QWORD); CFG fields at
        # +0x70/+0x78/+0x80/+0x88/+0x90.
        if lc_off + 0x60 > len(data):
            return
        pe.security_cookie_va = struct.unpack_from("<Q", data, lc_off + 0x58)[0]
        if lc_off + 0x98 <= len(data):
            cfg_table_va = struct.unpack_from("<Q", data, lc_off + 0x80)[0]
            cfg_count = struct.unpack_from("<Q", data, lc_off + 0x88)[0]
            pe.cfg_flags = struct.unpack_from("<I", data, lc_off + 0x90)[0]
            _read_cfg_table(data, pe, cfg_table_va, cfg_count)
        return

    # PE32 layout: SecurityCookie at +0x3C, SEHandlerTable at +0x40,
    # SEHandlerCount at +0x44, GuardCFFunctionTable at +0x54,
    # GuardCFFunctionCount at +0x58, GuardFlags at +0x5C.
    if lc_off + 0x48 > len(data):
        return
    pe.security_cookie_va = struct.unpack_from("<I", data, lc_off + 0x3C)[0]
    seh_table_va = struct.unpack_from("<I", data, lc_off + 0x40)[0]
    seh_count = struct.unpack_from("<I", data, lc_off + 0x44)[0]
    if seh_table_va and seh_count:
        # SEHandlerTable is a VA (already absolute), array of DWORD RVAs.
        table_off = pe.va_to_file_offset(seh_table_va)
        if table_off is not None:
            # Real binaries declare hundreds of SEH handlers at most;
            # cap at 1M for fuzz safety.
            for i in range(min(seh_count, 1_000_000)):
                entry_off = table_off + i * 4
                if entry_off + 4 > len(data):
                    break
                pe.safe_seh_handlers.append(
                    struct.unpack_from("<I", data, entry_off)[0]
                )

    if lc_off + 0x60 <= len(data):
        cfg_table_va = struct.unpack_from("<I", data, lc_off + 0x54)[0]
        cfg_count = struct.unpack_from("<I", data, lc_off + 0x58)[0]
        pe.cfg_flags = struct.unpack_from("<I", data, lc_off + 0x5C)[0]
        _read_cfg_table(data, pe, cfg_table_va, cfg_count)


def _read_cfg_table(data: bytes, pe: PEInfo, table_va: int, count: int) -> None:
    """Read a GuardCFFunctionTable. Each entry is at least 4 bytes (RVA);
    the high bits of `GuardFlags` indicate optional metadata bytes that
    follow each RVA. We compute the per-entry stride and harvest only the
    RVA from each slot."""
    if not table_va or not count:
        return
    table_off = pe.va_to_file_offset(table_va)
    if table_off is None:
        return
    # GuardFlags bits 28..31 hold the count of extra metadata bytes per
    # entry, capped to 7. Stride is 4 + extra_bytes.
    extra = (pe.cfg_flags >> 28) & 0x0F
    stride = 4 + min(extra, 7)
    # /guard:cf tables can be large (Windows 10 ntdll has ~40k entries)
    # but a megabyte of guarded functions is well beyond realistic.
    for i in range(min(count, 1_000_000)):
        entry_off = table_off + i * stride
        if entry_off + 4 > len(data):
            break
        rva = struct.unpack_from("<I", data, entry_off)[0]
        pe.cfg_function_rvas.append(rva)


def parse_exception_table(data: bytes, pe: PEInfo) -> None:
    """Parse data directory 3 (Exception Table). For PE32+ this is an
    array of RUNTIME_FUNCTION entries (12 bytes each) giving definitive
    function boundaries — useful both for surfacing real function starts
    and for navigating SEH unwind data."""
    if len(pe.data_directories) <= DIR_EXCEPTION:
        return
    et_rva, et_size = pe.data_directories[DIR_EXCEPTION]
    if et_rva == 0 or et_size == 0:
        return
    et_off = pe.rva_to_file_offset(et_rva)
    if et_off is None:
        return
    end = min(et_off + et_size, len(data))
    # Bound at ~1M RUNTIME_FUNCTION entries: more than any realistic PE.
    max_entries = min((end - et_off) // 12, 1_000_000)
    for i in range(max_entries):
        cur = et_off + i * 12
        if cur + 12 > end:
            break
        begin, fin, uw = struct.unpack_from("<III", data, cur)
        if begin == 0 and fin == 0 and uw == 0:
            break
        pe.runtime_functions.append((begin, fin, uw))


RELOC_TYPE_ABSOLUTE = 0
RELOC_TYPE_HIGHLOW = 3
RELOC_TYPE_DIR64 = 10


def parse_relocations(data: bytes, pe: PEInfo) -> None:
    """Populate `pe.pointer_rvas` from data directory 5 (the Base Relocation
    Table). Each block applies to one 4 KB page; entries of type 3
    (HIGHLOW, 32-bit) or 10 (DIR64, 64-bit) mark RVAs of absolute pointers
    that the PE loader needs to rebase. Padding entries (type 0) are
    skipped."""
    if len(pe.data_directories) <= DIR_BASERELOC:
        return
    rel_rva, rel_size = pe.data_directories[DIR_BASERELOC]
    if rel_rva == 0 or rel_size == 0:
        return
    rel_off = pe.rva_to_file_offset(rel_rva)
    if rel_off is None:
        return

    end = rel_off + rel_size
    accept = {RELOC_TYPE_HIGHLOW, RELOC_TYPE_DIR64}
    block = rel_off
    while block + 8 <= end and block + 8 <= len(data):
        page_rva, block_size = struct.unpack_from("<II", data, block)
        if block_size < 8 or block + block_size > end:
            break
        entries_end = block + block_size
        entry = block + 8
        while entry + 2 <= entries_end:
            word = struct.unpack_from("<H", data, entry)[0]
            entry += 2
            kind = word >> 12
            if kind == RELOC_TYPE_ABSOLUTE:
                continue
            if kind not in accept:
                continue
            pe.pointer_rvas.add(page_rva + (word & 0x0FFF))
        block += block_size


def parse_debug(data: bytes, pe: PEInfo) -> None:
    """Populate `pe.pdb_path` from data directory 6 (Debug). Walks the
    IMAGE_DEBUG_DIRECTORY array, looking for a CodeView (type 2) entry that
    embeds either an `RSDS`/`NB10` record with a trailing PDB filename."""
    if len(pe.data_directories) <= DIR_DEBUG:
        return
    dbg_rva, dbg_size = pe.data_directories[DIR_DEBUG]
    if dbg_rva == 0 or dbg_size == 0:
        return
    dbg_off = pe.rva_to_file_offset(dbg_rva)
    if dbg_off is None:
        return

    end = dbg_off + dbg_size
    entry = dbg_off
    while entry + 28 <= end and entry + 28 <= len(data):
        (
            _chars,
            _ts,
            _vmaj,
            _vmin,
            entry_type,
            size_of_data,
            _addr_of_raw,
            ptr_to_raw,
        ) = struct.unpack_from("<IIHHIIII", data, entry)
        entry += 28
        if entry_type != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        if ptr_to_raw == 0 or size_of_data < 4:
            continue
        if ptr_to_raw + size_of_data > len(data):
            continue
        cv = data[ptr_to_raw : ptr_to_raw + size_of_data]
        magic = cv[:4]
        if magic == b"RSDS" and len(cv) >= 24:
            # Layout: magic(4) + GUID(16) + age(4) + name
            g0, g1, g2, g3 = struct.unpack_from("<IHH8s", cv, 4)
            tail = "-".join(f"{b:02X}" for b in g3)
            pe.pdb_guid = f"{g0:08X}-{g1:04X}-{g2:04X}-{tail}"
            pe.pdb_age = struct.unpack_from("<I", cv, 20)[0]
            pe.pdb_path = _read_cstr(cv, 24)
            return
        if magic == b"NB10" and len(cv) >= 16:
            # Layout: magic(4) + offset(4) + signature(4) + age(4) + name
            sig = struct.unpack_from("<I", cv, 8)[0]
            pe.pdb_guid = f"{sig:08X}"
            pe.pdb_age = struct.unpack_from("<I", cv, 12)[0]
            pe.pdb_path = _read_cstr(cv, 16)
            return


def parse_tls(data: bytes, pe: PEInfo) -> None:
    """Populate `pe.tls_callback_vas` from data directory 9 (TLS).
    `IMAGE_TLS_DIRECTORY` for PE32 has AddressOfCallBacks at offset 0x0C
    (PE32+ at 0x18). The pointer dereferences to a NULL-terminated array
    of callback VAs."""
    if len(pe.data_directories) <= DIR_TLS:
        return
    tls_rva, tls_size = pe.data_directories[DIR_TLS]
    if tls_rva == 0 or tls_size == 0:
        return
    tls_off = pe.rva_to_file_offset(tls_rva)
    if tls_off is None:
        return

    if pe.is_pe32_plus:
        if tls_off + 0x20 > len(data):
            return
        cb_va = struct.unpack_from("<Q", data, tls_off + 0x18)[0]
        ptr_size = 8
        ptr_fmt = "<Q"
    else:
        if tls_off + 0x10 > len(data):
            return
        cb_va = struct.unpack_from("<I", data, tls_off + 0x0C)[0]
        ptr_size = 4
        ptr_fmt = "<I"

    if cb_va == 0:
        return
    cb_off = pe.va_to_file_offset(cb_va)
    if cb_off is None:
        return

    # Bound at 1024 TLS callbacks — already absurd for a real binary.
    for _cb_i in range(1024):
        if cb_off + ptr_size > len(data):
            break
        v = struct.unpack_from(ptr_fmt, data, cb_off)[0]
        if v == 0:
            break
        pe.tls_callback_vas.append(v)
        cb_off += ptr_size


def linker_version_label(major: int, minor: int) -> str:
    """Translate an `IMAGE_OPTIONAL_HEADER.MajorLinkerVersion` value into a
    rough Visual C++ / linker product name. Real binaries are usually
    produced by Microsoft's `link.exe`; the major number tracks the MSVC
    release closely enough to surface as a hint."""
    mapping = {
        2: "MSVC 2.x",
        3: "MSVC 4.x",
        4: "MSVC 4.x",
        5: "MSVC 5.0",
        6: "MSVC 6.0",
        7: "MSVC 7.0 / VS .NET 2002",
        8: "MSVC 8.0 / VS 2005",
        9: "MSVC 9.0 / VS 2008",
        10: "MSVC 10.0 / VS 2010",
        11: "MSVC 11.0 / VS 2012",
        12: "MSVC 12.0 / VS 2013",
        14: "MSVC 14.x / VS 2015-2022",
    }
    return mapping.get(major, f"linker v{major}.{minor:02d}")


RESOURCE_TYPE_NAMES = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    17: "DLGINCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST",
}


def _read_resource_name(data: bytes, name_field: int, root_off: int) -> object:
    """Return either the integer ID, or the decoded UTF-16 name string."""
    if name_field & 0x80000000:
        name_off = root_off + (name_field & 0x7FFFFFFF)
        if name_off + 2 > len(data):
            return name_field & 0x7FFFFFFF
        length = struct.unpack_from("<H", data, name_off)[0]
        text_off = name_off + 2
        text_end = text_off + length * 2
        if text_end > len(data):
            return name_field & 0x7FFFFFFF
        return data[text_off:text_end].decode("utf-16-le", errors="replace")
    return name_field


def parse_resources(data: bytes, pe: PEInfo) -> None:
    """Walk the .rsrc tree (3 nominal levels: type → name → language) and
    record each leaf in `pe.resources`."""
    if len(pe.data_directories) <= DIR_RESOURCE:
        return
    rsrc_rva, rsrc_size = pe.data_directories[DIR_RESOURCE]
    if rsrc_rva == 0 or rsrc_size == 0:
        return
    root_off = pe.rva_to_file_offset(rsrc_rva)
    if root_off is None:
        return

    def walk_dir(dir_off: int, depth: int, path: tuple) -> None:
        # Bound the recursion: a valid resource tree has only 3 levels
        # (type → name → language). Anything deeper indicates a circular
        # reference or malformed data — bail out rather than recurse.
        if depth > 8:
            return
        if dir_off + 16 > len(data):
            return
        (
            _chars,
            _ts,
            _vmaj,
            _vmin,
            n_named,
            n_id,
        ) = struct.unpack_from("<IIHHHH", data, dir_off)
        # Cap entry count so a fuzzed PE can't make us iterate forever.
        total = min(n_named + n_id, 65536)
        entry_off = dir_off + 16
        for _ in range(total):
            if entry_off + 8 > len(data):
                return
            name_field, data_field = struct.unpack_from("<II", data, entry_off)
            entry_off += 8
            name_val = _read_resource_name(data, name_field, root_off)
            if data_field & 0x80000000:
                sub_off = root_off + (data_field & 0x7FFFFFFF)
                walk_dir(sub_off, depth + 1, path + (name_val,))
            else:
                leaf_off = root_off + data_field
                if leaf_off + 16 > len(data):
                    continue
                leaf_rva, leaf_size, _cp, _rsv = struct.unpack_from(
                    "<IIII", data, leaf_off
                )
                if len(path) >= 2:
                    rtype, rid = path[0], path[1]
                else:
                    rtype, rid = path[0], None
                pe.resources.append(
                    PEResource(
                        rtype=rtype,
                        rid=rid,
                        language=name_val if isinstance(name_val, int) else 0,
                        rva=leaf_rva,
                        size=leaf_size,
                    )
                )

    walk_dir(root_off, 0, ())


def _align4(off: int) -> int:
    return (off + 3) & ~3


def _read_wstr(blob: bytes, off: int) -> tuple:
    """Read a UTF-16 NUL-terminated string starting at `off`. Returns
    (decoded_string, next_offset_past_terminator)."""
    end = off
    while end + 1 < len(blob):
        if blob[end] == 0 and blob[end + 1] == 0:
            break
        end += 2
    text = blob[off:end].decode("utf-16-le", errors="replace")
    return text, end + 2


def _walk_versioninfo_node(blob: bytes, off: int, out: dict, base_off: int) -> int:
    """Walk one VS_VERSIONINFO-style node starting at `off`. Recurses into
    children. Strings are recorded into `out`. Returns the offset just past
    this node (already aligned)."""
    if off + 6 > len(blob):
        return len(blob)
    w_length, w_value_length, w_type = struct.unpack_from("<HHH", blob, off)
    node_end = off + w_length
    if w_length == 0 or node_end > len(blob):
        return len(blob)
    key, body_off = _read_wstr(blob, off + 6)
    body_off = _align4(body_off - base_off) + base_off

    value_end = body_off
    if (
        w_value_length > 0
        and body_off + (w_value_length * (2 if w_type == 1 else 1)) <= node_end
    ):
        if w_type == 1:  # text — value is UTF-16
            value = blob[body_off : body_off + w_value_length * 2]
            # Strip trailing NUL WCHAR(s) without splitting on misaligned
            # zero pairs.
            chars = [
                value[i : i + 2] for i in range(0, len(value) - (len(value) & 1), 2)
            ]
            text_chars = []
            for wch in chars:
                if wch == b"\x00\x00":
                    break
                text_chars.append(wch)
            value_text = b"".join(text_chars).decode("utf-16-le", errors="replace")
            if key not in {"VS_VERSION_INFO", "StringFileInfo", "VarFileInfo"}:
                out[key] = value_text
            value_end = body_off + w_value_length * 2
        else:
            # Binary value. The VarFileInfo's "Translation" child carries
            # an array of (LANGID, codepage) WORD pairs as binary data —
            # one entry per locale supported by the version resource.
            if key == "Translation" and w_value_length >= 4:
                pairs = []
                pair_off = body_off
                while pair_off + 4 <= node_end:
                    langid, codepage = struct.unpack_from("<HH", blob, pair_off)
                    pairs.append((langid, codepage))
                    pair_off += 4
                    if pair_off - body_off >= w_value_length:
                        break
                # Render as a comma-separated list of `0xLLLL/0xCCCC`
                # so the version_info dict stays str→str.
                out["Translation"] = ", ".join(
                    f"0x{lid:04X}/0x{cp:04X}" for lid, cp in pairs
                )
            value_end = body_off + w_value_length
    value_end = _align4(value_end - base_off) + base_off

    # Recurse into children, if any space remains.
    child = value_end
    while child < node_end:
        next_child = _walk_versioninfo_node(blob, child, out, base_off)
        if next_child <= child:
            break
        child = _align4(next_child - base_off) + base_off

    return node_end


_UNWIND_OP_NAMES = {
    0: "PUSH_NONVOL",
    1: "ALLOC_LARGE",
    2: "ALLOC_SMALL",
    3: "SET_FPREG",
    4: "SAVE_NONVOL",
    5: "SAVE_NONVOL_FAR",
    6: "EPILOG",
    7: "SPARE_CODE",
    8: "SAVE_XMM128",
    9: "SAVE_XMM128_FAR",
    10: "PUSH_MACHFRAME",
}


def parse_clr_header(data: bytes, pe: PEInfo) -> None:
    """Parse data directory 14 (CLR Runtime Header) when present.
    Identifies the binary as a .NET assembly and surfaces metadata /
    entry-point / strong-name fields so the analyst doesn't have to
    chase down the assembly's structure manually."""
    if len(pe.data_directories) <= DIR_COM_DESCRIPTOR:
        return
    clr_rva, clr_size = pe.data_directories[DIR_COM_DESCRIPTOR]
    if clr_rva == 0 or clr_size == 0:
        return
    f_off = pe.rva_to_file_offset(clr_rva)
    if f_off is None or f_off + 72 > len(data):
        return
    (
        cb_size,
        rt_major,
        rt_minor,
        md_rva,
        md_size,
        flags,
        entry_tok,
        res_rva,
        res_size,
        sn_rva,
        sn_size,
    ) = struct.unpack_from("<IHHIIIIIIII", data, f_off)
    pe.clr_header = CLRHeader(
        cb_size=cb_size,
        runtime_major=rt_major,
        runtime_minor=rt_minor,
        metadata_rva=md_rva,
        metadata_size=md_size,
        flags=flags,
        entry_point_token_or_rva=entry_tok,
        resources_rva=res_rva,
        resources_size=res_size,
        strong_name_signature_rva=sn_rva,
        strong_name_signature_size=sn_size,
    )


def parse_unwind_info(data: bytes, pe: PEInfo) -> None:
    """Decode each PE32+ RUNTIME_FUNCTION's IMAGE_UNWIND_INFO record.

    The Microsoft x64 SEH spec lays UNWIND_INFO out as:
        +0  : byte    Version (low 3 bits) | Flags (high 5 bits)
        +1  : byte    SizeOfProlog
        +2  : byte    CountOfUnwindCodes
        +3  : byte    FrameRegister (low 4 bits) | FrameRegOffset*16 (high 4)
        +4  : code[]  CountOfUnwindCodes × 2 bytes
        +    : padding to QWORD
        +    : optional handler / chain-info (per flags)

    Each unwind code is a `(prolog_offset, opcode, info)` triple. We
    only decode the ops + chained-record pointer; exception-handler
    data isn't surfaced (rarely useful from a disassembly viewpoint).
    """
    if not pe.is_pe32_plus:
        return
    seen: Set[int] = set()
    for begin, _end, raw_uw in pe.runtime_functions:
        uw = raw_uw & 0x7FFFFFFF
        if not uw or uw in seen:
            continue
        seen.add(uw)
        f_off = pe.rva_to_file_offset(uw)
        if f_off is None or f_off + 4 > len(data):
            continue
        b0, b1, n_codes, b3 = struct.unpack_from("<BBBB", data, f_off)
        version = b0 & 0x07
        flags = b0 >> 3
        prolog_size = b1
        frame_register = b3 & 0x0F
        frame_register_offset = (b3 >> 4) * 16

        codes_off = f_off + 4
        codes_end = codes_off + n_codes * 2
        if codes_end > len(data):
            continue
        codes: List[Tuple[int, str, int]] = []
        i = 0
        while i < n_codes:
            code_off = codes_off + i * 2
            offset_in_prolog = data[code_off]
            packed = data[code_off + 1]
            op = packed & 0x0F
            info = packed >> 4
            codes.append((offset_in_prolog, _UNWIND_OP_NAMES.get(op, f"op{op}"), info))
            # Ops 1, 4, 5, 8, 9 carry extra slots — skip them so we
            # don't misread the next code's prolog_offset.
            extra_slots = {1: 1 + (1 if info else 0), 4: 1, 5: 2, 8: 1, 9: 2}.get(op, 0)
            i += 1 + extra_slots

        chained_rva: Optional[int] = None
        if flags & 0x04:  # UNW_FLAG_CHAININFO
            # The chained RUNTIME_FUNCTION starts at the byte
            # immediately after the unwind codes, aligned to DWORD.
            chain_off = (codes_end + 3) & ~3
            if chain_off + 12 <= len(data):
                chained_rva = struct.unpack_from("<I", data, chain_off)[0]

        pe.unwind_info[uw] = UnwindInfo(
            version=version,
            flags=flags,
            prolog_size=prolog_size,
            frame_register=frame_register,
            frame_register_offset=frame_register_offset,
            codes=codes,
            chained_function_rva=chained_rva,
        )


def parse_coff_symtab(data: bytes, pe: PEInfo) -> None:
    """Parse the deprecated COFF symbol table when the optional header
    points at one. Modern MSVC binaries leave PointerToSymbolTable
    zero and ship debug info via PDB; this parser exists so vintage
    MSVC 4-6 binaries (and some object-file-style PEs) get their
    embedded symbol records surfaced as `pe.coff_symbols`.

    Each IMAGE_SYMBOL record is 18 bytes:
      0   :  8 bytes  Name (zero-terminated; if first 4 bytes are 0
                              the next 4 bytes are a string-table offset)
      8   :  4 bytes  Value
      12  :  2 bytes  SectionNumber (signed: 0/-1/-2 are special)
      14  :  2 bytes  Type
      16  :  1 byte   StorageClass
      17  :  1 byte   NumberOfAuxSymbols

    The string table immediately follows the symbol records; its
    leading DWORD is its total length.
    """
    if not pe.coff_symtab_ptr or not pe.coff_num_symbols:
        return
    base = pe.coff_symtab_ptr
    n_syms = pe.coff_num_symbols
    end = base + n_syms * 18
    if end > len(data):
        return
    str_table_off = end

    def _read_name(record_off: int) -> str:
        name_bytes = data[record_off : record_off + 8]
        # If the first 4 bytes are zero, the next 4 are the string-
        # table offset (relative to the string table base).
        if name_bytes[:4] == b"\x00\x00\x00\x00":
            str_off = struct.unpack_from("<I", name_bytes, 4)[0]
            abs_off = str_table_off + str_off
            if abs_off >= len(data):
                return ""
            return _read_cstr(data, abs_off)
        return name_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace")

    # Cap iteration the same way other parsers do.
    i = 0
    while i < min(n_syms, 1_000_000):
        rec = base + i * 18
        if rec + 18 > len(data):
            break
        name = _read_name(rec)
        value, section_number, sym_type, storage_class, aux = struct.unpack_from(
            "<IhHBB", data, rec + 8
        )
        pe.coff_symbols.append(
            COFFSymbol(
                name=name,
                value=value,
                section_number=section_number,
                sym_type=sym_type,
                storage_class=storage_class,
                aux_records=aux,
            )
        )
        # Skip the aux records — splat doesn't currently surface them
        # but their slot count needs to advance the iterator so the
        # next named symbol lines up.
        i += 1 + aux


def parse_version_info(data: bytes, pe: PEInfo) -> None:
    """Decode the VS_VERSIONINFO StringTable entries from every VERSION
    resource (`rtype == 16`). Populates `pe.version_info` with keys like
    `CompanyName`, `FileVersion`, `ProductName`, `OriginalFilename`."""
    for r in pe.resources:
        if not (isinstance(r.rtype, int) and r.rtype == 16):
            continue
        f_off = pe.rva_to_file_offset(r.rva)
        if f_off is None:
            continue
        if f_off + r.size > len(data):
            continue
        blob = data[f_off : f_off + r.size]
        try:
            _walk_versioninfo_node(blob, 0, pe.version_info, 0)
        except Exception:
            # Malformed VERSIONINFO; leave whatever we already extracted.
            continue


def init(target_bytes: bytes):
    """Splat platform entry point — called once per run with the full
    target file bytes. Parses the PE, stashes the result in the
    module-level `info` and `raw_image` globals (consulted by every
    segtype + the disassembler), and rejects architectures we don't
    have a Capstone backend for (ARM32 / ARM64 / unsupported machines)
    with a friendly error pointing the user at the limitation."""
    global info, raw_image
    info = parse_pe(target_bytes)
    raw_image = target_bytes
    if info.machine in (MACHINE_ARM64, MACHINE_ARM32):
        log.error(
            f"win32 target uses ARM architecture (machine 0x{info.machine:04X}); "
            "the splat win32 platform currently only supports x86 / x86_64 "
            "(Capstone-driven disassembly). PE structures parse cleanly but "
            "instruction decode would need a separate backend."
        )
    if info.machine not in (MACHINE_I386, MACHINE_AMD64):
        log.error(
            f"win32 target has unsupported machine type 0x{info.machine:04X} "
            "(only i386 / amd64 are recognized)"
        )
