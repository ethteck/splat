"""Win32 .data segment — dumped as a `.byte` block so it can be reassembled
without depending on spimdisasm's data analyzer."""

import struct
from pathlib import Path
from typing import List, Optional

from ..common.segment import CommonSegment
from ...util import options


# Minimum length (excluding the NUL terminator) of an ASCII run that should
# be emitted as `.asciz` rather than raw bytes.
STRING_MIN_LEN = 4


def _is_string_byte(b: int) -> bool:
    # ASCII control/printable subset OR Latin-1 Supplement printables.
    # Mirrors the wide-string scanner; covers localised ANSI resources
    # written in Western European code pages.
    return b == 0x09 or b == 0x0A or b == 0x0D or 0x20 <= b <= 0x7E or 0xA0 <= b <= 0xFF


def _escape_string(raw: bytes) -> str:
    out = []
    for b in raw:
        if b == ord('"'):
            out.append('\\"')
        elif b == ord("\\"):
            out.append("\\\\")
        elif b == 0x0A:
            out.append("\\n")
        elif b == 0x0D:
            out.append("\\r")
        elif b == 0x09:
            out.append("\\t")
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def _scan_string(data: bytes, start: int) -> Optional[int]:
    """If a printable run beginning at `start` and ending in a NUL byte is
    at least STRING_MIN_LEN characters long, return the end offset (one
    past the NUL). Otherwise return None."""
    i = start
    while i < len(data) and _is_string_byte(data[i]):
        i += 1
    if i >= len(data) or data[i] != 0:
        return None
    if (i - start) < STRING_MIN_LEN:
        return None
    return i + 1


# Minimum length in WCHARs (excluding the WCHAR NUL terminator) for a
# UTF-16LE string to be recognised as such.
WIDE_STRING_MIN_LEN = 4


def _scan_wide_string(data: bytes, start: int) -> Optional[int]:
    """Detect a UTF-16LE printable run terminated by `\\x00\\x00`. Returns
    the end offset (one past the terminating WCHAR), or None when no
    valid wide string of sufficient length is present.

    Only matches at even offsets — WCHAR strings are 2-byte aligned."""
    if start & 1:
        return None
    i = start
    count = 0
    while i + 1 < len(data):
        lo, hi = data[i], data[i + 1]
        if hi != 0:
            # Cautious: reject non-Latin-1 to avoid false positives.
            return None
        if lo == 0:
            # WCHAR terminator.
            break
        # ASCII control/printable subset OR Latin-1 supplement printables
        # (0xA0–0xFF, NBSP through ÿ). Covers German umlauts, accented
        # French chars, Spanish ñ, etc. — common in localised resources.
        if not (_is_string_byte(lo) or 0xA0 <= lo <= 0xFF):
            return None
        count += 1
        i += 2
    if i + 1 >= len(data):
        return None
    if data[i] != 0 or data[i + 1] != 0:
        return None
    if count < WIDE_STRING_MIN_LEN:
        return None
    return i + 2


def _decode_wide(raw: bytes) -> str:
    """Decode a WCHAR string body (no terminator) into a printable form
    using the same escapes as `_escape_string`."""
    try:
        s = raw.decode("utf-16-le", errors="replace")
    except Exception:
        s = ""
    out = []
    for ch in s:
        b = ord(ch)
        if b == ord('"'):
            out.append('\\"')
        elif b == ord("\\"):
            out.append("\\\\")
        elif b == 0x0A:
            out.append("\\n")
        elif b == 0x0D:
            out.append("\\r")
        elif b == 0x09:
            out.append("\\t")
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\u{b:04x}")
    return "".join(out)


class Win32SegData(CommonSegment):
    """Writable initialised data segment (`.data` in MASM lingo).

    Emits a `.byte` / `.long` / `.quad` representation of the
    section bytes. Detects:
    - pointer slots flagged by base-relocations (and synthesises a
      `func_<va>` / `D_<va>` label for the target);
    - NUL-terminated printable strings → `.asciz`;
    - UTF-16LE wide-string runs → preserved as raw bytes with a
      `/* L"..." */` preview comment;
    - long zero runs → collapsed into `.space N` directives.
    `exact_encoding: true` in the YAML disables every heuristic so
    bytes pass through verbatim."""

    LINKER_SECTION = ".data"
    SECTION_FLAGS = "wa"
    # Detect printable NUL-terminated runs and emit them as `.asciz`.
    # Enabled by default; .data has plenty of CRT strings, source paths,
    # and format strings worth surfacing. The min-length filter (see
    # `data._scan_string`) keeps the false-positive rate low.
    DETECT_STRINGS = True
    # When the PE has no .reloc table (RELOCS_STRIPPED EXEs) we have no
    # ground truth for what bytes are pointers. Subclasses that opt in get
    # a heuristic scan: any 4-byte-aligned word whose value falls inside an
    # image section is treated as a pointer. Off by default to avoid
    # rewriting integer data as bogus pointers.
    HEURISTIC_POINTERS = False

    @property
    def exact_encoding(self) -> bool:
        """When enabled, pointer slots emit raw `.long 0xN` / `.quad 0xN`
        instead of `.long <label>`, and strings are NOT extracted (every
        byte stays as `.byte`). Result: byte-identical .data after a
        standalone `as` assembly (no linker required to resolve labels).
        Inherits from parent code-group YAML if not set per-subsegment."""
        from ...platforms.win32 import resolve_exact_encoding

        return resolve_exact_encoding(self.yaml, self.parent)

    @staticmethod
    def is_data() -> bool:
        return True

    def get_linker_section(self) -> str:
        return self.LINKER_SECTION

    def get_section_flags(self) -> Optional[str]:
        return self.SECTION_FLAGS

    def out_path(self) -> Path:
        return options.opts.data_path / self.dir / f"{self.name}.s"

    def should_split(self) -> bool:
        return (
            self.extract
            and options.opts.is_mode_active("code")
            and self.rom_start is not None
            and self.rom_end is not None
        )

    # Minimum length of an all-zero run before we collapse it into a
    # single `.space` directive.
    ZERO_RUN_MIN = 8

    def _emit_byte_chunk(self, data: bytes, start: int, end: int) -> List[str]:
        """Emit bytes in 16-byte rows, collapsing any run of NULs of length
        ≥ ZERO_RUN_MIN into a single `.space N` line."""
        lines: List[str] = []
        i = start
        pending_start = start
        while i < end:
            # Detect a NUL run starting at `i`.
            if data[i] == 0:
                j = i
                while j < end and data[j] == 0:
                    j += 1
                if j - i >= self.ZERO_RUN_MIN:
                    # Flush any non-zero bytes that came before the run.
                    if pending_start < i:
                        for k in range(pending_start, i, 16):
                            chunk = data[k : min(k + 16, i)]
                            hexed = ", ".join(f"0x{b:02X}" for b in chunk)
                            lines.append(f"    .byte {hexed}")
                    lines.append(f"    .space 0x{j - i:X}")
                    i = j
                    pending_start = i
                    continue
                # Sub-threshold zero run — skip past the whole thing
                # rather than re-scanning every byte; saves O(MIN * N) on
                # data with many short zero clusters.
                i = j
                continue
            i += 1
        if pending_start < end:
            for k in range(pending_start, end, 16):
                chunk = data[k : min(k + 16, end)]
                hexed = ", ".join(f"0x{b:02X}" for b in chunk)
                lines.append(f"    .byte {hexed}")
        return lines

    def _pointer_offsets(self, data: bytes) -> List[int]:
        """Offsets (within `data`) where a 32-bit pointer lives.

        Prefers the PE Base Relocation Table when present. Falls back to a
        heuristic scan — opt-in via `HEURISTIC_POINTERS` — that classifies
        any 4-byte-aligned word as a pointer when its value lands inside an
        image section."""
        if self.vram_start is None:
            return []
        from ...platforms import win32 as win32_platform

        pe = win32_platform.info
        data_len = len(data)
        seg_start_rva = self.vram_start - pe.image_base
        seg_end_rva = seg_start_rva + data_len

        if pe.pointer_rvas:
            return sorted(
                rva - seg_start_rva
                for rva in pe.pointer_rvas
                if seg_start_rva <= rva < seg_end_rva
            )

        if not self.HEURISTIC_POINTERS:
            return []

        # Heuristic scan. Restrict candidates to values that target a code
        # section — pointer tables we care about in stripped EXEs (vtables,
        # jump tables) all point at executable code, and the alternative
        # (accept any image-resident value) yields too many false positives
        # from 4-character tags and ID constants.
        code_ranges = [
            (
                pe.image_base + s.virtual_address,
                pe.image_base + s.virtual_address + max(s.virtual_size, s.raw_size),
            )
            for s in pe.sections
            if s.is_code
        ]
        if not code_ranges:
            return []
        # Plausible x86 function-prologue first-bytes. Reduces heuristic
        # false positives (ASCII 4-char tags etc. happen to look like
        # in-image pointers but never point at a real instruction start).
        prologue_first_bytes = {
            0x50,
            0x51,
            0x52,
            0x53,
            0x54,
            0x55,
            0x56,
            0x57,  # push r32
            0x6A,
            0x68,  # push imm
            0x80,
            0x81,
            0x83,  # ALU r/m, imm
            0x8B,
            0x89,
            0x8A,
            0x88,  # mov r/m, ...
            0x8C,
            0x8E,  # mov sreg/r
            0x8D,  # lea
            0xB0,
            0xB1,
            0xB2,
            0xB3,
            0xB4,
            0xB5,
            0xB6,
            0xB7,  # mov r8, imm8
            0xB8,
            0xB9,
            0xBA,
            0xBB,
            0xBC,
            0xBD,
            0xBE,
            0xBF,  # mov r32, imm32
            0xC6,
            0xC7,  # mov r/m, imm
            0xE8,
            0xE9,  # call/jmp rel32
            0xFF,  # call/jmp [...]
            0xC2,
            0xC3,  # ret (leaf)
            0xCB,
            0xCA,  # retf
            0xCC,  # int3
            0xEB,  # short jmp
            0x33,
            0x31,  # xor reg, reg
            0x0F,  # two-byte op
            0x66,  # opsize prefix
            0x64,
            0x65,  # fs/gs prefix
            0x67,  # addrsize prefix
            0xF2,
            0xF3,  # rep / repne prefix
            0xF6,
            0xF7,  # test/not/neg r/m
            0x40,
            0x41,
            0x42,
            0x43,
            0x44,
            0x45,
            0x46,
            0x47,  # inc r32 (32-bit) / REX (64-bit)
            0x48,
            0x49,
            0x4A,
            0x4B,
            0x4C,
            0x4D,
            0x4E,
            0x4F,  # dec r32 (32-bit) / REX.W+ (64-bit)
            0xA0,
            0xA1,
            0xA2,
            0xA3,  # mov mov al/eax, [mem]
            0xD8,
            0xD9,
            0xDA,
            0xDB,
            0xDC,
            0xDD,
            0xDE,
            0xDF,  # FPU x87 group
            0xF8,
            0xF9,
            0xFA,
            0xFB,
            0xFC,
            0xFD,  # clc/stc/cli/sti/cld/std (rare leaf)
        }
        offsets: List[int] = []
        ptr_size, ptr_fmt, _, _ = win32_platform.ptr_layout(pe.is_pe32_plus)
        start = (-self.vram_start) & (ptr_size - 1)

        def looks_like_function(target: int) -> bool:
            rva = target - pe.image_base
            f_off = pe.rva_to_file_offset(rva)
            if f_off is None or f_off >= len(win32_platform.raw_image):
                return False
            return win32_platform.raw_image[f_off] in prologue_first_bytes

        for i in range(start, data_len - (ptr_size - 1), ptr_size):
            value = struct.unpack_from(ptr_fmt, data, i)[0]
            if not any(lo <= value < hi for lo, hi in code_ranges):
                continue
            if not looks_like_function(value):
                continue
            offsets.append(i)
        return offsets

    def _resolve_pointer(self, va: int) -> Optional[str]:
        from ...util import symbols as symbols_mod
        from ...platforms import win32 as win32_platform

        entries = symbols_mod.all_symbols_dict.get(va)
        if entries:
            return entries[0].name

        # No declared symbol — synthesise one based on which section the
        # pointer lands in. Matches the labels Win32SegText auto-emits at
        # every direct call target.
        pe = win32_platform.info
        rva = va - pe.image_base
        for section in pe.sections:
            sec_end = section.virtual_address + max(
                section.virtual_size, section.raw_size
            )
            if section.virtual_address <= rva < sec_end:
                if section.is_code:
                    return f"func_{va:08X}"
                return f"D_{va:08X}"
        return None

    def _dump_with_strings_and_pointers(
        self, data: bytes, pointer_offsets: List[int]
    ) -> List[str]:
        """Mix `.asciz` strings (if DETECT_STRINGS) and `.long`/`.quad`
        pointers in with the usual `.byte` block. Pointers always win over
        byte runs; strings win when no pointer overlaps."""
        from ...platforms import win32 as win32_platform

        ptr_size, ptr_fmt, ptr_directive, ptr_width = win32_platform.ptr_layout(
            win32_platform.info.is_pe32_plus
        )

        ptr_set = set(pointer_offsets)
        lines: List[str] = []
        n = len(data)
        i = 0
        chunk_start = 0

        def flush_chunk(upto: int) -> None:
            if chunk_start < upto:
                lines.extend(self._emit_byte_chunk(data, chunk_start, upto))

        exact = self.exact_encoding
        while i < n:
            if i in ptr_set and i + ptr_size <= n:
                flush_chunk(i)
                raw = struct.unpack_from(ptr_fmt, data, i)[0]
                target = None if exact else self._resolve_pointer(raw)
                if target is not None:
                    lines.append(
                        f"    {ptr_directive} {target}  /* 0x{raw:0{ptr_width}X} */"
                    )
                else:
                    lines.append(f"    {ptr_directive} 0x{raw:0{ptr_width}X}")
                i += ptr_size
                chunk_start = i
                continue
            if self.DETECT_STRINGS and not exact:
                end = _scan_string(data, i)
                # Reject the string if it would straddle a pointer slot.
                if end is not None and not any(i <= p < end for p in ptr_set):
                    flush_chunk(i)
                    text = _escape_string(data[i : end - 1])
                    lines.append(f'    .asciz "{text}"')
                    i = end
                    chunk_start = i
                    continue
                # UTF-16LE wide string (e.g. Windows API L"..." literals).
                w_end = _scan_wide_string(data, i)
                if w_end is not None and not any(i <= p < w_end for p in ptr_set):
                    flush_chunk(i)
                    body = data[i : w_end - 2]
                    text = _decode_wide(body)
                    # Emit as raw bytes so the layout round-trips byte-for-
                    # byte even when GAS's `.string16` directive is absent.
                    lines.append(f'    /* L"{text}" */')
                    bb = ", ".join(f"0x{b:02X}" for b in data[i:w_end])
                    lines.append(f"    .byte {bb}")
                    i = w_end
                    chunk_start = i
                    continue
            i += 1
        flush_chunk(n)
        return lines

    def split(self, rom_bytes: bytes):
        if self.rom_start is None or self.rom_end is None:
            return
        if self.rom_start == self.rom_end:
            return

        path = self.out_path()
        path.parent.mkdir(parents=True, exist_ok=True)

        data = rom_bytes[self.rom_start : self.rom_end]
        pointer_offsets = self._pointer_offsets(data)
        if pointer_offsets or self.DETECT_STRINGS:
            body_lines = self._dump_with_strings_and_pointers(data, pointer_offsets)
        else:
            body_lines = self._emit_byte_chunk(data, 0, len(data))

        with path.open("w", encoding="utf-8", newline="\n") as f:
            preamble = options.opts.generated_s_preamble
            if preamble:
                f.write(preamble + "\n\n")
            f.write(self.get_section_asm_line() + "\n\n")
            f.write(f".global {self.name}\n")
            f.write(f"{self.name}:\n")
            for line in body_lines:
                f.write(line + "\n")

        self.log(f"Wrote {self.name} to {path}")
