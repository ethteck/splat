"""Win32 .text segment — x86 disassembly via capstone."""

import re
import struct
from pathlib import Path
from typing import Dict, Optional, Set

from ..common.segment import CommonSegment
from ...util import log, options
from ...util.symbols import Symbol


_HEX_RE = re.compile(r"\b0x([0-9a-fA-F]+)\b")

# Capstone, even in intel-syntax mode, emits some mnemonics with AT&T-style
# size suffixes that GAS doesn't recognize. Map them back to the canonical
# intel-syntax names. Trailing whitespace is significant (capstone often
# trails a space in the mnemonic field).
_MNEMONIC_REWRITES = {
    "popal": "popad",
    "pushal": "pushad",
    "popfd": "popfd",
    "pushfd": "pushfd",
}

# Mnemonics whose memory operand carries no GAS-usable size qualifier
# (state-save instructions span 94/108/512+ bytes — capstone tends to
# annotate the operand as `dword ptr` which GAS then rejects).
_SIZELESS_MEMORY_MNEMONICS = {
    "fnsave",
    "fsave",
    "fnstenv",
    "fstenv",
    "frstor",
    "fxsave",
    "fxrstor",
    "fxsave64",
    "fxrstor64",
}

# Capstone uses some older size-qualifier names; GAS prefers different
# spellings. Apply as a literal substring rewrite on the operand string.
_OPERAND_REWRITES = [
    ("xword ptr ", "tbyte ptr "),
    ("xmmword ptr ", "xmmword ptr "),  # no-op; placeholder for future
]

# Capstone uses `riz`/`eiz` to denote an absent index register in SIB
# expressions. GAS doesn't recognise either — strip them in every
# position they can appear: `+ riz*N` (middle/tail), `riz*N + ` (head).
_NO_INDEX_TAIL_RE = re.compile(r"\s*\+\s*[re]iz\*\d+")
_NO_INDEX_HEAD_RE = re.compile(r"\[[re]iz\*\d+\s*\+\s*")
_NO_INDEX_LONE_RE = re.compile(r"\[\s*[re]iz\*\d+\s*\]")

# SSE scalar instructions whose source memory operand is 8 bytes but
# capstone often labels as `xmmword ptr`. GAS wants `qword ptr` (or no
# qualifier).
_SCALAR_SSE_DOUBLE = {
    "comisd",
    "ucomisd",
    "addsd",
    "subsd",
    "mulsd",
    "divsd",
    "minsd",
    "maxsd",
    "sqrtsd",
    "cvtsi2sd",
    "cvtsd2si",
    "cvttsd2si",
    "cvtsd2ss",
    "movsd",
}
# SSE scalar single — 4-byte source.
_SCALAR_SSE_SINGLE = {
    "comiss",
    "ucomiss",
    "addss",
    "subss",
    "mulss",
    "divss",
    "minss",
    "maxss",
    "sqrtss",
    "cvtsi2ss",
    "cvtss2si",
    "cvttss2si",
    "cvtss2sd",
    "movss",
}
# Matches `[rip + 0xN]` / `[rip - 0xN]` / `[rip]` (the last when disp == 0
# — capstone elides the literal). Needed for PE32+ RIP-relative memory
# operands, where the absolute target = insn.address + insn.size + disp.
_RIP_REL_RE = re.compile(r"\[rip(?:\s*(?P<sign>[+-])\s*0x(?P<hex>[0-9a-fA-F]+))?\]")


class Win32SegText(CommonSegment):
    """Executable code segment.

    Two-pass disassembly through Capstone (x86 or x86_64 picked from
    `pe.is_pe32_plus`): the first pass walks every direct call/jmp
    target inside the segment to seed function / branch labels; the
    second emits instructions with operand strings rewritten so
    addresses, IAT slots, exports, and RIP-relative loads resolve
    to readable labels. GAS-incompatible Capstone outputs are
    rewritten to keep the `.s` output assemblable. With
    `exact_encoding: true`, instruction bytes are emitted verbatim
    (decoded mnemonic as a comment) so the output round-trips
    byte-identically through GAS+objcopy."""

    # Default class-level kill switch. Per-segment YAML can override via
    # `exact_encoding: true` to force byte-identical reassembly: every
    # instruction is emitted as a `.byte` directive carrying the original
    # bytes, with the decoded mnemonic moved to a trailing comment.
    # Disasm readability suffers (no label substitution in operands), but
    # round-trip through GAS produces byte-identical .text content.
    EXACT_ENCODING_DEFAULT = False

    @staticmethod
    def is_text() -> bool:
        return True

    def get_linker_section(self) -> str:
        return ".text"

    def get_section_flags(self) -> Optional[str]:
        return "ax"

    @property
    def exact_encoding(self) -> bool:
        from ...platforms.win32 import resolve_exact_encoding

        return resolve_exact_encoding(
            self.yaml, self.parent, self.EXACT_ENCODING_DEFAULT
        )

    def out_path(self) -> Path:
        return options.opts.asm_path / self.dir / f"{self.name}.s"

    def should_scan(self) -> bool:
        return (
            options.opts.is_mode_active("code")
            and self.rom_start is not None
            and self.rom_end is not None
        )

    def should_split(self) -> bool:
        return self.extract and self.should_scan()

    def split(self, rom_bytes: bytes):
        if self.rom_start is None or self.rom_end is None:
            return
        if self.rom_start == self.rom_end:
            return
        if not isinstance(self.vram_start, int):
            log.error(
                f"win32 text segment '{self.name}' requires a vram address; got {self.vram_start!r}"
            )

        from ...disassembler.capstone_disassembler import get_capstone_disassembler

        cs_disasm = get_capstone_disassembler()
        if cs_disasm is None:
            log.error(
                "win32 text segment requested but capstone disassembler is not active"
            )
        engine = cs_disasm.get_engine()

        data = rom_bytes[self.rom_start : self.rom_end]
        vram = self.vram_start

        out_path = self.out_path()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # If this segment maps cleanly onto a single PE section, trim the
        # decode range to the section's VirtualSize so the file-alignment
        # NUL padding at the tail doesn't get disassembled as thousands of
        # spurious `add [eax], al` lines. The trimmed bytes get emitted as
        # a single `.space` directive so the output round-trips.
        from ...platforms import win32 as _pe_mod

        _pe = _pe_mod.info
        _seg_rva = vram - _pe.image_base
        section = next(
            (
                s
                for s in _pe.sections
                if s.virtual_address == _seg_rva and s.raw_size > 0
            ),
            None,
        )
        decode_len = len(data)
        trailing_pad = 0
        if (
            section is not None
            and section.virtual_size < section.raw_size
            and section.virtual_size <= len(data)
        ):
            decode_len = section.virtual_size
            trailing_pad = len(data) - decode_len

        # Build a quick lookup of any user-declared symbols that fall inside
        # this segment so they show up as labels in the disassembly.
        seg_symbols: Dict[int, Optional[Symbol]] = {}
        for vram_addr, syms in self.seg_symbols.items():
            if self.vram_start <= vram_addr < (self.vram_start + len(data)):
                seg_symbols[vram_addr] = syms[0]
        # Also synthesize a label for the platform-level entry point if it
        # lands inside this segment.
        from ...platforms import win32 as win32_platform

        # `entry_point_rva == 0` for DLLs/EXEs with no entry point (e.g.,
        # resource-only DLLs). Treat 0 as "no entry" so we don't accidentally
        # label address 0 as `entrypoint`.
        entry_va = (
            win32_platform.info.entry_point_va
            if win32_platform.info.entry_point_rva
            else -1
        )
        if self.vram_start <= entry_va < (self.vram_start + len(data)):
            seg_symbols.setdefault(entry_va, None)

        # First pass: find every `call <imm>` / `jmp <imm>` / `j<cc> <imm>`
        # target that lands inside this segment so we can emit a label there
        # in the second pass. Use capstone's group info (detail=True is set
        # by CapstoneDisassembler.configure).
        import capstone

        # Disasm input restricted to the section's real content so we don't
        # waste cycles labelling addresses inside the alignment padding.
        decode_data = data[:decode_len]
        seg_end = vram + decode_len
        call_targets: Set[int] = set()
        jump_targets: Set[int] = set()

        # Seed call_targets with every pointer-relocation target that falls
        # inside this text segment. Data-driven references (vtables, indirect
        # call tables) are otherwise invisible to the call/jmp scan.
        # Pointer size matches the PE bitness — DIR64 relocs for PE32+ refer
        # to 8-byte slots; HIGHLOW for PE32 refers to 4-byte slots.
        _ptr_seed_size = 8 if win32_platform.info.is_pe32_plus else 4
        for rva in win32_platform.info.pointer_rvas:
            f_off = win32_platform.info.rva_to_file_offset(rva)
            if f_off is None or f_off + _ptr_seed_size > len(rom_bytes):
                continue
            tgt_val = int.from_bytes(
                rom_bytes[f_off : f_off + _ptr_seed_size], "little"
            )
            if vram <= tgt_val < seg_end:
                call_targets.add(tgt_val)
        # TLS callbacks land somewhere in .text but are not reached by any
        # direct call/jmp — seed them explicitly so their entries get labels.
        for cb in win32_platform.info.tls_callback_vas:
            if vram <= cb < seg_end:
                call_targets.add(cb)
        # Exports — for DLLs, an exported function may have no in-binary
        # callers (only external GetProcAddress users). Seed each export RVA
        # so the entry gets a func_<va> label; a `symbol_addrs.txt` entry,
        # if present, replaces that with the export's real name.
        for exp in win32_platform.info.exports:
            if exp.forwarder is not None:
                continue
            exp_va = win32_platform.info.image_base + exp.rva
            if vram <= exp_va < seg_end:
                call_targets.add(exp_va)
        # PE32+ Exception Directory entries give definitive function
        # boundaries — seed BeginAddress so SEH-only/cold-block entry
        # points get labels.
        for begin_rva, _end_rva, _uw_rva in win32_platform.info.runtime_functions:
            rf_va = win32_platform.info.image_base + begin_rva
            if vram <= rf_va < seg_end:
                call_targets.add(rf_va)
        # /SAFESEH handler functions are reachable only via the
        # IMAGE_LOAD_CONFIG_DIRECTORY's SEHandlerTable — not via any direct
        # call/jmp — so seed them explicitly.
        for handler_rva in win32_platform.info.safe_seh_handlers:
            handler_va = win32_platform.info.image_base + handler_rva
            if vram <= handler_va < seg_end:
                call_targets.add(handler_va)
        # /guard:cf — every entry is a known indirect-call target.
        for cfg_rva in win32_platform.info.cfg_function_rvas:
            cfg_va = win32_platform.info.image_base + cfg_rva
            if vram <= cfg_va < seg_end:
                call_targets.add(cfg_va)
        offset = 0
        data_len = decode_len
        while offset < data_len:
            advanced = False
            for insn in engine.disasm(decode_data[offset:], vram + offset):
                advanced = True
                offset = (insn.address + insn.size) - vram
                if not insn.operands:
                    continue
                op0 = insn.operands[0]
                if op0.type != capstone.CS_OP_IMM:
                    continue
                tgt = op0.imm
                if not (vram <= tgt < seg_end):
                    continue
                if insn.group(capstone.CS_GRP_CALL):
                    call_targets.add(tgt)
                elif insn.group(capstone.CS_GRP_JUMP):
                    jump_targets.add(tgt)
            if not advanced:
                offset += 1

        # Build a global-symbol lookup so we can annotate memory operands
        # that reach known data (IAT slots, exports, etc.) with a trailing
        # comment.
        from ...util import symbols as symbols_mod
        from .data import _is_string_byte, _escape_string

        pe = win32_platform.info
        _addr_mask = 0xFFFFFFFFFFFFFFFF if pe.is_pe32_plus else 0xFFFFFFFF

        # Identify single-instruction `jmp dword ptr [<iat>]` thunks at every
        # call_target so they can be renamed `<imp_name>_thunk` (or
        # `<imp_name>_thunk_<va>` if the same import has multiple thunks).
        # Map every IAT slot's VA (eager + delayed) to its canonical label.
        iat_to_label: Dict[int, str] = dict(win32_platform.compute_iat_labels(pe))

        # Pre-populate `synth_labels` with export and import names so DLLs
        # surface readable references (`call dword ptr [imp_..._CreateThread]`,
        # `Init:` label, etc.) without requiring a hand-authored
        # `symbol_addrs.txt`. The same map is consulted by both `label_for`
        # (label emission) and `resolve_sym` (op_str substitution).
        synth_labels: Dict[int, str] = {}
        export_labels = win32_platform.compute_export_labels(
            pe, reserved={"entrypoint"} if pe.entry_point_rva else set()
        )
        for va, safe in export_labels.items():
            if vram <= va < seg_end:
                synth_labels[va] = safe
        # Imports live in .rdata, not .text — but they're referenced from
        # within .text via absolute memory operands, so `resolve_sym` needs
        # to see them too. Reuse the same {slot_va: label} map computed
        # above for IAT-thunk renaming so labels stay in sync.
        synth_labels.update(iat_to_label)

        thunk_labels: Dict[int, str] = {}
        if iat_to_label:
            used: Dict[str, int] = {}
            rip_reg = capstone.x86.X86_REG_RIP if pe.is_pe32_plus else 0
            for target in sorted(call_targets):
                off = target - vram
                if off < 0 or off >= decode_len:
                    continue
                # Single-pass decode of one instruction from the call target.
                for insn in engine.disasm(decode_data[off:], target):
                    if insn.mnemonic != "jmp" or not insn.operands:
                        break
                    op0 = insn.operands[0]
                    if op0.type != capstone.CS_OP_MEM:
                        break
                    if op0.mem.index != 0 or op0.mem.segment != 0:
                        break
                    if pe.is_pe32_plus:
                        # PE32+ thunk: `jmp qword ptr [rip + disp]`.
                        # IAT slot VA = next_ip + disp.
                        if op0.mem.base != rip_reg:
                            break
                        slot_va = (insn.address + insn.size + op0.mem.disp) & _addr_mask
                    else:
                        # PE32 thunk: `jmp dword ptr [imm32]`. No base.
                        if op0.mem.base != 0:
                            break
                        slot_va = op0.mem.disp & _addr_mask
                    iat_label = iat_to_label.get(slot_va)
                    if iat_label is None:
                        break
                    base = f"{iat_label}_thunk"
                    count = used.get(base, 0)
                    used[base] = count + 1
                    final = base if count == 0 else f"{base}_{target:08X}"
                    thunk_labels[target] = final
                    break

        def section_for(va: int):
            rva = va - pe.image_base
            for s in pe.sections:
                sec_end = s.virtual_address + max(s.virtual_size, s.raw_size)
                if s.virtual_address <= rva < sec_end:
                    return s
            return None

        def peek_string(va: int) -> Optional[str]:
            s = section_for(va)
            if s is None or s.raw_size == 0:
                return None
            offset_in_section = (va - pe.image_base) - s.virtual_address
            # Reject VAs in the section's virtual-only tail — those have no
            # backing bytes; reading would step into the next section.
            if offset_in_section >= s.raw_size:
                return None
            file_off = s.raw_pointer + offset_in_section
            if file_off >= len(rom_bytes):
                return None
            limit = min(64, len(rom_bytes) - file_off)
            chunk = rom_bytes[file_off : file_off + limit]
            end = 0
            while end < len(chunk) and _is_string_byte(chunk[end]):
                end += 1
            if end < 4 or end >= len(chunk) or chunk[end] != 0:
                return None
            text = _escape_string(chunk[:end])
            # Escape `*/` to avoid prematurely terminating the GAS C-style
            # comment we're going to wrap this preview in.
            text = text.replace("*/", "*\\/")
            return f'"{text}"'

        def resolve_sym(addr: int) -> Optional[str]:
            if addr in thunk_labels:
                return thunk_labels[addr]
            entries = symbols_mod.all_symbols_dict.get(addr)
            if entries:
                return entries[0].name
            if addr in synth_labels:
                return synth_labels[addr]
            if addr == entry_va:
                return "entrypoint"
            if addr in call_targets:
                return f"func_{addr:08X}"
            if addr in jump_targets:
                return f"loc_{addr:08X}"
            s = section_for(addr)
            if s is None:
                return None
            if s.is_code:
                # Cross-segment code references resolve to `func_<va>` —
                # matches the naming convention the target segment will
                # emit when it builds its own call_targets set, so the
                # label resolves at link time across .o files.
                return f"func_{addr:08X}"
            return f"D_{addr:08X}"

        def substitute_op_str(insn) -> str:
            """Replace hex literals in `insn.op_str` with their resolved
            labels, in-place. Leaves the original string alone when no
            literal resolves to a known address — so register-relative
            offsets like `[esp + 0x58]` survive untouched.

            For non-branch instructions (mov/push/lea/etc.) where the hex
            literal is an immediate operand, the substitution uses the
            `offset <label>` form so GAS treats the operand as the label's
            address rather than as a memory load."""

            op_str = insn.op_str
            # PE32+ RIP-relative: compute absolute target and substitute
            # the entire `[rip + 0xN]` token if it resolves.
            next_ip = insn.address + insn.size

            def rip_repl(match: "re.Match") -> str:
                # `[rip]` with no displacement → disp = 0.
                hex_grp = match.group("hex")
                disp = int(hex_grp, 16) if hex_grp else 0
                if match.group("sign") == "-":
                    disp = -disp
                target = (next_ip + disp) & 0xFFFFFFFFFFFFFFFF
                name = resolve_sym(target)
                if name is None:
                    return match.group(0)
                return f"[{name}]"

            op_str = _RIP_REL_RE.sub(rip_repl, op_str)

            # Avoid substituting hex literals that fall outside the loaded
            # image (stack offsets, small immediate constants, etc.). Any
            # real symbol address sits at ≥ ImageBase by construction.
            image_min = pe.image_base
            image_max = pe.image_base + pe.size_of_image

            is_branch = bool(
                insn.group(capstone.CS_GRP_CALL) or insn.group(capstone.CS_GRP_JUMP)
            )

            # `mov reg, imm` / `mov [mem], imm` / `push imm` need `offset`
            # in GAS intel-syntax so the assembler treats the label as an
            # immediate address rather than as a memory load.
            def repl(match: "re.Match") -> str:
                value = int(match.group(1), 16)
                if not (image_min <= value < image_max):
                    return match.group(0)
                name = resolve_sym(value)
                if name is None:
                    return match.group(0)
                if is_branch:
                    return name
                # Only add `offset` when the substituted token is sitting in
                # an "immediate slot" — i.e., NOT inside square brackets.
                start = match.start()
                # Walk back to find the most recent `[` or `]`; whichever
                # is closer to the match tells us whether we're inside [].
                close = op_str.rfind("]", 0, start)
                openb = op_str.rfind("[", 0, start)
                inside_brackets = openb > close
                if inside_brackets:
                    # If the hex is preceded by `+ ` or `- ` inside the
                    # brackets, it's a displacement in a register-relative
                    # expression (`[reg + 0xN]`); the value is a constant
                    # offset, not an address — substituting would yield
                    # an "*ABS* - *UND*" link error. Keep raw.
                    #
                    # Exception: `[reg*N + 0xADDR]` is jump-table dispatch
                    # where the displacement IS the table base, so we DO
                    # substitute when the sign is `+`. `[reg*N - 0xADDR]`
                    # never has a meaningful symbolic interpretation, so
                    # keep raw regardless.
                    preceding = op_str[openb + 1 : start].rstrip()
                    if preceding and preceding[-1] == "-":
                        return match.group(0)
                    if (
                        preceding
                        and preceding[-1] == "+"
                        and "*" not in op_str[openb + 1 : start]
                    ):
                        return match.group(0)
                    return name
                return f"offset {name}"

            return _HEX_RE.sub(repl, op_str)

        def operand_comments(insn) -> str:
            """Render a tail-of-line `/* ... */` comment when an operand
            carries information that's NOT already encoded by the
            substituted op_str — primarily inline string previews for
            data pointers. The plain `0x...=label` mapping is suppressed
            because `substitute_op_str` already swaps the hex for the
            label in the visible instruction text."""
            notes: list = []
            seen: Set[int] = set()
            for op in insn.operands:
                if op.type == capstone.CS_OP_IMM:
                    imm = op.imm & _addr_mask
                    if imm in seen:
                        continue
                    text = peek_string(imm)
                    if text is None:
                        continue
                    notes.append(f"{imm:#x} {text}")
                    seen.add(imm)
                elif op.type == capstone.CS_OP_MEM:
                    # Absolute (32-bit) memory operand.
                    if op.mem.base == 0 and op.mem.index == 0 and op.mem.segment == 0:
                        addr = op.mem.disp & _addr_mask
                        if addr in seen:
                            continue
                        text = peek_string(addr)
                        if text is None:
                            continue
                        notes.append(f"[{addr:#x}] {text}")
                        seen.add(addr)
                        continue
                    # PE32+ RIP-relative: compute absolute target; surface
                    # a string preview if it points at one.
                    if op.mem.base != 0:
                        try:
                            reg_name = insn.reg_name(op.mem.base) or ""
                        except Exception:
                            reg_name = ""
                        if (
                            reg_name == "rip"
                            and op.mem.index == 0
                            and op.mem.segment == 0
                        ):
                            target = (
                                insn.address + insn.size + op.mem.disp
                            ) & 0xFFFFFFFFFFFFFFFF
                            if target in seen:
                                continue
                            text = peek_string(target)
                            if text is None:
                                continue
                            notes.append(f"[rip→0x{target:x}] {text}")
                            seen.add(target)
            if not notes:
                return ""
            return "  /* " + ", ".join(notes) + " */"

        def label_for(addr: int) -> str:
            if addr in thunk_labels:
                return thunk_labels[addr]
            sym = seg_symbols.get(addr)
            if sym is not None:
                return sym.name
            if addr in synth_labels:
                return synth_labels[addr]
            if addr == entry_va:
                return "entrypoint"
            if addr in call_targets:
                return f"func_{addr:08X}"
            return f"loc_{addr:08X}"

        labelled: Set[int] = set(seg_symbols) | call_targets | jump_targets

        exact = self.exact_encoding

        with out_path.open("w", encoding="utf-8", newline="\n") as f:
            preamble = options.opts.generated_s_preamble
            if preamble:
                f.write(preamble + "\n\n")
            f.write(self.get_section_asm_line() + "\n\n")
            if not exact:
                # `.intel_syntax noprefix` only matters when we emit
                # actual mnemonics; exact-encoding mode emits raw bytes.
                f.write(".intel_syntax noprefix\n")
            f.write(f".global {self.name}\n")
            f.write(f"{self.name}:\n")

            # Walk the byte range forward. Capstone stops on the first
            # undecodable instruction; emit the bad byte as `.byte` data and
            # resume one byte later so jump-tables / embedded data inside
            # real-world .text sections don't truncate the disassembly.
            #
            # Runs of int3 (0xCC) or nop (0x90) ≥ 2 bytes are collapsed into
            # a single `.byte` line — MSVC pads between functions with these
            # so the saving is large in real-world binaries.
            # Pre-compute the set of offsets inside this segment where the
            # base-relocation table marks an embedded 32-bit pointer. These
            # are typically MSVC switch jump-tables or function-pointer
            # tables that live inside `.text` itself; we must emit them as
            # `.long <label>` rather than disassembling them as code.
            ptr_size, ptr_fmt, ptr_directive, _ = win32_platform.ptr_layout(
                pe.is_pe32_plus
            )
            seg_start_rva = vram - pe.image_base
            seg_end_rva = seg_start_rva + decode_len
            embedded_ptr_offsets: Set[int] = set()
            for rva in pe.pointer_rvas:
                if seg_start_rva <= rva < seg_end_rva:
                    embedded_ptr_offsets.add(rva - seg_start_rva)

            offset = 0
            while offset < data_len:
                # Embedded pointer slot: emit as `.long` (or `.quad`) and
                # advance past the slot without invoking capstone.
                if offset in embedded_ptr_offsets and offset + ptr_size <= data_len:
                    here_va = vram + offset
                    # Anchor the label first if anything references this
                    # slot — switch-jump dispatch loads `[<table> + idx*4]`
                    # via the table-base address.
                    if here_va in labelled:
                        is_func = (
                            here_va in seg_symbols
                            or here_va == entry_va
                            or here_va in call_targets
                        )
                        if is_func:
                            f.write(f"\n.global {label_for(here_va)}\n")
                        f.write(f"{label_for(here_va)}:\n")
                    tgt = struct.unpack_from(ptr_fmt, decode_data, offset)[0]
                    ptr_label: Optional[str] = (
                        None if exact else (resolve_sym(tgt) if tgt else None)
                    )
                    if ptr_label is not None:
                        f.write(
                            f"    {ptr_directive} {ptr_label}  /* 0x{here_va:08X} = 0x{tgt:X} */\n"
                        )
                    else:
                        f.write(
                            f"    {ptr_directive} 0x{tgt:X}  /* 0x{here_va:08X} */\n"
                        )
                    offset += ptr_size
                    continue
                # Check for a run of padding bytes that isn't broken by a
                # labelled address we still need to anchor.
                if decode_data[offset] in (0xCC, 0x90):
                    pad = decode_data[offset]
                    run = 1
                    while (
                        offset + run < data_len
                        and decode_data[offset + run] == pad
                        and (vram + offset + run) not in labelled
                    ):
                        run += 1
                    if run >= 2:
                        kind = "int3" if pad == 0xCC else "nop"
                        f.write(
                            "    .byte "
                            + ", ".join([f"0x{pad:02X}"] * run)
                            + f"  /* 0x{vram + offset:08X} ({run}× {kind} padding) */\n"
                        )
                        offset += run
                        continue

                produced_any = False
                for insn in engine.disasm(decode_data[offset:], vram + offset):
                    if insn.address in labelled:
                        # Function-style label gets a `.global` line so it can
                        # be linked against; local block labels do not.
                        is_func = (
                            insn.address in seg_symbols
                            or insn.address == entry_va
                            or insn.address in call_targets
                        )
                        if is_func:
                            f.write(f"\n.global {label_for(insn.address)}\n")
                        f.write(f"{label_for(insn.address)}:\n")
                    raw_mnem = insn.mnemonic.strip()
                    if exact:
                        # Byte-identical mode: emit the original bytes as
                        # `.byte` directives, with the decoded instruction
                        # in a trailing comment for readability.
                        insn_bytes = bytes(insn.bytes)
                        hexed = ", ".join(f"0x{b:02X}" for b in insn_bytes)
                        f.write(
                            f"    .byte {hexed}"
                            f"  /* 0x{insn.address:08X}: "
                            f"{raw_mnem} {insn.op_str}".rstrip()
                            + " */\n"
                        )
                    else:
                        rendered_ops = substitute_op_str(insn)
                        mnemonic = _MNEMONIC_REWRITES.get(raw_mnem, insn.mnemonic)
                        # Drop GAS-incompatible size qualifiers on operands
                        # of state-save instructions; translate older names.
                        if raw_mnem in _SIZELESS_MEMORY_MNEMONICS:
                            rendered_ops = re.sub(
                                r"\b(?:byte|word|dword|qword|tbyte|xword) ptr ",
                                "",
                                rendered_ops,
                            )
                        for old, new in _OPERAND_REWRITES:
                            rendered_ops = rendered_ops.replace(old, new)
                        # Strip capstone's `riz`/`eiz` "no index" placeholder
                        # — GAS doesn't recognise either. Cover all three
                        # positional forms.
                        rendered_ops = _NO_INDEX_TAIL_RE.sub("", rendered_ops)
                        rendered_ops = _NO_INDEX_HEAD_RE.sub("[", rendered_ops)
                        rendered_ops = _NO_INDEX_LONE_RE.sub("[0]", rendered_ops)
                        # Scalar SSE doubles want `qword ptr`, not capstone's
                        # `xmmword ptr`; scalar singles want `dword ptr`.
                        if raw_mnem in _SCALAR_SSE_DOUBLE:
                            rendered_ops = rendered_ops.replace(
                                "xmmword ptr ", "qword ptr "
                            )
                        elif raw_mnem in _SCALAR_SSE_SINGLE:
                            rendered_ops = rendered_ops.replace(
                                "xmmword ptr ", "dword ptr "
                            )
                        # `enter imm16, imm8` rejects signed negative second
                        # operands in GAS intel-syntax; normalise to unsigned.
                        if raw_mnem == "enter":
                            rendered_ops = re.sub(
                                r"-0x([0-9a-fA-F]+)",
                                lambda m: f"0x{(0x100 - int(m.group(1), 16)) & 0xFF:X}",
                                rendered_ops,
                            )
                        f.write(
                            f"    {mnemonic} {rendered_ops}".rstrip()
                            + f"  /* 0x{insn.address:08X} */"
                            + operand_comments(insn)
                            + "\n"
                        )
                    offset = (insn.address + insn.size) - vram
                    produced_any = True
                    # If we're about to walk into a padding run or an
                    # embedded pointer slot, hand control back to the outer
                    # loop so it can render that range directly.
                    if offset < data_len:
                        if (
                            decode_data[offset] in (0xCC, 0x90)
                            and (vram + offset) not in labelled
                        ):
                            break
                        if offset in embedded_ptr_offsets:
                            break
                if offset >= data_len:
                    break
                if not produced_any:
                    f.write(
                        f"    .byte 0x{decode_data[offset]:02X}  /* 0x{vram + offset:08X} (undecodable) */\n"
                    )
                    offset += 1

            if trailing_pad > 0:
                # In exact_encoding mode preserve the actual padding
                # bytes — MSVC linkers fill .text tail with 0xCC, not
                # zero. `.space` would zero them.
                if exact:
                    pad_bytes = data[decode_len : decode_len + trailing_pad]
                    hexed = ", ".join(f"0x{b:02X}" for b in pad_bytes)
                    f.write(
                        f"\n    .byte {hexed}  /* {trailing_pad} bytes file-alignment padding */\n"
                    )
                else:
                    f.write(
                        f"\n    .space 0x{trailing_pad:X}  /* file-alignment padding */\n"
                    )

        self.log(f"Wrote {self.name} to {out_path}")

        # Sidecar index file: `<segname>.functions.txt` next to the .s file.
        # Lists every function-style label and its byte length so callers can
        # navigate the huge text dump without grepping it.
        func_starts = sorted(
            set(call_targets)
            | set(seg_symbols.keys())
            | ({entry_va} if vram <= entry_va < seg_end else set())
        )
        end_marker = vram + decode_len
        addr_width = 16 if pe.is_pe32_plus else 8

        # Pre-compute kind-source sets so the per-entry lookup is O(1).
        _export_vas = {pe.image_base + e.rva for e in pe.exports if e.forwarder is None}
        _tls_vas = set(pe.tls_callback_vas)
        _seh_vas = {pe.image_base + rva for rva in pe.safe_seh_handlers}
        _cfg_vas = {pe.image_base + rva for rva in pe.cfg_function_rvas}
        _rt_vas = {pe.image_base + begin for begin, _e, _u in pe.runtime_functions}

        def kind_for(addr: int) -> str:
            if addr in thunk_labels:
                return "thunk"
            if addr in seg_symbols and seg_symbols[addr] is not None:
                return "decl"
            if addr in _export_vas:
                return "export"
            if addr == entry_va:
                return "entry"
            if addr in _tls_vas:
                return "tls"
            if addr in _seh_vas:
                return "seh"
            if addr in _cfg_vas:
                return "cfg"
            if addr in _rt_vas:
                return "rt"
            return "func"

        idx_path = out_path.with_suffix(".functions.txt")
        with idx_path.open("w", encoding="utf-8", newline="\n") as idx:
            idx.write(f"# segment: {self.name}\n")
            idx.write("# columns: VA(hex)  size(decimal bytes)  kind  label\n")
            for i, addr in enumerate(func_starts):
                next_addr = (
                    func_starts[i + 1] if i + 1 < len(func_starts) else end_marker
                )
                size = next_addr - addr
                idx.write(
                    f"0x{addr:0{addr_width}X}  {size:>8d}  {kind_for(addr):<6s}  {label_for(addr)}\n"
                )
        self.log(f"Wrote function index to {idx_path}")
