from typing import Optional, Set
import os
import re
import sys
from collections import OrderedDict
from pathlib import Path

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN
from capstone.mips import *

from segtypes.segment import Segment
from util import options
from util import symbols
from util.symbols import Symbol


class N64SegCode(Segment):
    double_mnemonics = ["ldc1", "sdc1"]
    word_mnemonics = ["addiu", "sw", "lw", "jtbl"]
    float_mnemonics = ["lwc1", "swc1"]
    short_mnemonics = ["addiu", "lh", "sh", "lhu"]
    byte_mnemonics = ["lb", "sb", "lbu"]

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)
    md.detail = True
    md.skipdata = True

    def __init__(self, segment, rom_start, rom_end):
        super().__init__(segment, rom_start, rom_end)

        self.reported_file_split = False
        self.labels_to_add = set()
        self.jtbl_glabels_to_add = set()
        self.jtbl_jumps = {}
        self.jumptables = {}

        self.rodata_syms = {}
        self.needs_symbols = True

    defined_funcs: Set[str] = set()
    
    STRIP_C_COMMENTS_RE = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )

    C_FUNC_RE = re.compile(
        r"^(static\s+)?[^\s]+\s+([^\s(]+)\(([^;)]*)\)[^;]+?{",
        re.MULTILINE
    )

    @staticmethod
    def strip_c_comments(text):
        def replacer(match):
            s = match.group(0)
            if s.startswith("/"):
                return " "
            else:
                return s
        return re.sub(N64SegCode.STRIP_C_COMMENTS_RE, replacer, text)

    @staticmethod
    def get_standalone_asm_header():
        ret = []

        ret.append(".include \"macro.inc\"")
        ret.append("")
        ret.append("# assembler directives")
        ret.append(".set noat      # allow manual use of $at")
        ret.append(".set noreorder # don't insert nops after branches")
        ret.append(".set gp=64     # allow use of 64-bit general purpose registers")
        ret.append("")
        ret.append(".section .text, \"ax\"")
        ret.append("")

        return ret

    @staticmethod
    def get_funcs_defined_in_c(c_file):
        with open(c_file, "r") as f:
            text = N64SegCode.strip_c_comments(f.read())

        return set(m.group(2) for m in N64SegCode.C_FUNC_RE.finditer(text))

    def scan(self, rom_bytes: bytes):
        if not self.rom_start == self.rom_end:
            if self.type == "c":
                output_path = self.get_generic_out_path()
                if options.get("do_c_func_detection", True) and os.path.exists(output_path):
                    # TODO run cpp?
                    self.defined_funcs = N64SegCode.get_funcs_defined_in_c(output_path)
                    self.mark_c_funcs_as_defined(self.defined_funcs)

            insns = [insn for insn in N64SegCode.md.disasm(rom_bytes[self.rom_start : self.rom_end], self.vram_start)]

            funcs = self.process_insns(insns, self.rom_start)

            # TODO: someday make func a subclass of symbol and store this disasm info there too
            for func in funcs:
                self.parent.get_symbol(func, type="func", create=True, define=True, local_only=True)

            funcs = self.determine_symbols(funcs)
            self.gather_jumptable_labels(rom_bytes)
            self.funcs_text = self.add_labels(funcs)

    def split(self, rom_bytes: bytes):
        if not self.rom_start == self.rom_end:
            if self.type == "c":
                asm_out_dir = options.get_asm_path() / "nonmatchings" / self.parent.dir
                asm_out_dir.mkdir(parents=True, exist_ok=True)

                for func in self.funcs_text:
                    func_name = self.get_symbol(func, type="func", local_only=True).name

                    if func_name not in self.defined_funcs:
                        self.create_c_asm_file(self.funcs_text, func, asm_out_dir, self, func_name)

                out_path = self.get_generic_out_path()
                if not os.path.exists(out_path) and options.get("create_new_c_files", True):
                    self.create_c_file(self.funcs_text, self, asm_out_dir, out_path)
            else:
                asm_out_dir = options.get_asm_path()
                asm_out_dir.mkdir(parents=True, exist_ok=True)

                out_lines = self.get_standalone_asm_header()
                for func in self.funcs_text:
                    out_lines.extend(self.funcs_text[func][0])
                    out_lines.append("")

                outpath = asm_out_dir / (self.name + ".s")

                if self.type == "asm" or not outpath.exists():
                    with open(outpath, "w", newline="\n") as f:
                        f.write("\n".join(out_lines))

    def get_linker_entries(self):
        return [sub.get_linker_entry() for sub in self.subsegments]

    def retrieve_symbol(self, d, k, t):
        if k not in d:
            return None

        if t:
            items = [s for s in d[k] if s.type == t or s.type == "unknown"]
        else:
            items = d[k]

        if len(items) > 1:
            pass #print(f"Trying to retrieve {k:X} from symbol dict but there are {len(items)} entries to pick from - picking the first")
        if len(items) == 0:
            return None
        return items[0]

    def retrieve_symbol_from_ranges(self, vram, rom=None):
        rom_matches = []
        ram_matches = []

        for symbol in self.symbol_ranges:
            if symbol.contains_vram(vram):
                if symbol.rom and rom and symbol.contains_rom(rom):
                    rom_matches.append(symbol)
                else:
                    ram_matches.append(symbol)

        ret = rom_matches + ram_matches

        if len(ret) > 0:
            return ret[0]
        else:
            return None

    def get_symbol(self, addr, type=None, create=False, define=False, reference=False, offsets=False, local_only=False, dead=True):
        ret = None
        rom = None

        in_segment = self.contains_vram(addr)

        if in_segment:
            # If the vram address is within this segment, we can calculate the symbol's rom address
            rom = self.ram_to_rom(addr)
            ret = self.retrieve_symbol(self.seg_symbols, addr, type)
        elif not local_only:
            ret = self.retrieve_symbol(self.ext_symbols, addr, type)

        # Search for symbol ranges
        if not ret and offsets:
            ret = self.retrieve_symbol_from_ranges(addr, rom)

        if not dead and ret and ret.dead:
            ret = None

        # Create the symbol if it doesn't exist
        if not ret and create:
            ret = Symbol(addr, rom=rom, type=type)
            symbols.all_symbols.append(ret)

            if in_segment:
                if self.is_overlay:
                    ret.set_in_overlay()
                if addr not in self.seg_symbols:
                    self.seg_symbols[addr] = []
                self.seg_symbols[addr].append(ret)
            elif not local_only:
                if addr not in self.ext_symbols:
                    self.ext_symbols[addr] = []
                self.ext_symbols[addr].append(ret)

        if ret:
            if define:
                ret.defined = True
            if reference:
                ret.referenced = True

        return ret

    def get_gcc_inc_header(self):
        ret = []
        ret.append(".set noat      # allow manual use of $at")
        ret.append(".set noreorder # don't insert nops after branches")
        ret.append("")

        return ret

    @staticmethod
    def is_nops(insns):
        for insn in insns:
            if insn.mnemonic != "nop":
                return False
        return True

    @staticmethod
    def is_branch_insn(mnemonic):
        return (mnemonic.startswith("b") and not mnemonic.startswith("binsl") and not mnemonic == "break") or mnemonic == "j"

    def process_insns(self, insns, rom_addr):
        ret = OrderedDict()

        func_addr = None
        func = []
        end_func = False
        labels = []

        # Collect labels
        for insn in insns:
            if self.is_branch_insn(insn.mnemonic):
                op_str_split = insn.op_str.split(" ")
                branch_target = op_str_split[-1]
                branch_addr = int(branch_target, 0)
                labels.append((insn.address, branch_addr))

        # Main loop
        for i, insn in enumerate(insns):
            mnemonic = insn.mnemonic
            op_str = insn.op_str
            func_addr = insn.address if len(func) == 0 else func[0][0].address

            if mnemonic == "move":
                # Let's get the actual instruction out
                opcode = insn.bytes[3] & 0b00111111
                op_str += ", $zero"

                if opcode == 37:
                    mnemonic = "or"
                elif opcode == 45:
                    mnemonic = "daddu"
                elif opcode == 33:
                    mnemonic = "addu"
                else:
                    print("INVALID INSTRUCTION " + insn)
            elif mnemonic == "jal":
                jal_addr = int(op_str, 0)
                jump_func = self.get_symbol(jal_addr, type="func", create=True, reference=True)
                op_str = jump_func.name
            elif self.is_branch_insn(insn.mnemonic):
                op_str_split = op_str.split(" ")
                branch_target = op_str_split[-1]
                branch_target_int = int(branch_target, 0)
                label = ""

                label = self.get_symbol(branch_target_int, type="label", reference=True, local_only=True)

                if label:
                    label_name = label.name
                else:
                    self.labels_to_add.add(branch_target_int)
                    label_name = f".L{branch_target[2:].upper()}"

                op_str = " ".join(op_str_split[:-1] + [label_name])
            elif mnemonic == "mtc0" or mnemonic == "mfc0":
                rd = (insn.bytes[2] & 0xF8) >> 3
                op_str = op_str.split(" ")[0] + " $" + str(rd)

            func.append((insn, mnemonic, op_str, rom_addr))
            rom_addr += 4

            if mnemonic == "jr":
                # Record potential jtbl jumps
                if op_str != "$ra":
                    self.jtbl_jumps[insn.address] = op_str

                keep_going = False
                for label in labels:
                    if (label[0] > insn.address and label[1] <= insn.address) or (label[0] <= insn.address and label[1] > insn.address):
                        keep_going = True
                        break
                if not keep_going:
                    end_func = True
                    continue

            if i < len(insns) - 1 and self.get_symbol(insns[i + 1].address, local_only=True, type="func", dead=False):
                end_func = True

            if end_func:
                if self.is_nops(insns[i:]) or i < len(insns) - 1 and insns[i + 1].mnemonic != "nop":
                    end_func = False
                    ret[func_addr] = func
                    func = []

        # Add the last function (or append nops to the previous one)
        if not self.is_nops([i[0] for i in func]):
            ret[func_addr] = func
        else:
            next(reversed(ret.values())).extend(func)

        return ret

    def get_subsection_for_ram(self, addr):
        for sub in self.subsegments:
            if sub.contains_vram(addr):
                return sub
        return None

    def update_access_mnemonic(self, sym, mnemonic):
        if not sym.access_mnemonic:
            sym.access_mnemonic = mnemonic
        elif sym.access_mnemonic == "addiu":
            sym.access_mnemonic = mnemonic
        elif sym.access_mnemonic in self.double_mnemonics:
            return
        elif sym.access_mnemonic in self.float_mnemonics and mnemonic in self.double_mnemonics:
            sym.access_mnemonic = mnemonic
        elif sym.access_mnemonic in self.short_mnemonics:
            return
        elif sym.access_mnemonic in self.byte_mnemonics:
            return
        else:
            sym.access_mnemonic = mnemonic

    # Determine symbols
    def determine_symbols(self, funcs):
        hi_lo_max_distance = options.get("hi_lo_max_distance", 6)
        ret = {}

        for func_addr in funcs:
            func = funcs[func_addr]
            func_end_addr = func[-1][0].address + 4

            possible_jtbl_jumps = [(k, v) for k, v in self.jtbl_jumps.items() if k >= func_addr and k < func_end_addr]
            possible_jtbl_jumps.sort(key=lambda x:x[0])

            for i in range(len(func)):
                insn = func[i][0]

                # Ensure the first item in the list is always ahead of where we're looking
                while len(possible_jtbl_jumps) > 0 and possible_jtbl_jumps[0][0] < insn.address:
                    del possible_jtbl_jumps[0]

                if insn.mnemonic == "lui":
                    op_split = insn.op_str.split(", ")
                    reg = op_split[0]

                    if not op_split[1].startswith("0x"):
                        continue

                    lui_val = int(op_split[1], 0)
                    if lui_val >= 0x8000:
                        for j in range(i + 1, min(i + hi_lo_max_distance, len(func))):
                            s_insn = func[j][0]

                            s_op_split = s_insn.op_str.split(", ")

                            if s_insn.mnemonic == "lui" and reg == s_op_split[0]:
                                break

                            if s_insn.mnemonic in ["addiu", "ori"]:
                                s_reg = s_op_split[-2]
                            else:
                                s_reg = s_op_split[-1][s_op_split[-1].rfind("(") + 1: -1]

                            if reg == s_reg:
                                if s_insn.mnemonic not in ["addiu", "lw", "sw", "lh", "sh", "lhu", "lb", "sb", "lbu", "lwc1", "swc1", "ldc1", "sdc1"]:
                                    break

                                # Match!
                                reg_ext = ""

                                junk_search = re.search(
                                    r"[\(]", s_op_split[-1])
                                if junk_search is not None:
                                    if junk_search.start() == 0:
                                        break
                                    s_str = s_op_split[-1][:junk_search.start()]
                                    reg_ext = s_op_split[-1][junk_search.start():]
                                else:
                                    s_str = s_op_split[-1]

                                symbol_addr = (lui_val * 0x10000) + int(s_str, 0)

                                sym = None
                                offset_str = ""

                                if symbol_addr > func_addr and symbol_addr < self.vram_end and len(possible_jtbl_jumps) > 0 and func_end_addr - s_insn.address >= 0x30:
                                    for jump in possible_jtbl_jumps:
                                        if jump[1] == s_op_split[0]:
                                            dist_to_jump = possible_jtbl_jumps[0][0] - s_insn.address
                                            if dist_to_jump <= 16:
                                                sym = self.get_symbol(symbol_addr, create=True, reference=True, type="jtbl", local_only=True)
                                                self.jumptables[symbol_addr] = (func_addr, func_end_addr)
                                                break

                                if not sym:
                                    sym = self.get_symbol(symbol_addr, create=True, offsets=True, reference=True)
                                    offset = symbol_addr - sym.vram_start
                                    if offset != 0:
                                        offset_str = f"+0x{offset:X}"

                                if self.rodata_vram_start != -1 and self.rodata_vram_end != -1:
                                    if self.rodata_vram_start <= sym.vram_start < self.rodata_vram_end:
                                        if func_addr not in self.rodata_syms:
                                            self.rodata_syms[func_addr] = []
                                        self.rodata_syms[func_addr].append(sym)

                                self.update_access_mnemonic(sym, s_insn.mnemonic)

                                sym_label = sym.name + offset_str

                                func[i] += ("%hi({})".format(sym_label),)
                                func[j] += ("%lo({}){}".format(sym_label, reg_ext),)
                                break
            ret[func_addr] = func
        return ret

    def add_labels(self, funcs):
        ret = {}

        for func in funcs:
            func_text = []

            # Add function glabel
            rom_addr = funcs[func][0][3]
            sym = self.get_symbol(func, type="func", create=True, define=True, local_only=True)
            func_text.append(f"glabel {sym.name}")

            indent_next = False

            mnemonic_ljust = options.get("mnemonic_ljust", 11)
            rom_addr_padding = options.get("rom_address_padding", None)

            for insn in funcs[func]:
                insn_addr = insn[0].address
                # Add a label if we need one
                if insn_addr in self.jtbl_glabels_to_add:
                    func_text.append(f"glabel L{insn_addr:X}_{insn[3]:X}")
                elif insn_addr in self.labels_to_add:
                    self.labels_to_add.remove(insn_addr)
                    func_text.append(".L{:X}:".format(insn_addr))

                if rom_addr_padding:
                    rom_str = "{0:0{1}X}".format(insn[3], rom_addr_padding)
                else:
                    rom_str = "{:X}".format(insn[3])

                asm_comment = "/* {} {:X} {} */".format(rom_str, insn_addr, insn[0].bytes.hex().upper())

                if len(insn) > 4:
                    op_str = ", ".join(insn[2].split(", ")[:-1] + [insn[4]])
                else:
                    op_str = insn[2]

                if self.is_branch_insn(insn[0].mnemonic):
                    branch_addr = int(insn[0].op_str.split(",")[-1].strip(), 0)
                    if branch_addr in self.jtbl_glabels_to_add:
                        label_str = f"L{branch_addr:X}_{self.ram_to_rom(branch_addr):X}"
                        op_str = ", ".join(insn[2].split(", ")[:-1] + [label_str])

                insn_text = insn[1]
                if indent_next:
                    indent_next = False
                    insn_text = " " + insn_text

                asm_insn_text = "  {}{}".format(insn_text.ljust(mnemonic_ljust), op_str).rstrip()

                func_text.append(asm_comment + asm_insn_text)

                if insn[0].mnemonic != "branch" and insn[0].mnemonic.startswith("b") or insn[0].mnemonic.startswith("j"):
                    indent_next = True

            ret[func] = (func_text, rom_addr)

            if options.get("find_file_boundaries"):
                # If this is not the last function in the file
                if func != list(funcs.keys())[-1]:

                    # Find where the function returns
                    jr_pos: Optional[int] = None
                    for i, insn in enumerate(reversed(funcs[func])):
                        if insn[0].mnemonic == "jr" and insn[0].op_str == "$ra":
                            jr_pos = i
                            break

                    # If there is more than 1 nop after the return
                    if jr_pos is not None and jr_pos > 1 and self.is_nops([i[0] for i in funcs[func][-jr_pos + 1:]]):
                        new_file_addr = funcs[func][-1][3] + 4
                        if (new_file_addr % 16) == 0:
                            if not self.reported_file_split:
                                self.reported_file_split = True
                                print(f"Segment {self.name}, function at vram {func:X} ends with extra nops, indicating a likely file split.")
                                print("File split suggestions for this segment will follow in config yaml format:")
                            print(f"      - [0x{new_file_addr:X}, asm]")

        return ret

    def get_c_preamble(self):
        ret = []

        preamble = options.get("generated_c_preamble", "#include \"common.h\"")
        ret.append(preamble)
        ret.append("")

        return ret

    def gather_jumptable_labels(self, rom_bytes):
        # TODO: use the seg_symbols for this
        # jumptables = [j.type == "jtbl" for j in self.seg_symbols]
        for jumptable in self.jumptables:
            start, end = self.jumptables[jumptable]
            rom_offset = self.rom_start + jumptable - self.vram_start

            if rom_offset <= 0:
                return

            while (rom_offset):
                word = rom_bytes[rom_offset : rom_offset + 4]
                word_int = int.from_bytes(word, "big")
                if word_int >= start and word_int <= end:
                    self.jtbl_glabels_to_add.add(word_int)
                else:
                    break

                rom_offset += 4

    def mark_c_funcs_as_defined(self, c_funcs):
        for func_name in c_funcs:
            found = False
            for func_addr in self.seg_symbols:
                for symbol in self.seg_symbols[func_addr]:
                    if symbol.name == func_name:
                        symbol.defined = True
                        found = True
                        break
                if found:
                    break

    def create_c_asm_file(self, funcs_text, func, out_dir, sub, func_name):
        if options.get_compiler() == "GCC":
            out_lines = self.get_gcc_inc_header()
        else:
            out_lines = []

        if func in self.rodata_syms:
            func_rodata = list({s for s in self.rodata_syms[func] if s.disasm_str})
            func_rodata.sort(key=lambda s:s.vram_start)

            if len(func_rodata) > 0:
                rsub = self.get_subsection_for_ram(func_rodata[0].vram_start)
                if rsub and rsub.type != "rodata":
                    out_lines.append(".section .rodata")

                    for sym in func_rodata:
                        if sym.disasm_str:
                            out_lines.extend(sym.disasm_str.replace("\n\n", "\n").split("\n"))

                    out_lines.append("")
                    out_lines.append(".section .text")
                    out_lines.append("")

        out_lines.extend(funcs_text[func][0])
        out_lines.append("")

        outpath = Path(os.path.join(out_dir, sub.name, func_name + ".s"))
        outpath.parent.mkdir(parents=True, exist_ok=True)

        with open(outpath, "w", newline="\n") as f:
            f.write("\n".join(out_lines))
        self.log(f"Disassembled {func_name} to {outpath}")

    def create_c_file(self, funcs_text, sub, asm_out_dir, c_path):
        c_lines = self.get_c_preamble()

        for func in funcs_text:
            func_name = self.get_symbol(func, type="func", local_only=True).name
            if options.get_compiler() == "GCC":
                c_lines.append("INCLUDE_ASM(s32, \"{}\", {});".format(sub.name, func_name))
            else:
                asm_outpath = Path(os.path.join(asm_out_dir, sub.name, func_name + ".s"))
                rel_asm_outpath = os.path.relpath(asm_outpath, options.get_base_path())
                c_lines.append(f"#pragma GLOBAL_ASM(\"{rel_asm_outpath}\")")
            c_lines.append("")

        Path(c_path).parent.mkdir(parents=True, exist_ok=True)
        with open(c_path, "w") as f:
            f.write("\n".join(c_lines))
        print(f"Wrote {sub.name} to {c_path}")
