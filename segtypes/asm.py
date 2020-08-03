from capstone import *
from capstone.mips import *

from segtypes.segment import N64Segment
import os
from pathlib import Path
import re

class N64SegAsm(N64Segment):
    def __init__(self, rom_start, rom_end, segtype, name, ram_addr):
        super().__init__(rom_start, rom_end, segtype, name, ram_addr)
        self.labels = set()
        self.undefined_functions = set()
        self.defined_functions = set()
        self.all_functions = set()

    def format_insn(self, lines, insn, rom_addr):
        mnemonic = insn.mnemonic
        op_str = insn.op_str

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
            jump_func = self.get_func_name(op_str[2:])
            self.undefined_functions.add(jump_func)
            op_str = jump_func
        elif mnemonic == "break":
            pass
        elif mnemonic.startswith("b"):
            op_str_split = op_str.split(" ")
            branch_target = op_str_split[-1]
            label = ".L" + branch_target[2:].upper()
            self.labels.add(label)
            op_str = " ".join(op_str_split[:-1] + [label])
        elif mnemonic == "mtc0" or mnemonic == "mfc0":
            rd = (insn.bytes[2] & 0xF8) >> 3
            op_str = op_str.split(" ")[0] + " $" + str(rd)

        asm_line = "/* {:X} {:X} {} */  {}{}".format(rom_addr, insn.address, insn.bytes.hex().upper(), mnemonic.ljust(10), op_str)
        lines.append(asm_line)

    def get_func_name(self, addr):
        return "func_{}".format(addr.upper())
        
    def get_unique_func_name(self, func_name):
        if func_name in self.all_functions:
            return func_name + "_" + self.name.split("_")[0]
        return func_name
    
    def add_glabel(self, addr):
        func = self.get_func_name(addr)
        self.undefined_functions.discard(func)
        self.defined_functions.add(func)
        return "glabel " + func

    def pass_1(self, lines):
        ret = []

        ret.append(".include \"macro.inc\"")
        ret.append("")
        ret.append("# assembler directives")
        ret.append(".set noat      # allow manual use of $at")
        ret.append(".set noreorder # don't insert nops after branches")
        ret.append(".set gp=64     # allow use of 64-bit general purpose registers")
        ret.append("")
        ret.append(".section .text{:X}_{}, \"ax\"".format(self.ram_addr, self.name))
        ret.append("")
        ret.append(self.add_glabel("{:X}".format(self.ram_addr)))

        for line in lines:
            line_split = line.split(" ")
            vram_addr = int(line_split[2], 16)

            if re.search(r"jr\s+.ra", line):
                func = "func_{:X}".format(vram_addr + 8)
                self.undefined_functions.add(func)
            ret.append(line)
        
        ret.append("")

        return ret
    
    def pass_2(self, lines):
        ret = []

        for line in lines:
            line_split = line.split(" ")
            if len(line_split) > 2:
                line_addr = line.split(" ")[2]
                if re.match(r"[0-9A-F]{8}", line_addr):
                    line_label = ".L" + line_addr
                    line_func = "func_" + line_addr
                    if line_label in self.labels:
                        ret.append(line_label + ":")
                        self.labels.remove(line_label)
                        self.undefined_functions.discard(line_func)
                    elif line_func in self.undefined_functions and line_func not in self.defined_functions:
                        ret.append("")
                        if not line.rstrip().endswith("nop"):
                            ret.append(self.add_glabel(line_addr))
                        else:
                            self.undefined_functions.remove(line_func)
            ret.append(line)
        
        return ret
    
    def pass_3(self, lines):
        ret = []

        dup_funcs = self.defined_functions.intersection(self.all_functions)
        for line in lines:
            for func in dup_funcs:
                line = line.replace(func, self.get_unique_func_name(func))
            ret.append(line)
        
        return ret


    def split(self, rom_bytes, base_path):
        out_dir = self.create_split_dir(base_path, "asm")

        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)
        md.detail = True
        md.skipdata = True

        md.insn_name

        out_lines = []
        rom_addr = self.rom_start

        for insn in md.disasm(rom_bytes[self.rom_start : self.rom_end], self.ram_addr):
            self.format_insn(out_lines, insn, rom_addr)
            rom_addr += 4
        
        out_lines = self.pass_1(out_lines)
        out_lines = self.pass_2(out_lines)
        out_lines = self.pass_3(out_lines)

        with open(os.path.join(out_dir,  self.name + ".s"), "w", newline="\n") as f:
            f.write("\n".join(out_lines))


    @staticmethod
    def create_makefile_target():
        return ""

    def get_ld_section(self):
        section_name = ".text{:X}_{}".format(self.ram_addr, self.name)

        lines = []
        lines.append("    /* 0x{:X} {:X}-{:X} [{:X}] */".format(self.ram_addr, self.rom_start, self.rom_end, self.rom_end - self.rom_start))
        lines.append("    {} 0x{:X} : AT(0x{:X}) ".format(section_name, self.ram_addr, self.rom_start) + "{")
        lines.append("        build/asm/{}.o({});".format(self.name, section_name))
        lines.append("    }")
        lines.append("")
        lines.append("")
        return "\n".join(lines)
