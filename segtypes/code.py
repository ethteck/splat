from capstone import *
from capstone.mips import *

from segtypes.segment import N64Segment
import os
from pathlib import Path
import re

class N64SegCode(N64Segment):
    def __init__(self, rom_start, rom_end, segtype, name, ram_addr, files):
        super().__init__(rom_start, rom_end, segtype, name, ram_addr, files)
        self.labels = set()
        self.undefined_functions = set()
        self.defined_functions = set()
        self.all_functions = set()
        self.c_functions = {}


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

            if jump_func not in self.c_functions.values():
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
        def_name = "func_{}".format(addr.upper())

        if def_name in self.c_functions:
            return self.c_functions[def_name]
        else:
            return def_name
        
    def get_unique_func_name(self, func_name):
        if func_name in self.all_functions:
            return func_name + "_" + self.name[-5:]
        return func_name
    
    def add_glabel(self, addr):
        func = self.get_func_name(addr)
        self.undefined_functions.discard(func)
        self.defined_functions.add(func)
        return "glabel " + func
    
    def get_header(self, vram_addr):
        ret = []

        ret.append(".include \"macro.inc\"")
        ret.append("")
        ret.append("# assembler directives")
        ret.append(".set noat      # allow manual use of $at")
        ret.append(".set noreorder # don't insert nops after branches")
        ret.append(".set gp=64     # allow use of 64-bit general purpose registers")
        ret.append("")
        ret.append(".section {}, \"ax\"".format(self.get_sect_name()))
        ret.append("")
        ret.append(self.add_glabel("{:X}".format(vram_addr)))

        return ret

    def pass_1(self, lines):
        ret = []

        for line in lines:
            if re.search(r"jr\s+.ra", line):
                vram_addr = int(line.split(" ")[2], 16)

                func = "func_{:X}".format(vram_addr + 8)
                if func not in self.c_functions.values():
                    self.undefined_functions.add(func)
            ret.append(line)
        
        return ret
    
    def pass_2(self, lines, subtype):
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
                    elif (line_func in self.undefined_functions and line_func not in self.defined_functions) or (line_func in self.c_functions.keys() and subtype == "hasm"):
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


    def split(self, rom_bytes, base_path, options):

        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)
        md.detail = True
        md.skipdata = True

        for split_file in self.files:
            if split_file["subtype"] in ["asm", "hasm"] and "skip-asm" not in options:
                out_dir = self.create_split_dir(base_path, "asm")

                out_lines = self.get_header(split_file["vram"])
                rom_addr = split_file["start"]
                for insn in md.disasm(rom_bytes[split_file["start"] : split_file["end"]], split_file["vram"]):
                    self.format_insn(out_lines, insn, rom_addr)
                    rom_addr += 4
                
                out_lines = self.pass_1(out_lines)
                out_lines = self.pass_2(out_lines, split_file["subtype"])
                out_lines = self.pass_3(out_lines)
                out_lines.append("")

                outpath = Path(os.path.join(out_dir,  split_file["name"] + ".s"))
                outpath.parent.mkdir(parents=True, exist_ok=True)

                with open(outpath, "w", newline="\n") as f:
                    f.write("\n".join(out_lines))
            elif split_file["subtype"] == "bin":
                out_dir = self.create_split_dir(base_path, "bin")

                with open(os.path.join(out_dir, split_file["name"] + ".bin"), "wb") as f:
                    f.write(rom_bytes[split_file["start"] : split_file["end"]])


    @staticmethod
    def create_makefile_target():
        return ""


    @staticmethod
    def get_subdir(subtype):
        if subtype in ["c", ".data", ".rodata"]:
            return "src"
        elif subtype in ["asm", "hasm"]:
            return "asm"
        return subtype


    def get_sect_name(self):
        return ".text_{:X}".format(self.rom_start)


    @staticmethod
    def get_sect_name_2(subtype, section_name):
        if subtype in "c":
            return ".text"
        elif subtype in ["bin", ".data"]:
            return ".data"
        elif subtype == ".rodata":
            return ".rodata"
        return section_name


    def get_ld_section(self):
        ret = []

        section_name = self.get_sect_name()

        ret.append("    /* 0x{:X} {:X}-{:X} (len {:X}) */".format(self.vram_addr, self.rom_start, self.rom_end, self.rom_end - self.rom_start))
        ret.append("    {} 0x{:X} : AT(0x{:X}) ".format(section_name, self.vram_addr, self.rom_start) + "{")

        for split_file in self.files:
            subdir = self.get_subdir(split_file["subtype"])
            section_name2 = self.get_sect_name_2(split_file["subtype"], section_name)
            ret.append("        build/{}/{}.o({});".format(subdir, split_file["name"], section_name2))
        
        ret.append("    }")
        ret.append("")
        ret.append("")
        return "\n".join(ret)
