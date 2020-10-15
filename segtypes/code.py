from capstone import *
from capstone.mips import *

from collections import OrderedDict
from segtypes.segment import N64Segment
import os
from pathlib import Path
from pycparser import c_parser, c_ast, parse_file
import re


class N64SegCode(N64Segment):
    def __init__(self, rom_start, rom_end, segtype, name, ram_addr, files, options):
        super().__init__(rom_start, rom_end, segtype, name, ram_addr, files, options)
        self.labels_to_add = {}
        self.glabels_to_add = set()
        self.glabels_added = set()
        self.all_functions = set()
        self.c_functions = {}
        self.c_variables = {}
        self.c_labels_to_add = set()


    def get_func_name(self, addr):
        def_name = "func_{:X}".format(addr)

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
        self.glabels_to_add.discard(func)
        self.glabels_added.add(func)
        return "glabel " + func
    

    def get_header(self):
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
                jump_func = self.get_func_name(jal_addr)

                if jump_func not in self.c_functions.values():
                    self.glabels_to_add.add(jump_func)
                op_str = jump_func
            elif self.is_branch_insn(insn.mnemonic):
                op_str_split = op_str.split(" ")
                branch_target = op_str_split[-1]

                if func_addr not in self.labels_to_add:
                    self.labels_to_add[func_addr] = set()
                self.labels_to_add[func_addr].add(int(branch_target, 0))

                label = ".L" + branch_target[2:].upper()
                op_str = " ".join(op_str_split[:-1] + [label])
            elif mnemonic == "mtc0" or mnemonic == "mfc0":
                rd = (insn.bytes[2] & 0xF8) >> 3
                op_str = op_str.split(" ")[0] + " $" + str(rd)
            
            func.append((insn, mnemonic, op_str, rom_addr))
            rom_addr += 4
            
            if mnemonic == "jr":
                keep_going = False
                for label in labels:
                    if (label[0] > insn.address and label[1] <= insn.address) or (label[0] <= insn.address and label[1] > insn.address):
                        keep_going = True
                        break
                if not keep_going:
                    end_func = True
                    continue
            
            if i < len(insns) - 1 and self.get_func_name(insns[i + 1].address) in self.c_labels_to_add:
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
            ret[next(reversed(ret))].extend(func) # Requires Python 3.7 (I think)

        return ret


    # Determine symbols
    def determine_symbols(self, funcs):
        ret = {}

        for func_addr in funcs:
            func = funcs[func_addr]

            for i in range(len(func)):
                insn = func[i][0]

                if insn.mnemonic == "lui":
                    op_split = insn.op_str.split(", ")
                    reg = op_split[0]

                    if not op_split[1].startswith("0x"):
                        continue
                        
                    lui_val = int(op_split[1], 0)
                    if lui_val >= 0x8000:
                        for j in range(i + 1, min(i + 8, len(func))):
                            s_insn = func[j][0]

                            if s_insn.mnemonic in ["addiu", "lw", "sw", "lh", "sh", "lhu", "lb", "sb", "lbu"]:
                                s_op_split = s_insn.op_str.split(", ")

                                if s_insn.mnemonic.startswith("s"):
                                    s_reg = s_op_split[-1][s_op_split[-1].rfind("(") + 1 : -1]
                                else:
                                    s_reg = s_op_split[-2]

                                if reg == s_reg:
                                    # Match!
                                    
                                    reg_ext = ""

                                    junk_search = re.search(r"[\(]", s_op_split[-1])
                                    if junk_search is not None:
                                        if junk_search.start() == 0:
                                            break
                                        s_str = s_op_split[-1][:junk_search.start()]
                                        reg_ext = s_op_split[-1][junk_search.start():]
                                    else:
                                        s_str = s_op_split[-1]

                                    s_val = int(s_str, 0)

                                    symbol_addr = (lui_val * 0x10000) + s_val

                                    if symbol_addr in self.c_variables:
                                        sym_name = self.c_variables[symbol_addr]
                                    else:
                                        break
                                        # sym_name = "D_{:X}".format(symbol_addr)

                                    func[i] += ("%hi({})".format(sym_name),)
                                    func[j] += ("%lo({}){}".format(sym_name, reg_ext),)
                                    break

            ret[func_addr] = func

        return ret


    def add_labels(self, funcs):
        ret = {}

        for func in funcs:
            func_text = []

            # Add function glabel
            func_text.append(self.add_glabel(func))

            indent_next = False

            for insn in funcs[func]:
                # Add a label if we need one
                if func in self.labels_to_add and insn[0].address in self.labels_to_add[func]:
                    self.labels_to_add[func].remove(insn[0].address)
                    func_text.append(".L{:X}:".format(insn[0].address))
                    
                asm_comment = "/* {:X} {:X} {} */".format(insn[3], insn[0].address, insn[0].bytes.hex().upper())
                
                if len(insn) > 4:
                    op_str = ", ".join(insn[2].split(", ")[:-1] + [insn[4]])
                else:
                    op_str = insn[2]

                insn_text = insn[1]
                if indent_next:
                    indent_next = False
                    insn_text = " " + insn_text

                mnemonic_ljust = 11
                if "mnemonic_ljust" in self.options:
                    mnemonic_ljust = self.options["mnemonic_ljust"]

                asm_insn_text = "  {}{}".format(insn_text.ljust(mnemonic_ljust), op_str)
                func_text.append(asm_comment + asm_insn_text)

                if insn[0].mnemonic != "branch" and insn[0].mnemonic.startswith("b") or insn[0].mnemonic.startswith("j"):
                    indent_next = True

            ret[func] = func_text

            if self.options.get("find-file-boundaries"):
                if func != next(reversed(funcs)) and self.is_nops([i[0] for i in funcs[func][-2:]]):
                    print("function at vram {:X} ends with nops so a new file probably starts at rom address 0x{:X}".format(func, funcs[func][-1][3] + 4))

        return ret


    # Rename duplicate functions (text-level)
    def rename_duplicates(self, funcs_text):
        ret = {}

        dup_funcs = self.glabels_added.intersection(self.all_functions)
        for func in funcs_text:
            func_text = []
            for line in funcs_text[func]:
                for dup_func in dup_funcs:
                    line = line.replace(dup_func, self.get_unique_func_name(dup_func))
                func_text.append(line)
            ret[func] = func_text
        
        return ret


    def get_pycparser_args(self):
        option = self.options.get("cpp_args")
        return ["-Iinclude", "-D_LANGUAGE_C", "-ffreestanding", "-DF3DEX_GBI_2", "-DSPLAT"] if option is None else option


    def split(self, rom_bytes, base_path):
        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)
        md.detail = True
        md.skipdata = True

        for split_file in self.files:
            if split_file["subtype"] in ["asm", "hasm", "c"]:
                if self.type not in self.options["modes"] and "all" not in self.options["modes"]:
                    continue

                out_dir = self.create_split_dir(base_path, "asm")

                rom_addr = split_file["start"]

                insns = []
                for insn in md.disasm(rom_bytes[split_file["start"] : split_file["end"]], split_file["vram"]):
                    insns.append(insn)

                funcs = self.process_insns(insns, rom_addr)
                funcs = self.determine_symbols(funcs)
                funcs_text = self.add_labels(funcs)
                # funcs_text = self.rename_duplicates(funcs_text) # TODO need a better solution

                if split_file["subtype"] == "c":
                    print("Splitting " + split_file["name"])
                    defined_funcs = set()

                    class FuncDefVisitor(c_ast.NodeVisitor):
                        def visit_FuncDef(self, node):
                            defined_funcs.add(node.decl.name)
                    
                    v = FuncDefVisitor()

                    old_dir = os.getcwd()
                    os.chdir(base_path)
                    c_path = os.path.join(base_path, "src", split_file["name"] + ".c")
                    cpp_args = self.get_pycparser_args()
                    ast = parse_file(c_path, use_cpp=True, cpp_args=cpp_args)
                    os.chdir(old_dir)
                    v.visit(ast)

                    out_dir = self.create_split_dir(base_path, os.path.join("asm", "nonmatchings"))
                    
                    for func in funcs_text:
                        func_name = self.get_func_name(func)

                        if func_name not in defined_funcs:
                            # TODO make more graceful
                            if "compiler" in self.options and self.options["compiler"] == "GCC":
                                out_lines = self.get_gcc_inc_header()
                            else:
                                out_lines = []
                            out_lines.extend(funcs_text[func])
                            out_lines.append("")

                            outpath = Path(os.path.join(out_dir, split_file["name"], func_name + ".s"))
                            outpath.parent.mkdir(parents=True, exist_ok=True)

                            with open(outpath, "w", newline="\n") as f:
                                f.write("\n".join(out_lines))

                else:
                    out_lines = self.get_header()
                    for func in funcs_text:
                        out_lines.extend(funcs_text[func])
                        out_lines.append("")

                    outpath = Path(os.path.join(out_dir, split_file["name"] + ".s"))
                    outpath.parent.mkdir(parents=True, exist_ok=True)

                    with open(outpath, "w", newline="\n") as f:
                        f.write("\n".join(out_lines))
            elif split_file["subtype"] == "bin" and ("bin" in self.options["modes"] or "all" in self.options["modes"]):
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
        elif subtype in ["asm", "hasm", "header"]:
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
