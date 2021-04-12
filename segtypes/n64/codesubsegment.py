from segtypes.n64.code import N64SegCode
from collections import OrderedDict


from segtypes.segment import Segment
from util import options
from util.symbols import Symbol

# abstract class for c, asm, data, etc
class N64SegCodeSubsegment(Segment):
    def __init__(self, segment, rom_start, rom_end):
        super().__init__(segment, rom_start, rom_end)
        assert(isinstance(self.parent, N64SegCode))

    @property
    def needs_symbols(self) -> bool:
        return True

    def get_linker_section(self) -> str:
        return ".text"

    def get_linker_entries(self):
        pass

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
                jump_func = self.parent.get_symbol(jal_addr, type="func", create=True, reference=True)
                op_str = jump_func.name
            elif self.is_branch_insn(insn.mnemonic):
                op_str_split = op_str.split(" ")
                branch_target = op_str_split[-1]
                branch_target_int = int(branch_target, 0)
                label = ""

                label = self.parent.get_symbol(branch_target_int, type="label", reference=True, local_only=True)

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

            if i < len(insns) - 1 and self.parent.get_symbol(insns[i + 1].address, local_only=True, type="func", dead=False):
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

