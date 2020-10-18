#! /usr/bin/python3

from capstone import *
from capstone.mips import *

import argparse
import os

parser = argparse.ArgumentParser(description="Disassemble a file")
parser.add_argument("file", help="path to a file containing MIPS assembly")


def main(fname):
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)
    md.detail = True
    md.skipdata = True

    with open(fname, "rb") as f:
        fbytes = f.read()

    jr_count = 0
    insns = []
    for insn in md.disasm(fbytes, 0x80000000):
        if insn.mnemonic == "jr" and "ra" in insn.op_str:
            jr_count += 1
    return jr_count

for root, dirs, files in os.walk("/home/ethteck/repos/papermario/bin/Yay0"):
    for fname in files:
        if fname.endswith(".bin"):
            num = main(os.path.join(root, fname))
            print(fname + " - " + str(num))

# if __name__ == "__main__":
#     args = parser.parse_args()
#     main(args.file)