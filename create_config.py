#! /usr/bin/python3

import argparse
from util import rominfo

parser = argparse.ArgumentParser(description="Create a split config from a rom")
parser.add_argument("rom", help="path to a .z64 rom")


def main(rom_path):
    rom = rominfo.get_info(rom_path)
    basename = rom.name.replace(" ", "").lower()

    header = \
"""name: {0} ({1})
basename: {2}
options:
  find-file-boundaries: True
  pycparser_flags: ["-Iinclude", "-D_LANGUAGE_C", "-ffreestanding", "-DF3DEX_GBI_2", "-DSPLAT"]
  compiler: "IDO"\n
""".format(rom.name.title(), rom.get_country_name(), basename)

    segments = \
"""segments:
  - name: header
    type: header
    start: 0x0
  - name: boot
    type: bin
    start: 0x40
  - name: the_rest
    type: bin
    start: 0x1000
  - [0x{:X}]
""".format(rom.size)

    outstr = header + segments
    
    outname = rom.name.replace(" ", "").lower()
    with open(outname + ".yaml", "w", newline="\n") as f:
        f.write(outstr)
    
if __name__ == "__main__":
    args = parser.parse_args()
    main(args.rom)
