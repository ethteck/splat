#! /usr/bin/python3

import argparse
from util import rominfo
from segtypes.code import N64SegCode

parser = argparse.ArgumentParser(description="Create a splat config from a rom")
parser.add_argument("rom", help="path to a .z64 rom")


def main(rom_path):
    rom = rominfo.get_info(rom_path)
    basename = rom.name.replace(" ", "").lower()

    header = \
"""name: {0} ({1})
basename: {2}
options:
  find-file-boundaries: True
  compiler: "IDO"
""".format(rom.name.title(), rom.get_country_name(), basename)

    # codeseg = N64SegCode(0x1000, rom.size, "asm", "firstseg", rom.entry_point, [{"start": 0x1000, "end": rom.size, "name": "firstseg", "vram": rom.entry_point, "subtype": "asm"}], {})
    # codeseg.split

    segments = \
"""segments:
  - name: header
    type: header
    start: 0x0
    vram: 0
    files:
      - [0x0, header, header]
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
