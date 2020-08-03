import argparse
from util import rominfo

parser = argparse.ArgumentParser(description="Create a split config from a rom")
parser.add_argument("rom", help="path to a .z64 rom")


def main(rom_path):
    rom = rominfo.get_info(rom_path)
    basename = rom.name.replace(" ", "").lower()

    header = \
"""name: {0} ({1})
crc1: {2}
crc2: {3}
basename: {4}\n
""".format(rom.name.title(), rom.get_country_name(), rom.crc1, rom.crc2, basename)

    segments = \
"""segments:
  - [0x0000000, 0x0000040, "header", "header"]
  - [0x0000040, 0x0001000, "bin", "boot"]
  - [0x0001000, {0}, "bin", "the_rest"]
""".format(hex(rom.size))

    outstr = header + segments
    
    outname = rom.name.replace(" ", "").lower()
    with open(outname + ".yaml", "w", newline="\n") as f:
        f.write(outstr)
    
if __name__ == "__main__":
    args = parser.parse_args()
    main(args.rom)
