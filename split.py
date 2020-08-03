#! /usr/bin/python3

import argparse
import importlib
import os
from pathlib import Path
import segtypes
import sys
import yaml
from segtypes.asm import N64SegAsm

parser = argparse.ArgumentParser(description="Split a rom given a rom, a config, and output directory")
parser.add_argument("rom", help="path to a .z64 rom")
parser.add_argument("config", help="path to a compatible config .yaml file")
parser.add_argument("outdir", help="a directory in which to extract the rom")

def handle_segment_types(types):
    targets = []
    for seg_type in types:
        segmodule = importlib.import_module("segtypes." + seg_type)
        segment_class = getattr(segmodule, "N64Seg" + seg_type.title())
        target = segment_class.create_makefile_target()
        targets.append(target)
        # getattr(segmodule, "setup")
    return targets

def write_makefile(rom_name, repo_path, targets):
    with open("makefile_template.txt") as f:
        makefile_template = f.read()
    
    makefile = makefile_template.replace("{}", rom_name)

    for target in targets:
        makefile += target
    
    with open(repo_path + "/Makefile", "w", newline="\n") as f:
        f.write(makefile)

def write_ldscript(rom_name, repo_path, sections):
    mid = ""
    for section in sections:
        mid += section
    
    with open(os.path.join(repo_path, rom_name + ".ld"), "w", newline="\n") as f:
        f.write("SECTIONS\n{\n" + mid + "}")

def main(rom_path, config_path, repo_path):
    with open(rom_path, "rb") as f:
        rom_bytes = f.read()

    # Create main output dir
    Path(repo_path).mkdir(parents=True, exist_ok=True)

    # Load config
    with open(config_path) as f:
        config = yaml.safe_load(f.read())
    
    segments = []
    sections = []
    segment_types = set()

    defined_funcs = set()
    undefined_funcs = set()

    last_addr = 0
    last_length = 0
    last_basename = ""
    
    # Initialize segments
    for i, segment in enumerate(config['segments']):
        if len(segment) == 1:
            # We're at the end
            continue

        seg_start = segment[0]
        seg_end = config['segments'][i + 1][0]
        seg_type = segment[1]

        # Get segment name (auto generate based on previous if possible)
        if len(segment) < 3:
            if last_basename and seg_type == "asm":
                seg_name = last_basename + "_{:X}".format(seg_start)
            else:
                seg_name = "{:X}".format(seg_start)
        else:
            seg_name = segment[2]
            last_basename = seg_name

        # Get vram addr (auto advance vram addr if possible)
        ram_addr = 0 if len(segment) < 4 else segment[3]
        if ram_addr == 0 and seg_type == "asm":
            ram_addr = last_addr + last_length

        segment_types.add(seg_type)

        segmodule = importlib.import_module("segtypes." + seg_type)
        segment_class = getattr(segmodule, "N64Seg" + seg_type.title())

        segment = segment_class(seg_start, seg_end, seg_type, seg_name, ram_addr)
        segments.append(segment)

        if type(segment) == N64SegAsm:
            segment.all_functions = defined_funcs
            segment.split(rom_bytes, repo_path)

            defined_funcs |= segment.defined_functions
            undefined_funcs |= segment.undefined_functions
        else:
            segment.split(rom_bytes, repo_path)

        sections.append(segment.get_ld_section())

        last_addr = ram_addr
        last_length = seg_end - seg_start
    
    # Write Makefile
    # Do segment-specific setup and gather Makefile targets
    # targets = handle_segment_types(segment_types)
    # write_makefile(config['basename'], repo_path, targets)

    # Write ldscript
    write_ldscript(config['basename'], repo_path, sections)

    # Write undefined_syms.txt
    to_write = sorted(undefined_funcs - defined_funcs)
    with open(os.path.join(repo_path,"undefined_syms.txt"), "w", newline="\n") as f:
        for line in to_write:
            f.write(line + " = 0x" + line[5:13].upper() + ";\n")


if __name__ == "__main__":
    args = parser.parse_args()
    main(args.rom, args.config, args.outdir)
