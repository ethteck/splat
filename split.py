#! /usr/bin/python3

import argparse
import importlib
import os
from pathlib import Path
import segtypes
import sys
import yaml
from segtypes.code import N64SegCode

parser = argparse.ArgumentParser(description="Split a rom given a rom, a config, and output directory")
parser.add_argument("rom", help="path to a .z64 rom")
parser.add_argument("config", help="path to a compatible config .yaml file")
parser.add_argument("outdir", help="a directory in which to extract the rom")


def write_ldscript(rom_name, repo_path, sections):
    mid = ""
    for section in sections:
        mid += section
    
    with open(os.path.join(repo_path, rom_name + ".ld"), "w", newline="\n") as f:
        f.write("SECTIONS\n{\n" + mid + "}")


def parse_segment_start(segment):
    return segment[0] if "start" not in segment else segment["start"]


def parse_segment_name(segment):
    if len(segment) < 4:
        return "{:X}".format(parse_segment_start(segment))
    else:
        return segment["name"]


def parse_segment_vram(segment):
    return 0 if "vram" not in segment else segment["vram"]


def parse_segment_files(segment, seg_end):
    ret = []
    vram = parse_segment_vram(segment)
    if "files" in segment:
        for i, split_file in enumerate(segment["files"]):
            start = split_file[0]
            end = seg_end if i == len(segment["files"]) - 1 else segment["files"][i + 1][0]
            name = "{}_{:X}".format(parse_segment_name(segment), start)
            subtype = split_file[1]

            ret.append({"start": start, "end": end, "name": name, "vram": vram, "subtype": subtype})
            vram += end - start
    return ret


def gather_c_funcs(repo_path):
    with open(os.path.join(repo_path, "include", "functions.h")) as f:
        func_lines = f.readlines()
    
    ret = {}

    for line in func_lines:
        if line.startswith("/* 0x"):
            line_split = line.strip().split(" ")
            addr = "func_" + line_split[1][2:]
            name = line_split[4][:line_split[4].find("(")]
            ret[addr] = name

    return ret


def main(rom_path, config_path, repo_path):
    with open(rom_path, "rb") as f:
        rom_bytes = f.read()

    # Create main output dir
    Path(repo_path).mkdir(parents=True, exist_ok=True)

    # Load config
    with open(config_path) as f:
        config = yaml.safe_load(f.read())
    
    c_funcs = gather_c_funcs(repo_path)
    
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

        seg_start = parse_segment_start(segment)
        seg_end = parse_segment_start(config['segments'][i + 1])
        seg_type = segment[1] if "type" not in segment else segment["type"]
        seg_name = parse_segment_name(segment)
        seg_vram_addr = parse_segment_vram(segment)
        seg_files = parse_segment_files(segment, seg_end)

        segment_types.add(seg_type)

        segmodule = importlib.import_module("segtypes." + seg_type)
        segment_class = getattr(segmodule, "N64Seg" + seg_type.title())

        segment = segment_class(seg_start, seg_end, seg_type, seg_name, seg_vram_addr, seg_files)
        segments.append(segment)

        if type(segment) == N64SegCode:
            segment.all_functions = defined_funcs
            segment.c_functions = c_funcs
            segment.split(rom_bytes, repo_path)

            defined_funcs |= segment.defined_functions
            undefined_funcs |= segment.undefined_functions
        else:
            segment.split(rom_bytes, repo_path)

        sections.append(segment.get_ld_section())

        last_addr = seg_vram_addr
        last_length = seg_end - seg_start

    # Write ldscript
    write_ldscript(config['basename'], repo_path, sections)

    # Write undefined_funcs.txt
    c_predefined_funcs = set(c_funcs.keys())
    to_write = sorted(undefined_funcs - defined_funcs - c_predefined_funcs)
    with open(os.path.join(repo_path,"undefined_funcs.txt"), "w", newline="\n") as f:
        for line in to_write:
            f.write(line + " = 0x" + line[5:13].upper() + ";\n")


if __name__ == "__main__":
    args = parser.parse_args()
    main(args.rom, args.config, args.outdir)
