#! /usr/bin/python3

import argparse
import importlib
import os
import re
from pathlib import Path
import segtypes
import sys
import yaml
from segtypes.code import N64SegCode

parser = argparse.ArgumentParser(description="Split a rom given a rom, a config, and output directory")
parser.add_argument("rom", help="path to a .z64 rom")
parser.add_argument("config", help="path to a compatible config .yaml file")
parser.add_argument("outdir", help="a directory in which to extract the rom")
parser.add_argument('--modes', nargs='+', choices=["ld", "bin", "asm", "all", "makefile", ""])


def write_ldscript(rom_name, repo_path, sections):
    mid = ""
    for section in sections:
        mid += section
    
    with open(os.path.join(repo_path, rom_name + ".ld"), "w", newline="\n") as f:
        f.write("SECTIONS\n{\n" + mid + "}")


def parse_segment_start(segment):
    return segment[0] if "start" not in segment else segment["start"]


def parse_segment_type(segment):
    if type(segment) is dict:
        return segment["type"]
    else:
        return segment[1]


def parse_segment_name(segment):
    if type(segment) is dict:
        return segment["name"]
    else:
        if len(segment) >= 3 and type(segment[2]) is str:
            return segment[2]
        else:
            return "{:X}".format(parse_segment_start(segment))


def parse_segment_vram(segment):
    if type(segment) is dict:
        if "vram" in segment:
            return segment["vram"]
        else:
            return 0
    else:
        if len(segment) >=3 and type(segment[-1]) is int:
            return segment[-1]
        else:
            return 0


def parse_file_start(split_file):
    return split_file[0] if "start" not in split_file else split_file["start"]


def parse_segment_files(segment, seg_start, seg_end, seg_name, seg_vram):
    ret = []
    if "files" in segment:
        for i, split_file in enumerate(segment["files"]):
            if type(split_file) is dict:
                start = split_file["start"]
                end = split_file["end"]
                name = "{}_{:X}".format(parse_segment_name(segment), start) if "name" not in split_file else split_file["name"]
                subtype = split_file["type"]
            else:
                start = split_file[0]
                end = seg_end if i == len(segment["files"]) - 1 else segment["files"][i + 1][0]
                name = "{}_{:X}".format(parse_segment_name(segment), start) if len(split_file) < 3 else split_file[2]
                subtype = split_file[1]

            vram = seg_vram + (start - seg_start)

            fl = {"start": start, "end": end, "name": name, "vram": vram, "subtype": subtype}

            ret.append(fl)
    else:
        fl = {"start": seg_start, "end": seg_end, "name": seg_name, "vram": seg_vram, "subtype": "c"} # TODO make this better, don't assume code
        ret.append(fl)
    return ret


def gather_c_funcs(repo_path):
    funcs = {}
    labels_to_add = set()

    funcs_path = os.path.join(repo_path, "include", "functions.h")
    if os.path.exists(funcs_path):
        with open(funcs_path) as f:
            func_lines = f.readlines()
        
        for line in func_lines:
            if line.startswith("/* 0x"):
                line_split = line.strip().split(" ")
                addr_comment = line_split[1]
                addr = "func_" + addr_comment[2:10]
                name = line_split[4][:line_split[4].find("(")]
                
                # We need to add marked functions' glabels in asm
                if len(addr_comment) > 10 and addr_comment[10] == '!':
                    labels_to_add.add(name)
                
                funcs[addr] = name
    
    # Manual list of func name / addrs
    func_addrs_path = os.path.join(repo_path, "tools", "func_addrs.txt")
    if os.path.exists(func_addrs_path):
        with open(func_addrs_path) as f:
            func_addrs_lines = f.readlines()

        for line in func_addrs_lines:
            line_split = line.strip().split(";")
            name = line_split[0]
            if name.startswith("!"):
                name = name[1:]
                labels_to_add.add(name)

            addr = "func_" + line_split[1][2:10]
            funcs[addr] = name

    return funcs, labels_to_add


def gather_c_variables(repo_path):
    vars = {}

    vars_path = os.path.join(repo_path, "include", "variables.h")
    if os.path.exists(vars_path):
        with open(vars_path) as f:
            vars_lines = f.readlines()
        
        for line in vars_lines:
            if line.startswith("/* 0x"):
                line_split = line.strip().split(" ")
                addr_comment = line_split[1]
                addr = int(addr_comment, 0)
                
                name = line_split[-1][:re.search(r'[\\[;]', line_split[-1]).start()]

                vars[addr] = name

    undefined_syms_path = os.path.join(repo_path, "undefined_syms.txt")
    if os.path.exists(undefined_syms_path):
        with open(undefined_syms_path) as f:
            us_lines = f.readlines()
        
        for line in us_lines:
            line = line.strip()
            if not line == "" and not line.startswith("//"):
                line_split = line.split("=")
                name = line_split[0].strip()
                addr = int(line_split[1].strip()[:-1], 0)
                vars[addr] = name

    return vars


def main(rom_path, config_path, repo_path, modes):
    create_ld = "ld" in modes or "all" in modes
    create_asm = "asm" in modes or "all" in modes
    create_makefile = "makefile" in modes or "all" in modes

    with open(rom_path, "rb") as f:
        rom_bytes = f.read()

    # Create main output dir
    Path(repo_path).mkdir(parents=True, exist_ok=True)

    # Load config
    with open(config_path) as f:
        config = yaml.safe_load(f.read())

    options = config.get("options")

    c_funcs, c_func_labels_to_add = gather_c_funcs(repo_path)
    c_vars = gather_c_variables(repo_path)
    
    segments = []
    sections = []

    defined_funcs = set()
    undefined_funcs = set()
    
    # Initialize segments
    for i, segment in enumerate(config['segments']):
        if len(segment) == 1:
            # We're at the end
            continue

        seg_start = parse_segment_start(segment)
        seg_end = parse_segment_start(config['segments'][i + 1])
        seg_type = parse_segment_type(segment)
        seg_name = parse_segment_name(segment)
        seg_vram = parse_segment_vram(segment)
        seg_files = parse_segment_files(segment, seg_start, seg_end, seg_name, seg_vram)

        segmodule = importlib.import_module("segtypes." + seg_type)
        segment_class = getattr(segmodule, "N64Seg" + seg_type.title())

        segment = segment_class(seg_start, seg_end, seg_type, seg_name, seg_vram, seg_files, options)
        segments.append(segment)

        if type(segment) == N64SegCode:
            segment.all_functions = defined_funcs
            segment.c_functions = c_funcs
            segment.c_variables = c_vars
            segment.c_labels_to_add = c_func_labels_to_add
            segment.split(rom_bytes, repo_path)

            defined_funcs |= segment.glabels_added
            undefined_funcs |= segment.glabels_to_add
        else:
            segment.split(rom_bytes, repo_path)

        sections.append(segment.get_ld_section())

    # Write ldscript
    write_ldscript(config['basename'], repo_path, sections)

    # Write undefined_funcs.txt
    c_predefined_funcs = set(c_funcs.keys())
    to_write = sorted(undefined_funcs - defined_funcs - c_predefined_funcs)
    if len(to_write) > 0:
        with open(os.path.join(repo_path, "undefined_funcs.txt"), "w", newline="\n") as f:
            for line in to_write:
                f.write(line + " = 0x" + line[5:13].upper() + ";\n")


if __name__ == "__main__":
    args = parser.parse_args()
    main(args.rom, args.config, args.outdir, args.modes)
