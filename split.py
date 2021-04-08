#! /usr/bin/python3

from typing import Dict
import argparse
import importlib
import importlib.util
import os
import pylibyaml
import yaml
import pickle
from colorama import Style, Fore
from segtypes.segment import parse_segment_type
from segtypes.n64.code import N64SegCode
from segtypes.linker_entry import LinkerWriter, LinkerWriterFacade
from util import log
from util import options
from util.symbol import Symbol
import sys

parser = argparse.ArgumentParser(description="Split a rom given a rom, a config, and output directory")
parser.add_argument("config", help="path to a compatible config .yaml file")
parser.add_argument("--target", help="path to a file to split (.z64 rom)")
parser.add_argument("--basedir", help="a directory in which to extract the rom")
parser.add_argument("--modes", nargs="+", default="all")
parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
parser.add_argument("--use-cache", action="store_true", help="Only split changed segments in config")

sym_isolated_map: Dict[Symbol, int] = {}

def gather_symbols(symbol_addrs_path):
    symbols = []

    # Manual list of func name / addrs
    if os.path.exists(symbol_addrs_path):
        with open(symbol_addrs_path) as f:
            func_addrs_lines = f.readlines()

        for line in func_addrs_lines:
            line = line.strip()
            if not line == "" and not line.startswith("//"):
                comment_loc = line.find("//")
                line_ext = ""

                if comment_loc != -1:
                    line_ext = line[comment_loc + 2:].strip()
                    line = line[:comment_loc].strip()

                line_split = line.split("=")
                name = line_split[0].strip()
                addr = int(line_split[1].strip()[:-1], 0)

                sym = Symbol(addr, given_name=name)

                if line_ext:
                    for info in line_ext.split(" "):
                        if info.startswith("type:"):
                            type = info.split(":")[1]
                            sym.type = type
                        if info.startswith("size:"):
                            size = int(info.split(":")[1], 0)
                            sym.size = size
                        if info.startswith("rom:"):
                            rom_addr = int(info.split(":")[1], 0)
                            sym.rom = rom_addr
                        if info.startswith("dead:"):
                            sym.dead = True
                symbols.append(sym)
    return symbols


def get_base_segment_class(seg_type, platform):
    try:
        segmodule = importlib.import_module(f"segtypes.{platform}.{seg_type}")
    except ModuleNotFoundError:
        return None

    return getattr(segmodule, f"{platform.upper()}Seg{seg_type[0].upper()}{seg_type[1:]}")


def get_extension_class(seg_type, platform):
    ext_path = options.get_extensions_path()
    if not ext_path:
        return None

    try:
        ext_spec = importlib.util.spec_from_file_location(f"{platform}.segtypes.{seg_type}", ext_path / f"{seg_type}.py")
        ext_mod = importlib.util.module_from_spec(ext_spec)
        ext_spec.loader.exec_module(ext_mod)
    except Exception as err:
        log.write(err, status="error")
        return None

    return getattr(ext_mod, f"{platform.upper()}Seg{seg_type[0].upper()}{seg_type[1:]}")


def fmt_size(size):
    if size > 1000000:
        return str(size // 1000000) + " MB"
    elif size > 1000:
        return str(size // 1000) + " KB"
    else:
        return str(size) + " B"


def initialize_segments(config_segments):
    seen_segment_names = set()
    ret = []

    for i, segment in enumerate(config_segments[:-1]):
        seg_type = parse_segment_type(segment)

        platform = options.get("platform", "n64")

        segment_class = get_base_segment_class(seg_type, platform)
        if segment_class == None:
            # Look in extensions
            segment_class = get_extension_class(seg_type, platform)

        if segment_class == None:
            log.write(f"fatal error: could not load segment type '{seg_type}'\n(hint: confirm your extension directory is configured correctly)", status="error")
            sys.exit(2)

        segment = segment_class(segment, config_segments[i + 1])

        if segment_class.require_unique_name:
            if segment.name in seen_segment_names:
                segment.error("segment name is not unique")
            seen_segment_names.add(segment.name)

        ret.append(segment)

    return ret

def is_symbol_isolated(symbol, all_segments):
    if symbol in sym_isolated_map:
        return sym_isolated_map[symbol]

    relevant_segs = 0

    for segment in all_segments:
        if segment.contains_vram(symbol.vram_start):
            relevant_segs += 1
            if relevant_segs > 1:
                break

    sym_isolated_map[symbol] = relevant_segs < 2
    return sym_isolated_map[symbol]

def get_segment_symbols(segment, all_symbols, all_segments):
    seg_syms = {}
    other_syms = {}

    for symbol in all_symbols:
        if is_symbol_isolated(symbol, all_segments) and not symbol.rom:
            if segment.contains_vram(symbol.vram_start):
                if symbol.vram_start not in seg_syms:
                    seg_syms[symbol.vram_start] = []
                seg_syms[symbol.vram_start].append(symbol)
            else:
                if symbol.vram_start not in other_syms:
                    other_syms[symbol.vram_start] = []
                other_syms[symbol.vram_start].append(symbol)
        else:
            if symbol.rom and segment.contains_rom(symbol.rom):
                if symbol.vram_start not in seg_syms:
                    seg_syms[symbol.vram_start] = []
                seg_syms[symbol.vram_start].append(symbol)
            else:
                if symbol.vram_start not in other_syms:
                    other_syms[symbol.vram_start] = []
                other_syms[symbol.vram_start].append(symbol)

    return seg_syms, other_syms

def do_statistics(seg_sizes, rom_bytes, seg_split, seg_cached):
    unk_size = seg_sizes.get("unk", 0)
    rest_size = 0
    total_size = len(rom_bytes)

    for typ in seg_sizes:
        if typ != "unk":
            rest_size += seg_sizes[typ]

    assert(unk_size + rest_size == total_size)

    known_ratio = rest_size / total_size
    unk_ratio = unk_size / total_size

    log.write(f"Split {fmt_size(rest_size)} ({known_ratio:.2%}) in defined segments")
    for typ in seg_sizes:
        if typ != "unk":
            tmp_size = seg_sizes[typ]
            tmp_ratio = tmp_size / total_size
            log.write(f"{typ:>20}: {fmt_size(tmp_size):>8} ({tmp_ratio:.2%}) {Fore.GREEN}{seg_split[typ]} split{Style.RESET_ALL}, {Style.DIM}{seg_cached[typ]} cached")
    log.write(f"{'unknown':>20}: {fmt_size(unk_size):>8} ({unk_ratio:.2%}) from unknown bin files")

def main(config_path, base_dir, target_path, modes, verbose, use_cache=True) -> LinkerWriterFacade:
    # Load config
    with open(config_path) as f:
        config = yaml.load(f.read(), Loader=yaml.SafeLoader)

    options.initialize(config, config_path, base_dir, target_path)
    options.set("modes", modes)
    options.set("verbose", verbose)

    with options.get_target_path().open("rb") as f:
        rom_bytes = f.read()

    # Create main output dir
    options.get_base_path().mkdir(parents=True, exist_ok=True)

    symbol_addrs_path = options.get_symbol_addrs_path()
    all_symbols = gather_symbols(symbol_addrs_path)
    symbol_ranges = [s for s in all_symbols if s.size > 4]
    platform = options.get("platform", "n64")

    processed_segments = []

    LWClass = LinkerWriter if options.mode_active("ld") else LinkerWriterFacade
    linker_writer = LWClass(options.get("shiftable", False))

    seg_sizes: Dict[str, int] = {}
    seg_split: Dict[str, int] = {}
    seg_cached: Dict[str, int] = {}

    # Load cache
    if use_cache:
        try:
            with options.get_cache_path().open("rb") as f:
                cache = pickle.load(f)
        except Exception:
            cache = {}
    else:
        cache = {}
    
    # invalidate entire cache if options change
    if cache.get("__options__") != config.get("options"):
        cache = {
            "__options__": config.get("options"),
        }

    # Initialize segments
    all_segments = initialize_segments(config["segments"])

    for segment in all_segments:
        if platform == "n64" and type(segment) == N64SegCode: # remove special-case sometime
            segment_symbols, other_symbols = get_segment_symbols(segment, all_symbols, all_segments)
            segment.seg_symbols = segment_symbols
            segment.ext_symbols = other_symbols
            segment.all_symbols = all_symbols
            segment.symbol_ranges = symbol_ranges

        typ = segment.type
        if segment.type == "bin" and segment.is_name_default():
            typ = "unk"

        if typ not in seg_sizes:
            seg_sizes[typ] = 0
            seg_split[typ] = 0
            seg_cached[typ] = 0
        seg_sizes[typ] += segment.size

        if len(segment.errors) == 0:
            if segment.should_run():
                # Check cache
                cached = segment.cache()
                if use_cache and cached == cache.get(segment.unique_id()):
                    # Cache hit
                    seg_cached[typ] += 1
                else:
                    # Cache miss; split
                    cache[segment.unique_id()] = cached

                    segment.did_run = True
                    segment.split(rom_bytes)

                    if len(segment.errors) == 0:
                        processed_segments.append(segment)

                    seg_split[typ] += 1

        log.dot(status=segment.status())
        linker_writer.add(segment)

    for segment in processed_segments:
        segment.postsplit(processed_segments)
        log.dot(status=segment.status())

    linker_writer.finish(options.get_ld_script_path())

    # Write linker symbols header
    ld_header_path = options.get_linker_symbol_header_path()
    if options.mode_active("ld") and ld_header_path is not None:
        with open(ld_header_path, "w", newline="\n") as f:
            f.write("#ifndef _HEADER_SYMBOLS_H_\n")
            f.write("#define _HEADER_SYMBOLS_H_\n\n")
            for segment in all_segments:
                f.write(f"extern Addr {segment.name}_ROM_START;\n")
                f.write(f"extern Addr {segment.name}_ROM_END;\n")
                f.write(f"extern Addr {segment.name}_VRAM;\n")
            f.write("\n#endif\n")

    # Write undefined_funcs_auto.txt
    to_write = [s for s in all_symbols if s.referenced and not s.defined and s.type == "func"]
    if len(to_write) > 0:
        with open(options.get_undefined_funcs_auto_path(), "w", newline="\n") as f:
            for symbol in to_write:
                f.write(f"{symbol.name} = 0x{symbol.vram_start:X};\n")

    # write undefined_syms_auto.txt
    to_write = [s for s in all_symbols if s.referenced and not s.defined and not s.type == "func"]
    if len(to_write) > 0:
        with open(options.get_undefined_syms_auto_path(), "w", newline="\n") as f:
            for symbol in to_write:
                f.write(f"{symbol.name} = 0x{symbol.vram_start:X};\n")

    # print warnings during split/postsplit
    for segment in all_segments:
        if len(segment.warnings) > 0:
            log.write(f"{Style.DIM}0x{segment.rom_start:06X}{Style.RESET_ALL} {segment.type} {Style.BRIGHT}{segment.name}{Style.RESET_ALL}:")

            for warn in segment.warnings:
                log.write("warning: " + warn, status="warn")

            log.write("") # empty line

    # Statistics
    do_statistics(seg_sizes, rom_bytes, seg_split, seg_cached)

    # Save cache
    if cache != {} and use_cache:
        if verbose:
            print("Writing cache")
        with open(options.get_cache_path(), "wb") as f:
            pickle.dump(cache, f)

    return linker_writer

if __name__ == "__main__":
    args = parser.parse_args()
    main(args.config, args.basedir, args.target, args.modes, args.verbose, args.use_cache)
