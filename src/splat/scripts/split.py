#! /usr/bin/env python3

import argparse
import hashlib
import importlib
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pathlib import Path

from .. import __package_name__, __version__
from ..disassembler import disassembler_instance
from ..util import cache_handler, progress_bar, vram_classes, statistics

# This unused import makes the yaml library faster. don't remove
import pylibyaml  # pyright: ignore
import yaml

from colorama import Fore, Style
from intervaltree import Interval, IntervalTree
import sys

from ..segtypes.linker_entry import (
    LinkerWriter,
    get_segment_vram_end_symbol_name,
)
from ..segtypes.segment import Segment
from ..util import log, options, palettes, symbols, relocs

linker_writer: LinkerWriter
config: Dict[str, Any]

segment_roms: IntervalTree = IntervalTree()
segment_rams: IntervalTree = IntervalTree()


def initialize_segments(config_segments: Union[dict, list]) -> List[Segment]:
    global segment_roms
    global segment_rams

    segment_roms = IntervalTree()
    segment_rams = IntervalTree()

    segments_by_name: Dict[str, Segment] = {}
    ret: List[Segment] = []

    last_rom_end = 0

    for i, seg_yaml in enumerate(config_segments):
        # end marker
        if isinstance(seg_yaml, list) and len(seg_yaml) == 1:
            continue

        seg_type = Segment.parse_segment_type(seg_yaml)

        segment_class = Segment.get_class_for_type(seg_type)

        this_start, is_auto_segment = Segment.parse_segment_start(seg_yaml)

        j = i + 1
        while j < len(config_segments):
            next_start, next_is_auto_segment = Segment.parse_segment_start(
                config_segments[j]
            )
            if next_start is not None:
                break
            j += 1
        if next_start is None:
            log.error(
                "Next segment address could not be found. Segments list must end with a rom end pos marker ([0x10000000])"
            )

        if segment_class.is_noload():
            # Pretend bss's rom address is after the last actual rom segment
            this_start = last_rom_end
            # and it has a rom size of zero
            next_start = last_rom_end

        segment: Segment = Segment.from_yaml(
            segment_class, seg_yaml, this_start, next_start, None
        )

        if segment.require_unique_name:
            if segment.name in segments_by_name:
                log.error(f"segment name '{segment.name}' is not unique")

            segments_by_name[segment.name] = segment

        ret.append(segment)
        if (
            isinstance(segment.rom_start, int)
            and isinstance(segment.rom_end, int)
            and segment.rom_start != segment.rom_end
        ):
            segment_roms.addi(segment.rom_start, segment.rom_end, segment)
        if (
            isinstance(segment.vram_start, int)
            and isinstance(segment.vram_end, int)
            and segment.vram_start != segment.vram_end
        ):
            segment_rams.addi(segment.vram_start, segment.vram_end, segment)

        if next_start is not None:
            last_rom_end = next_start

    for segment in ret:
        if segment.given_follows_vram:
            if segment.given_follows_vram not in segments_by_name:
                log.error(
                    f"segment '{segment.given_follows_vram}', the 'follows_vram' value for segment '{segment.name}', does not exist"
                )
            segment.given_vram_symbol = get_segment_vram_end_symbol_name(
                segments_by_name[segment.given_follows_vram]
            )

    if ret[-1].type == "pad":
        log.error(
            "Last segment in config cannot be a pad segment; see https://github.com/ethteck/splat/wiki/Segments#pad"
        )

    return ret


def assign_symbols_to_segments():
    for symbol in symbols.all_symbols:
        if symbol.segment:
            continue

        if symbol.rom:
            cands: Set[Interval] = segment_roms[symbol.rom]
            if len(cands) > 1:
                log.error("multiple segments rom overlap symbol", symbol)
            elif len(cands) == 0:
                log.error("no segment rom overlaps symbol", symbol)
            else:
                cand: Interval = cands.pop()
                seg: Segment = cand.data
                seg.add_symbol(symbol)
        else:
            cands = segment_rams[symbol.vram_start]
            segs: List[Segment] = [cand.data for cand in cands]
            for seg in segs:
                if not seg.get_exclusive_ram_id():
                    seg.add_symbol(symbol)


def merge_configs(main_config, additional_config):
    # Merge rules are simple
    # For each key in the dictionary
    # - If list then append to list
    # - If a dictionary then repeat merge on sub dictionary entries
    # - Else assume string or number and replace entry

    for curkey in additional_config:
        if curkey not in main_config:
            main_config[curkey] = additional_config[curkey]
        elif type(main_config[curkey]) != type(additional_config[curkey]):
            log.error(f"Type for key {curkey} in configs does not match")
        else:
            # keys exist and match, see if a list to append
            if type(main_config[curkey]) == list:
                main_config[curkey] += additional_config[curkey]
            elif type(main_config[curkey]) == dict:
                # need to merge sub areas
                main_config[curkey] = merge_configs(
                    main_config[curkey], additional_config[curkey]
                )
            else:
                # not a list or dictionary, must be a number or string, overwrite
                main_config[curkey] = additional_config[curkey]

    return main_config


def brief_seg_name(seg: Segment, limit: int, ellipsis="…") -> str:
    s = seg.name.strip()
    if len(s) > limit:
        return s[:limit].strip() + ellipsis
    return s


# Return a mapping of vram classes to segments that need to be part of their vram symbol's calculation
def calc_segment_dependences(
    all_segments: List[Segment],
) -> Dict[vram_classes.VramClass, List[Segment]]:
    # Map vram class names to segments that have that vram class
    vram_class_to_segments: Dict[str, List[Segment]] = {}
    for seg in all_segments:
        if seg.vram_class is not None:
            if seg.vram_class.name not in vram_class_to_segments:
                vram_class_to_segments[seg.vram_class.name] = []
            vram_class_to_segments[seg.vram_class.name].append(seg)

    # Map vram class names to segments that the vram class follows
    vram_class_to_follows_segments: Dict[vram_classes.VramClass, List[Segment]] = {}
    for vram_class in vram_classes._vram_classes.values():
        if vram_class.follows_classes:
            vram_class_to_follows_segments[vram_class] = []

            for follows_class in vram_class.follows_classes:
                if follows_class in vram_class_to_segments:
                    vram_class_to_follows_segments[
                        vram_class
                    ] += vram_class_to_segments[follows_class]
    return vram_class_to_follows_segments


def initialize_config(
    config_path: List[str],
    modes: Optional[List[str]],
    verbose: bool,
    disassemble_all: bool = False,
) -> Dict[str, Any]:
    config: Dict[str, Any] = {}
    for entry in config_path:
        with open(entry) as f:
            additional_config = yaml.load(f.read(), Loader=yaml.SafeLoader)
        config = merge_configs(config, additional_config)

    vram_classes.initialize(config.get("vram_classes"))

    options.initialize(config, config_path, modes, verbose, disassemble_all)

    return config


def read_target_binary() -> bytes:
    rom_bytes = options.opts.target_path.read_bytes()

    if "sha1" in config:
        sha1 = hashlib.sha1(rom_bytes).hexdigest()
        e_sha1 = config["sha1"].lower()
        if e_sha1 != sha1:
            log.error(f"sha1 mismatch: expected {e_sha1}, was {sha1}")
    else:
        log.write("Warning: no sha1 in config")

    return rom_bytes


def initialize_platform(rom_bytes: bytes):
    platform_module = importlib.import_module(
        f"{__package_name__}.platforms.{options.opts.platform}"
    )
    platform_init = getattr(platform_module, "init")
    platform_init(rom_bytes)

    return platform_module


def initialize_all_symbols(all_segments: List[Segment]):
    # Load and process symbols
    symbols.initialize(all_segments)
    relocs.initialize()

    # Assign symbols to segments
    assign_symbols_to_segments()

    if options.opts.is_mode_active("code"):
        symbols.initialize_spim_context(all_segments)
        relocs.initialize_spim_context()


def do_scan(
    all_segments: List[Segment],
    rom_bytes: bytes,
    stats: statistics.Statistics,
    cache: cache_handler.Cache,
):
    processed_segments: List[Segment] = []

    scan_bar = progress_bar.get_progress_bar(all_segments)
    for segment in scan_bar:
        assert isinstance(segment, Segment)
        scan_bar.set_description(f"Scanning {brief_seg_name(segment, 20)}")

        for ty, sub_stats in segment.statistics.items():
            stats.add_size(ty, sub_stats.size)

        if segment.should_scan():
            # Check cache but don't write anything
            if cache.check_cache_hit(segment, False):
                continue

            segment.did_run = True
            segment.scan(rom_bytes)

            processed_segments.append(segment)

            for ty, sub_stats in segment.statistics.items():
                stats.count_split(ty, sub_stats.count)

    symbols.mark_c_funcs_as_defined()
    return processed_segments


def do_split(
    all_segments: List[Segment],
    rom_bytes: bytes,
    stats: statistics.Statistics,
    cache: cache_handler.Cache,
):
    split_bar = progress_bar.get_progress_bar(all_segments)
    for segment in split_bar:
        assert isinstance(segment, Segment)
        split_bar.set_description(f"Splitting {brief_seg_name(segment, 20)}")

        if cache.check_cache_hit(segment, True):
            for ty, sub_stats in segment.statistics.items():
                stats.count_cached(ty, sub_stats.count)
            continue

        if segment.should_split():
            segment_bytes = rom_bytes
            if segment.file_path:
                with open(segment.file_path, "rb") as segment_input_file:
                    segment_bytes = segment_input_file.read()
            segment.split(segment_bytes)


def write_linker_script(all_segments: List[Segment]) -> LinkerWriter:
    vram_class_dependencies = calc_segment_dependences(all_segments)
    vram_classes_to_search = set(vram_class_dependencies.keys())

    max_vram_end_insertion_points: Dict[Segment, List[Tuple[str, List[Segment]]]] = {}
    for seg in reversed(all_segments):
        if seg.vram_class in vram_classes_to_search:
            assert seg.vram_class.vram_symbol is not None
            if seg not in max_vram_end_insertion_points:
                max_vram_end_insertion_points[seg] = []
            max_vram_end_insertion_points[seg].append(
                (
                    seg.vram_class.vram_symbol,
                    vram_class_dependencies[seg.vram_class],
                )
            )
            vram_classes_to_search.remove(seg.vram_class)

    linker_writer = LinkerWriter()
    linker_bar = progress_bar.get_progress_bar(all_segments)

    # Check options are valid
    partial_linking = options.opts.ld_partial_linking
    partial_scripts_path = options.opts.ld_partial_scripts_path
    segments_path = options.opts.ld_partial_build_segments_path
    if partial_linking:
        if partial_scripts_path is None:
            log.error(
                "Partial linking is enabled but `ld_partial_scripts_path` has not been set"
            )
        if options.opts.ld_partial_build_segments_path is None:
            log.error(
                "Partial linking is enabled but `ld_partial_build_segments_path` has not been set"
            )

    for segment in linker_bar:
        assert isinstance(segment, Segment)
        linker_bar.set_description(f"Linker script {brief_seg_name(segment, 20)}")
        max_vram_syms = max_vram_end_insertion_points.get(segment, [])

        if options.opts.ld_partial_linking:
            linker_writer.add_referenced_partial_segment(segment, max_vram_syms)

            # Create linker script for segment
            sub_linker_writer = LinkerWriter(is_partial=True)
            sub_linker_writer.add_partial_segment(segment)

            assert partial_scripts_path is not None
            assert segments_path is not None

            seg_name = segment.get_cname()

            sub_linker_writer.save_linker_script(
                partial_scripts_path / f"{seg_name}.ld"
            )
            if options.opts.ld_dependencies:
                sub_linker_writer.save_dependencies_file(
                    partial_scripts_path / f"{seg_name}.d",
                    segments_path / f"{seg_name}.o",
                )
        else:
            linker_writer.add(segment, max_vram_syms)

    linker_writer.save_linker_script(options.opts.ld_script_path)
    linker_writer.save_symbol_header()

    if options.opts.ld_dependencies:
        elf_path = options.opts.elf_path
        if elf_path is None:
            log.error(
                "Generation of dependency file for linker script requested but `elf_path` was not provided in the yaml options"
            )
        linker_writer.save_dependencies_file(
            options.opts.ld_script_path.with_suffix(".d"), elf_path
        )

    return linker_writer


def write_ld_dependencies(linker_writer: LinkerWriter):
    if options.opts.ld_dependencies:
        elf_path = options.opts.elf_path
        if elf_path is None:
            log.error(
                "Generation of dependency file for linker script requested but `elf_path` was not provided in the yaml options"
            )
        linker_writer.save_dependencies_file(
            options.opts.ld_script_path.with_suffix(".d"), elf_path
        )


def write_elf_sections_file(all_segments: List[Segment]):
    # write elf_sections.txt - this only lists the generated sections in the elf, not subsections
    # that the elf combines into one section
    if options.opts.elf_section_list_path:
        section_list = ""
        for segment in all_segments:
            section_list += "." + segment.get_cname() + "\n"
        options.opts.elf_section_list_path.parent.mkdir(parents=True, exist_ok=True)
        with options.opts.elf_section_list_path.open("w", newline="\n") as f:
            f.write(section_list)


def write_undefined_auto(to_write: List[symbols.Symbol], file_path: Path):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", newline="\n") as f:
        for symbol in to_write:
            f.write(f"{symbol.name} = 0x{symbol.vram_start:X};\n")


def write_undefined_funcs_auto():
    if options.opts.create_undefined_funcs_auto:
        to_write = [
            s
            for s in symbols.all_symbols
            if s.referenced and not s.defined and s.type == "func"
        ]
        to_write.sort(key=lambda x: x.vram_start)

        write_undefined_auto(to_write, options.opts.undefined_funcs_auto_path)


def write_undefined_syms_auto():
    if options.opts.create_undefined_syms_auto:
        to_write = [
            s
            for s in symbols.all_symbols
            if s.referenced
            and not s.defined
            and s.type not in {"func", "label", "jtbl_label"}
        ]
        to_write.sort(key=lambda x: x.vram_start)

        write_undefined_auto(to_write, options.opts.undefined_syms_auto_path)


def print_segment_warnings(all_segments: List[Segment]):
    for segment in all_segments:
        if len(segment.warnings) > 0:
            log.write(
                f"{Style.DIM}0x{segment.rom_start:06X}{Style.RESET_ALL} {segment.type} {Style.BRIGHT}{segment.name}{Style.RESET_ALL}:"
            )

            for warn in segment.warnings:
                log.write("warning: " + warn, status="warn")

            log.write("")  # empty line


def dump_symbols() -> None:
    if not options.opts.dump_symbols:
        return

    splat_hidden_folder = options.opts.base_path / ".splat"
    splat_hidden_folder.mkdir(parents=True, exist_ok=True)

    with open(splat_hidden_folder / "splat_symbols.csv", "w") as f:
        f.write(
            "vram_start,given_name,name,type,given_size,size,rom,defined,user_declared,referenced,extract\n"
        )
        for s in sorted(symbols.all_symbols, key=lambda x: x.vram_start):
            f.write(f"{s.vram_start:X},{s.given_name},{s.name},{s.type},")
            if s.given_size is not None:
                f.write(f"0x{s.given_size:X},")
            else:
                f.write("None,")
            f.write(f"{s.size},")
            if s.rom is not None:
                f.write(f"0x{s.rom:X},")
            else:
                f.write("None,")
            f.write(f"{s.defined},{s.user_declared},{s.referenced},{s.extract}\n")

    symbols.spim_context.saveContextToFile(splat_hidden_folder / "spim_context.csv")


def main(
    config_path: List[str],
    modes: Optional[List[str]],
    verbose: bool,
    use_cache: bool = True,
    skip_version_check: bool = False,
    stdout_only: bool = False,
    disassemble_all: bool = False,
):
    if stdout_only:
        progress_bar.out_file = sys.stdout

    # Load config
    global config
    config = initialize_config(config_path, modes, verbose, disassemble_all)

    disassembler_instance.create_disassembler_instance(skip_version_check, __version__)

    rom_bytes = read_target_binary()

    # Create main output dir
    options.opts.base_path.mkdir(parents=True, exist_ok=True)

    stats = statistics.Statistics()

    cache = cache_handler.Cache(config, use_cache, verbose)

    initialize_platform(rom_bytes)

    # Initialize segments
    all_segments = initialize_segments(config["segments"])

    initialize_all_symbols(all_segments)

    # Resolve raster/palette siblings
    if options.opts.is_mode_active("img"):
        palettes.initialize(all_segments)

    # Scan
    do_scan(all_segments, rom_bytes, stats, cache)

    # Split
    do_split(all_segments, rom_bytes, stats, cache)

    if options.opts.is_mode_active(
        "ld"
    ):  # TODO move this to platform initialization when it gets implemented
        global linker_writer
        linker_writer = write_linker_script(all_segments)
        write_ld_dependencies(linker_writer)
        write_elf_sections_file(all_segments)

    # Write undefined_funcs_auto.txt
    write_undefined_funcs_auto()

    # write undefined_syms_auto.txt
    write_undefined_syms_auto()

    # print warnings during split
    print_segment_warnings(all_segments)

    # Statistics
    stats.print_statistics(len(rom_bytes))

    # Save cache
    cache.save(verbose)

    if options.opts.is_mode_active("code"):
        dump_symbols()


def add_arguments_to_parser(parser: argparse.ArgumentParser):
    parser.add_argument(
        "config", help="path to a compatible config .yaml file", nargs="+"
    )
    parser.add_argument("--modes", nargs="+", default="all")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--use-cache", action="store_true", help="Only split changed segments in config"
    )
    parser.add_argument(
        "--skip-version-check",
        action="store_true",
        help="Skips the disassembler's version check",
    )
    parser.add_argument(
        "--stdout-only", help="Print all output to stdout", action="store_true"
    )
    parser.add_argument(
        "--disassemble-all",
        help="Disasemble matched functions and migrated data",
        action="store_true",
    )


def process_arguments(args: argparse.Namespace):
    main(
        args.config,
        args.modes,
        args.verbose,
        args.use_cache,
        args.skip_version_check,
        args.stdout_only,
        args.disassemble_all,
    )


script_description = "Split a rom given a rom, a config, and output directory"


def add_subparser(subparser: argparse._SubParsersAction):
    parser = subparser.add_parser(
        "split", help=script_description, description=script_description
    )
    add_arguments_to_parser(parser)
    parser.set_defaults(func=process_arguments)


parser = argparse.ArgumentParser(description=script_description)
add_arguments_to_parser(parser)

if __name__ == "__main__":
    args = parser.parse_args()
    process_arguments(args)
