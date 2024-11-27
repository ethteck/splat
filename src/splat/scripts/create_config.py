#! /usr/bin/env python3

import argparse
import sys
from pathlib import Path

from ..util.n64 import find_code_length, rominfo
from ..util.psx import psxexeinfo
from ..util import log


def main(file_path: Path):
    if not file_path.exists():
        sys.exit(f"File {file_path} does not exist ({file_path.absolute()})")
    if file_path.is_dir():
        sys.exit(f"Path {file_path} is a directory ({file_path.absolute()})")

    # Check for N64 ROM
    if file_path.suffix.lower() == ".n64" or file_path.suffix.lower() == ".z64":
        create_n64_config(file_path)
        return

    file_bytes = file_path.read_bytes()

    # Check for PSX executable
    if file_bytes[0:8] == b"PS-X EXE":
        create_psx_config(file_path, file_bytes)
        return

    log.error(f"create_config does not support the file format of '{file_path}'")


def remove_invalid_path_characters(p: str) -> str:
    invalid_characters = ["<", ">", ":", '"', "/", "\\", "|", "?", "*"]
    for invalid in invalid_characters:
        p = p.replace(invalid, "_")
    return p


def create_n64_config(rom_path: Path):
    rom_bytes = rominfo.read_rom(rom_path)

    rom = rominfo.get_info(rom_path, rom_bytes)
    basename = rom.name.replace(" ", "").lower()
    cleaned_basename = remove_invalid_path_characters(basename)

    header = f"""\
name: {rom.name.title()} ({rom.get_country_name()})
sha1: {rom.sha1}
options:
  basename: {basename}
  target_path: {rom_path.with_suffix(".z64")}
  elf_path: build/{cleaned_basename}.elf
  base_path: .
  platform: n64
  compiler: {rom.compiler}

  # asm_path: asm
  # src_path: src
  # build_path: build
  # create_asm_dependencies: True

  ld_script_path: {cleaned_basename}.ld
  ld_dependencies: True

  find_file_boundaries: True
  header_encoding: {rom.header_encoding}

  o_as_suffix: True
  use_legacy_include_asm: False
  mips_abi_float_regs: o32

  asm_function_macro: glabel
  asm_jtbl_label_macro: jlabel
  asm_data_macro: dlabel

  # section_order: [".text", ".data", ".rodata", ".bss"]
  # auto_link_sections: [".data", ".rodata", ".bss"]

  symbol_addrs_path:
    - symbol_addrs.txt
  reloc_addrs_path:
    - reloc_addrs.txt

  # undefined_funcs_auto_path: undefined_funcs_auto.txt
  # undefined_syms_auto_path: undefined_syms_auto.txt

  extensions_path: tools/splat_ext

  # string_encoding: ASCII
  # data_string_encoding: ASCII
  rodata_string_guesser_level: 2
  data_string_guesser_level: 2
  # libultra_symbols: True
  # hardware_regs: True
  # gfx_ucode: # one of [f3d, f3db, f3dex, f3dexb, f3dex2]
"""

    # Start analysing after the entrypoint segment.
    first_section_end = find_code_length.run(
        rom_bytes, 0x1000 + rom.entrypoint_info.segment_size(), rom.entry_point
    )

    extra_message = ""
    if not rom.entrypoint_info.traditional_entrypoint:
        extra_message = " # This game uses a non-traditional entrypoint, meaning splat's analysis may be wrong"

    segments = f"""\
segments:
  - name: header
    type: header
    start: 0x0

  - name: boot
    type: bin
    start: 0x40

  - name: entry{extra_message}
    type: code
    start: 0x1000
    vram: 0x{rom.entry_point:X}
    subsegments:
      - [0x1000, hasm]
"""
    if rom.entrypoint_info.data_size > 0:
        segments += f"""\
      - [0x{0x1000 + rom.entrypoint_info.entry_size:X}, data]
"""

    main_rom_start = 0x1000 + rom.entrypoint_info.segment_size()
    segments += f"""\

  - name: main
    type: code
    start: 0x{main_rom_start:X}
    vram: 0x{rom.entry_point + rom.entrypoint_info.segment_size():X}
    follows_vram: entry
"""

    if rom.entrypoint_info.bss_size is not None:
        segments += f"""\
    bss_size: 0x{rom.entrypoint_info.bss_size:X}
"""

    segments += f"""\
    subsegments:
      - [0x{main_rom_start:X}, asm]
"""

    if (
        rom.entrypoint_info.bss_size is not None
        and rom.entrypoint_info.bss_start_address is not None
        and first_section_end > main_rom_start
    ):
        bss_start = rom.entrypoint_info.bss_start_address - rom.entry_point + 0x1000
        # first_section_end points to the start of data
        segments += f"""\
      - [0x{first_section_end:X}, data]
      - {{ type: bss, vram: 0x{rom.entrypoint_info.bss_start_address:08X} }}
"""
        # Point next segment to the detected end of the main one
        first_section_end = bss_start

    if first_section_end > main_rom_start:
        segments += f"""\

  - type: bin
    start: 0x{first_section_end:X}
    follows_vram: main
"""

    segments += f"""\

  - [0x{rom.size:X}]
"""

    out_file = f"{cleaned_basename}.yaml"
    with open(out_file, "w", newline="\n") as f:
        print(f"Writing config to {out_file}")
        f.write(header)
        f.write(segments)


def create_psx_config(exe_path: Path, exe_bytes: bytes):
    exe = psxexeinfo.PsxExe.get_info(exe_path, exe_bytes)
    basename = exe_path.name.replace(" ", "").lower()
    cleaned_basename = remove_invalid_path_characters(basename)

    header = f"""\
name: {exe_path.name}
sha1: {exe.sha1}
options:
  basename: {basename}
  target_path: {exe_path}
  elf_path: build/{cleaned_basename}.elf
  base_path: .
  platform: psx
  compiler: PSYQ

  # asm_path: asm
  # src_path: src
  # build_path: build
  # create_asm_dependencies: True

  ld_script_path: {cleaned_basename}.ld
  ld_dependencies: True

  find_file_boundaries: False
  gp_value: 0x{exe.initial_gp:08X}

  o_as_suffix: True
  use_legacy_include_asm: False

  asm_function_macro: glabel
  asm_jtbl_label_macro: jlabel
  asm_data_macro: dlabel

  section_order: [".rodata", ".text", ".data", ".bss"]
  # auto_link_sections: [".data", ".rodata", ".bss"]

  symbol_addrs_path:
    - symbol_addrs.txt
  reloc_addrs_path:
    - reloc_addrs.txt

  # undefined_funcs_auto_path: undefined_funcs_auto.txt
  # undefined_syms_auto_path: undefined_syms_auto.txt

  extensions_path: tools/splat_ext

  subalign: 2

  string_encoding: ASCII
  data_string_encoding: ASCII
  rodata_string_guesser_level: 2
  data_string_guesser_level: 2
"""

    segments = f"""\
segments:
  - name: header
    type: header
    start: 0x0

  - name: main
    type: code
    start: 0x800
    vram: 0x{exe.destination_vram:X}
    # bss_size: Please fill out this value when you figure out the bss size
    subsegments:
"""
    text_offset = exe.text_offset
    if text_offset != 0x800:
        segments += f"""\
      - [0x800, rodata, 800]
"""
    segments += f"""\
      - [0x{text_offset:X}, asm, {text_offset:X}] # estimated
"""

    if exe.data_offset != 0:
        data_offset = exe.data_offset
        segments += f"""\
      - [0x{data_offset:X}, data, {data_offset:X}] # estimated
"""

    segments += f"""\
  - [0x{exe.size:X}]
"""

    out_file = f"{cleaned_basename}.yaml"
    with open(out_file, "w", newline="\n") as f:
        print(f"Writing config to {out_file}")
        f.write(header)
        f.write(segments)


def add_arguments_to_parser(parser: argparse.ArgumentParser):
    parser.add_argument(
        "file",
        help="Path to a .z64/.n64 ROM or PSX executable",
    )


def process_arguments(args: argparse.Namespace):
    main(Path(args.file))


script_description = "Create a splat config from an N64 ROM or PSX executable."


def add_subparser(subparser: argparse._SubParsersAction):
    parser = subparser.add_parser(
        "create_config", help=script_description, description=script_description
    )
    add_arguments_to_parser(parser)
    parser.set_defaults(func=process_arguments)


parser = argparse.ArgumentParser(description=script_description)
add_arguments_to_parser(parser)

if __name__ == "__main__":
    args = parser.parse_args()
    process_arguments(args)
