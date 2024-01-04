#! /usr/bin/env python3

import argparse
import sys
from pathlib import Path

from ..util.gc import gcinfo
from ..util.n64 import find_code_length, rominfo
from ..util.psx import psxexeinfo


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

    # Check for GC disc image
    if int.from_bytes(file_bytes[0x1C:0x20], byteorder="big") == 0xC2339F3D:
        create_gc_config(file_path, file_bytes)
        return

    # Check for PSX executable
    if file_bytes[0:8] == b"PS-X EXE":
        create_psx_config(file_path, file_bytes)
        return

    # Check for WebAssembly module
    if file_bytes[0:4] == b"\x00asm":
        create_wasm_config(file_path)
        return


def create_n64_config(rom_path: Path):
    rom_bytes = rominfo.read_rom(rom_path)

    rom = rominfo.get_info(rom_path, rom_bytes)
    basename = rom.name.replace(" ", "").lower()

    header = f"""\
name: {rom.name.title()} ({rom.get_country_name()})
sha1: {rom.sha1}
options:
  basename: {basename}
  target_path: {rom_path.with_suffix(".z64")}
  elf_path: build/{basename}.elf
  base_path: .
  platform: n64
  compiler: {rom.compiler}

  # asm_path: asm
  # src_path: src
  # build_path: build
  # create_asm_dependencies: True

  ld_script_path: {basename}.ld
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
  # auto_all_sections: [".data", ".rodata", ".bss"]

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

    first_section_end = find_code_length.run(rom_bytes, 0x1000, rom.entry_point)

    segments = f"""\
segments:
  - name: header
    type: header
    start: 0x0

  - name: boot
    type: bin
    start: 0x40

  - name: entry
    type: code
    start: 0x1000
    vram: 0x{rom.entry_point:X}
    subsegments:
      - [0x1000, hasm]

  - name: main
    type: code
    start: 0x{0x1000 + rom.entrypoint_info.entry_size:X}
    vram: 0x{rom.entry_point + rom.entrypoint_info.entry_size:X}
    follows_vram: entry
"""

    if rom.entrypoint_info.bss_size is not None:
        segments += f"""\
    bss_size: 0x{rom.entrypoint_info.bss_size:X}
"""

    segments += f"""\
    subsegments:
      - [0x{0x1000 + rom.entrypoint_info.entry_size:X}, asm]
"""

    if (
        rom.entrypoint_info.bss_size is not None
        and rom.entrypoint_info.bss_start_address is not None
    ):
        bss_start = rom.entrypoint_info.bss_start_address - rom.entry_point + 0x1000
        # first_section_end points to the start of data
        segments += f"""\
      - [0x{first_section_end:X}, data]
      - {{ start: 0x{bss_start:X}, type: bss, vram: 0x{rom.entrypoint_info.bss_start_address:08X} }}
"""
        # Point next segment to the detected end of the main one
        first_section_end = bss_start

    segments += f"""\

  - type: bin
    start: 0x{first_section_end:X}
    follows_vram: main
  - [0x{rom.size:X}]
"""

    out_file = f"{basename}.yaml"
    with open(out_file, "w", newline="\n") as f:
        print(f"Writing config to {out_file}")
        f.write(header)
        f.write(segments)


def create_gc_config(iso_path: Path, iso_bytes: bytes):
    gc = gcinfo.get_info(iso_path, iso_bytes)
    basename = gc.system_code + gc.game_code + gc.region_code + gc.publisher_code

    header = f"""\
name: \"{gc.name.title()} ({gc.get_region_name()})\"
system_code: {gc.system_code}
game_code: {gc.game_code}
region_code: {gc.region_code}
publisher_code: {gc.publisher_code}
sha1: {gc.sha1}
options:
  filesystem_path: filesystem
  basename: {basename}
  target_path: {iso_path.with_suffix(".iso")}
  base_path: .
  compiler: {gc.compiler}
  platform: gc
  # undefined_funcs_auto: True
  # undefined_funcs_auto_path: undefined_funcs_auto.txt
  # undefined_syms_auto: True
  # undefined_syms_auto_path: undefined_syms_auto.txt
  # symbol_addrs_path: symbol_addrs.txt
  # asm_path: asm
  # src_path: src
  # build_path: build
  # extensions_path: tools/splat_ext
  # section_order: [".text", ".data", ".rodata", ".bss"]
  # auto_all_sections: [".data", ".rodata", ".bss"]
"""

    segments = f"""\
segments:
  - name: filesystem
    type: fst
    path: filesystem/sys/fst.bin
  - name: bootinfo
    type: bootinfo
    path: filesystem/sys/boot.bin
  - name: bi2
    type: bi2
    path: filesystem/sys/bi2.bin
  - name: apploader
    type: apploader
    path: filesystem/sys/apploader.img
  - name: main
    type: dol
    path: filesystem/sys/main.dol
"""

    out_file = f"{basename}.yaml"
    with open(out_file, "w", newline="\n") as f:
        print(f"Writing config to {out_file}")
        f.write(header)
        f.write(segments)


def create_psx_config(exe_path: Path, exe_bytes: bytes):
    exe = psxexeinfo.PsxExe.get_info(exe_path, exe_bytes)
    basename = exe_path.name.replace(" ", "").lower()

    header = f"""\
name: {exe_path.name}
sha1: {exe.sha1}
options:
  basename: {basename}
  target_path: {exe_path}
  base_path: .
  platform: psx
  compiler: GCC

  # asm_path: asm
  # src_path: src
  # build_path: build
  # create_asm_dependencies: True

  ld_script_path: {basename}.ld

  find_file_boundaries: False
  gp_value: 0x{exe.initial_gp:08X}

  o_as_suffix: True
  use_legacy_include_asm: False

  asm_function_macro: glabel
  asm_jtbl_label_macro: jlabel
  asm_data_macro: dlabel

  section_order: [".rodata", ".text", ".data", ".bss"]
  # auto_all_sections: [".data", ".rodata", ".bss"]

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

    out_file = f"{basename}.yaml"
    with open(out_file, "w", newline="\n") as f:
        print(f"Writing config to {out_file}")
        f.write(header)
        f.write(segments)


def create_wasm_config(file_path: Path):
    from wasm_tob import TypeSection, ImportSection, FunctionSection, ExportSection

    basename = file_path.stem

    with open(file_path, "rb") as f:
        raw = f.read()

    offset = 0

    mod_iter = iter(decode_wasm_module_with_length(raw))
    wasm_header, wasm_header_data, wasm_header_len = next(mod_iter)

    header = f"""\
name: {basename}
options:
  basename: {basename}
  target_path: {file_path}
  base_path: .
  platform: wasm
"""

    segments = f"""\
segments:
  - type: header
    start: {hex(offset)}
"""

    SECTION_MAP = {
        TypeSection: "types",
        ImportSection: "imports",
        FunctionSection: "functions",
        ExportSection: "exports",
    }

    offset += wasm_header_len

    for cur_sec, cur_sec_data, cur_sec_len in mod_iter:
        sec_type = type(cur_sec_data.get_decoder_meta()["types"]["payload"])
        sec_type_str = SECTION_MAP[sec_type] if sec_type in SECTION_MAP else "bin"
        # print(cur_sec_data.get_decoder_meta()['types']['payload'])
        # print(f"Segment: {sec_type_str}")

        segments += f"""\
  - type: {sec_type_str} # {sec_type.__name__}
    start: {hex(offset)}
"""
        offset += cur_sec_len

    segments += f"""\
  - [{hex(offset)}] # End marker
"""

    out_file = f"{basename}.yaml"
    with open(out_file, "w", newline="\n") as f:
        print(f"Writing config to {out_file}")
        f.write(header)
        f.write(segments)


def decode_wasm_module_with_length(module, decode_name_subsections=False):
    from collections import namedtuple
    from wasm_tob import (
        ModuleHeader,
        Section,
        TypeSection,
        SEC_UNK,
        SEC_NAME,
        NameSubSection,
    )

    ModuleFragment = namedtuple("ModuleFragment", "type data length")

    module_wnd = memoryview(module)

    # Read & yield module header.
    hdr = ModuleHeader()
    hdr_len, hdr_data, _ = hdr.from_raw(None, module_wnd)
    yield ModuleFragment(hdr, hdr_data, hdr_len)
    module_wnd = module_wnd[hdr_len:]

    # Read & yield sections.
    while module_wnd:
        sec = Section()
        sec_len, sec_data, _ = sec.from_raw(None, module_wnd)

        # If requested, decode name subsections when encountered.
        if (
            decode_name_subsections
            and sec_data.id == SEC_UNK
            and sec_data.name == SEC_NAME
        ):
            sec_wnd = sec_data.payload
            while sec_wnd:
                subsec = NameSubSection()
                subsec_len, subsec_data, _ = subsec.from_raw(None, sec_wnd)
                yield ModuleFragment(subsec, subsec_data, subsec_len)
                sec_wnd = sec_wnd[subsec_len:]
        else:
            yield ModuleFragment(sec, sec_data, sec_len)

        module_wnd = module_wnd[sec_len:]


def add_arguments_to_parser(parser: argparse.ArgumentParser):
    parser.add_argument(
        "file",
        help="Path to a .z64/.n64 ROM, PSX executable, or .iso/.gcm GameCube image",
    )


def process_arguments(args: argparse.Namespace):
    main(Path(args.file))


script_description = (
    "Create a splat config from an N64 ROM, PSX executable, or a GameCube disc image."
)


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

#! /usr/bin/env python3

import argparse
import sys
from pathlib import Path

from src.splat.util.gc import gcinfo
from src.splat.util.n64 import find_code_length, rominfo
from src.splat.util.psx import psxexeinfo

parser = argparse.ArgumentParser(
    description="Create a splat config from an N64 ROM, PSX executable, or a GameCube disc image."
)
parser.add_argument(
    "file", help="Path to a .z64/.n64 ROM, PSX executable, or .iso/.gcm GameCube image"
)
