from typing import Dict, List, Optional, Union, Literal
from pathlib import Path
from util import log

opts = {}

def initialize(config: Dict, config_path, base_path=None, target_path=None):
    global opts
    opts = dict(config.get("options", {}))

    if base_path:
        opts["base_path"] = Path(base_path)
    else:
        if not "base_path" in opts:
            log.error("Error: Base output dir not specified as a command line arg or via the config yaml (base_path)")

        opts["base_path"] = Path(config_path[0]).parent / opts["base_path"]

    if not target_path:
        if "target_path" not in opts:
            log.error("Error: Target binary path not specified as a command line arg or via the config yaml (target_path)")

def set(opt, val):
    opts[opt] = val

def get(opt, default=None):
    return opts.get(opt, default)

# Returns whether the given mode is currently enabled
def mode_active(mode):
    return mode in opts["modes"] or "all" in opts["modes"]

# TODO standardize names of options for categories & decide whether to stick to get_ or drop it
################################################################################
# Debug / logging options
################################################################################

# Determines whether to log more verbose output
def verbose() -> bool:
    return opts.get("verbose", False)


################################################################################
# Global options
#
# These can be set in the config yaml at the top level
################################################################################

# Determines the platform of the target binary
# Currently supported: n64, psx
def get_platform() -> str:
    return opts.get("platform", "n64")

# Determines the compiler used to compile the target binary
# Currently supported: IDO, GCC
def get_compiler() -> str:
    return opts.get("compiler", "IDO")

# Determines the endianness of the target binary
def get_endianess() -> Union[Literal["little"], Literal["big"]]:
    return opts.get("endianess", "little" if get_platform().upper() == "PSX" else "big")

# Determines the default section order of the target binary
# this can be overridden per-segment
def get_section_order() -> List[str]:
    return opts.get("section_order", [".text", ".data", ".rodata", ".bss"])

# Determines the code that is inserted by default in generated .c files
def get_generated_c_premble() -> str:
    return opts.get("generated_c_preamble", '#include "common.h"')

# Determines the code that is inserted by default in generated .s files
def get_generated_s_preamble() -> str:
    return opts.get("generated_s_preamble", "")

# Determines the base path of the project. Everything is relative to this path
def get_base_path() -> Path:
    return Path(opts["base_path"])

# Determines the asset path of the project. Assets such as raw binary files are stored here
def get_asset_path() -> Path:
    return Path(get_base_path() / opts.get("asset_path", "assets")).relative_to(get_base_path())

# Determines the path to the target binary
def get_target_path() -> Path:
    return get_base_path() / opts["target_path"]

# Determines the path to the symbol addresses file
# this file is to be updated by the user and contains addresses of symbols as well as optional metadata such as rom address, type, and more
def get_symbol_addrs_path():
    return get_base_path() / opts.get("symbol_addrs_path", "symbol_addrs.txt")

# Determines the path to the project build directory
def get_build_path():
    return get_base_path() / opts.get("build_path", "build")

# Determines the path to the source code directory
def get_src_path() -> Path:
    return get_base_path() / opts.get("src_path", "src")

# Determines the path to the asm code directory
def get_asm_path() -> Path:
    return get_base_path() / opts.get("asm_path", "asm")

# Determines the path to the cache file (used when supplied --use-cache via the CLI)
def get_cache_path():
    return get_base_path() / opts.get("cache_path", ".splat_cache")

# Determines whether to create an automatically-generated undefined functions file
# this file stores all functions that are referenced in the code but are not defined as seen by splat
def get_create_undefined_funcs_auto() -> bool:
    return opts.get("create_undefined_funcs_auto", True)

# Determines the path to the undefined_funcs_auto file
def get_undefined_funcs_auto_path():
    return get_base_path() / opts.get("undefined_funcs_auto_path", "undefined_funcs_auto.txt")

# Determines whether to create an automatically-generated undefined symbols file
# this file stores all symbols that are referenced in the code but are not defined as seen by splat
def get_create_undefined_syms_auto() -> bool:
    return opts.get("create_undefined_syms_auto", True)

# Determines the path to the undefined_symbols_auto file
def get_undefined_syms_auto_path():
    return get_base_path() / opts.get("undefined_syms_auto_path", "undefined_syms_auto.txt")

# TODO document
def get_create_elf_section_list_auto():
    return opts.get("create_elf_section_list_auto", False)

# TODO document
def get_elf_section_list_path():
    return get_base_path() / opts.get("elf_section_list_path", "elf_sections.txt")

# Determines the path in which to search for custom splat extensions
def get_extensions_path():
    ext_opt = opts.get("extensions_path")
    if not ext_opt:
        return None

    return get_base_path() / ext_opt

# Determines the path to library files that are to be linked into the target binary
def get_lib_path() -> Path:
    return get_base_path() / opts.get("lib_path", "lib")


################################################################################
# Linker script options
################################################################################

# Determines the desired path to the linker script that splat will generate
def get_ld_script_path():
    return get_base_path() / opts.get("ld_script_path", f"{opts.get('basename')}.ld")

# Determines the default subalign value to be specified in the generated linker script
def get_subalign() -> int:
    return opts.get("subalign", 16)

# Determines whether to automatically configure the linker script to link against common sections for all files 
# when the yaml doesn't have specific configurations for these sections. See release notes for details
def auto_all_sections() -> bool:
    return opts.get("auto_all_sections", False)

# Determines the desired path to the linker symbol header, which exposes externed definitions for all segment ram/rom start/end locations
def get_linker_symbol_header_path() -> Optional[Path]:
    if "linker_symbol_header_path" in opts:
        return get_base_path() / str(opts["linker_symbol_header_path"])
    else:
        return None

# Determines whether to create a shiftable linker script (EXPERIMENTAL)
def get_shiftable() -> bool:
    return opts.get("shiftable", False)

# Determines whether to add a discard section to the linker script
def linker_discard_section() -> bool:
    return opts.get("linker_discard_section", True)

# Determines whether to use a silly hack in the linker script to maybe help enforce alignment (DO NOT USE?)
def enable_ld_alignment_hack() -> bool:
    return opts.get("enable_ld_alignment_hack", False)


################################################################################
# C file options
################################################################################

# Determines whether to create new c files if they don't exist
def get_create_c_files() -> bool:
    return opts.get("create_c_files", True)

# Determines whether to detect matched/unmatched functions in existing c files
# so we can avoid creating .s files for already-decompiled functions
def do_c_func_detection() -> bool:
    return opts.get("do_c_func_detection", True)


################################################################################
# (Dis)assembly-related options
################################################################################

# Determines whether to detect and hint to the user about likely file splits when disassembling
def find_file_boundaries() -> bool:
    return opts.get("find_file_boundaries", True)

# Determines whether to attempt to automatically migrate rodata into functions (only works in certain circumstances)
def get_migrate_rodata_to_functions() -> bool:
    return opts.get("migrate_rodata_to_functions", True)

# Determines the macro used to declare functions in asm files
def get_asm_function_macro() -> str:
    return opts.get("asm_function_macro", "glabel")

# Determines the maximum number of instructions to attempt to match hi/lo pairs for symbols when disassembling
def hi_lo_max_distance() -> int:
    return opts.get("hi_lo_max_distance", 6)

# Determines the number of characters to left align before the TODO finish documenting
def mnemonic_ljust() -> int:
    return opts.get("mnemonic_ljust", 11)

# Determines whether to pad the rom address 
def rom_address_padding() -> bool:
    return opts.get("rom_address_padding", False)

# TODO document
def asm_endlabels() -> bool:
    return opts.get("asm_endlabels", False)


################################################################################
# N64-specific options
################################################################################

# Determines the encoding of the header
def get_header_encoding() -> str:
    return opts.get("header_encoding", "ASCII")


################################################################################
# GCC-specific options
################################################################################

# Determines whether to use a legacy INCLUDE_ASM macro format in c files
# only applies to GCC
def get_use_legacy_include_asm():
    return opts.get("use_legacy_include_asm", True)
