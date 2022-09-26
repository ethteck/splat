from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Type, TypeVar

from util import compiler
from util.compiler import Compiler

opts: "SplatOpts"


@dataclass
class SplatOpts:
    # Debug / logging
    verbose: bool
    dump_symbols: bool
    modes: List[str]

    # Project configuration
    base_path: Path
    target_path: Path
    platform: str
    compiler: Compiler
    endianness: str
    section_order: List[str]
    generated_c_preamble: str
    generated_s_preamble: str
    use_o_as_suffix: bool
    gp: Optional[int]

    # Paths
    asset_path: Path
    # Determines the path to the symbol addresses file(s)
    # A symbol_addrs file is to be updated/curated manually and contains addresses of symbols
    # as well as optional metadata such as rom address, type, and more
    #
    # It's possible to use more than one file by supplying a list instead of a string
    symbol_addrs_paths: List[Path]
    build_path: Path
    src_path: Path
    asm_path: Path
    data_path: Path
    nonmatchings_path: Path
    cache_path: Path

    create_undefined_funcs_auto: bool
    undefined_funcs_auto_path: Path

    create_undefined_syms_auto: bool
    undefined_syms_auto_path: Path

    extensions_path: Optional[Path]
    lib_path: Path

    elf_section_list_path: Optional[Path]

    # Linker script
    subalign: int
    auto_all_sections: List[str]
    ld_script_path: Path
    ld_symbol_header_path: Optional[Path]
    ld_discard_section: bool
    ld_section_labels: List[str]

    ################################################################################
    # C file options
    ################################################################################
    # Determines whether to create new c files if they don't exist
    create_c_files: bool
    # Determines whether to "auto-decompile" empty functions
    auto_decompile_empty_functions: bool
    # Determines whether to detect matched/unmatched functions in existing c files
    # so we can avoid creating .s files for already-decompiled functions
    do_c_func_detection: bool
    # Determines the newline char(s) to be used in c files
    c_newline: str

    ################################################################################
    # (Dis)assembly-related options
    ################################################################################
    # The following options determine the format that symbols should be named by default
    symbol_name_format: str
    # Same as above but for symbols with no rom address
    symbol_name_format_no_rom: str
    # Determines whether to detect and hint to the user about likely file splits when disassembling
    find_file_boundaries: bool
    # Determines whether to attempt to automatically migrate rodata into functions (only works in certain circumstances)
    migrate_rodata_to_functions: bool
    # Determines the header to be used in every asm file that's included from c files
    asm_inc_header: str
    # Determines the macro used to declare functions in asm files
    asm_function_macro: str
    # Determines the macro used to declare data symbols in asm files
    asm_data_macro: str
    # Determines the macro used at the end of a function, such as endlabel or .end
    asm_end_label: str
    # Determines the number of characters to left align before the TODO finish documenting
    mnemonic_ljust: int
    # Determines whether to pad the rom address
    rom_address_padding: bool
    # Determines which ABI names to use for general purpose registers
    mips_abi_gpr: str
    # Determines which ABI names to use for floating point registers
    # Valid values: 'numeric', 'o32', 'n32', 'n64'
    # o32 is highly recommended, as it provides logically named registers for floating point instructions
    # For more info, see https://gist.github.com/EllipticEllipsis/27eef11205c7a59d8ea85632bc49224d
    mips_abi_float_regs: str
    # Determines whether to ad ".set gp=64 to asm/hasm files"
    add_set_gp_64: bool
    # Generate .asmproc.d dependency files for each C file which still reference functions in assembly files
    create_asm_dependencies: bool

    ################################################################################
    # N64-specific options
    ################################################################################
    # Determines the encoding of the header
    header_encoding: str
    # Determines the type gfx ucode (used by gfx segments)
    # Valid options are ['f3d', 'f3db', 'f3dex', 'f3dexb', 'f3dex2']
    gfx_ucode: str

    ################################################################################
    # Compiler-specific options
    ################################################################################
    # Determines whether to use a legacy INCLUDE_ASM macro format in c files
    # only applies to GCC/SN64
    use_legacy_include_asm: bool

    # Returns whether the given mode is currently enabled
    def is_mode_active(self, mode: str) -> bool:
        return mode in self.modes or "all" in self.modes


def parse_yaml(
    yaml: Dict,
    basename: str,
    config_paths: List[str],
    modes: List[str],
    verbose: bool = False,
) -> SplatOpts:
    T = TypeVar("T")

    def yaml_as_type(value: object, t: Type[T]) -> T:
        if isinstance(value, t):
            return value
        raise ValueError(f"Expected {t}, got {type(value)}")

    def parse_opt(
        yaml: Mapping[str, object],
        opt: str,
        t: Type[T],
        default: Optional[T] = None,
    ) -> T:
        value = yaml.get(opt)
        if isinstance(value, t):
            # Fast path
            return value
        if value is None and opt not in yaml:
            if default is not None:
                return default
            raise ValueError(f"Missing required option {opt}")
        return yaml_as_type(value, t)

    def parse_opt_within(
        yaml: Mapping[str, object],
        opt: str,
        t: Type[T],
        within: List[T],
        default: Optional[T] = None,
    ) -> T:
        value = parse_opt(yaml, opt, t, default)
        if value not in within:
            raise ValueError(f"Invalid value for {opt}: {value}")
        return value

    def parse_path(
        yaml: Mapping[str, object], opt: str, default: Optional[str] = None
    ) -> Path:
        value = parse_opt(yaml, opt, str, default)
        return Path(value)

    def parse_optional_path(yaml: Mapping[str, object], opt: str, base_path: Path):
        value = yaml.get(opt)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"Expected str, got {type(value)}")
        return base_path / Path(value)

    def parse_symbol_addrs_paths(yaml: Mapping[str, object]) -> List[Path]:
        paths = yaml.get("symbol_addrs_path", "symbol_addrs.txt")

        if isinstance(paths, str):
            return [base_path / paths]
        elif isinstance(paths, list):
            return [base_path / path for path in paths]
        else:
            raise ValueError(f"Expected str or list, got {type(paths)}")

    platform = parse_opt(yaml, "platform", str, "n64")
    comp = compiler.for_name(parse_opt(yaml, "compiler", str, "IDO"))

    base_path = Path(config_paths[0]).parent / parse_opt(yaml, "base_path", str)
    asm_path: Path = base_path / parse_path(yaml, "asm_path", "asm")

    return SplatOpts(
        verbose=verbose,
        dump_symbols=parse_opt(yaml, "dump_symbols", bool, False),
        modes=modes,
        base_path=base_path,
        target_path=base_path / parse_path(yaml, "target_path"),
        platform=platform,
        compiler=comp,
        endianness=parse_opt(
            yaml,
            "endianness",
            str,
            "little" if platform.lower() == "psx" else "big",
        ),
        section_order=parse_opt(
            yaml, "section_order", list, [".text", ".data", ".rodata", ".bss"]
        ),
        generated_c_preamble=parse_opt(
            yaml, "generated_c_preamble", str, '#include "common.h"'
        ),
        generated_s_preamble=parse_opt(yaml, "generated_s_preamble", str, ""),
        use_o_as_suffix=parse_opt(yaml, "use_o_as_suffix", bool, False),
        gp=parse_opt(yaml, "gp_value", int, 0),
        asset_path=base_path / parse_path(yaml, "asset_path", "assets"),
        symbol_addrs_paths=parse_symbol_addrs_paths(yaml),
        build_path=base_path / parse_path(yaml, "build_path", "build"),
        src_path=base_path / parse_path(yaml, "src_path", "src"),
        asm_path=asm_path,
        data_path=asm_path / parse_path(yaml, "data_path", "data"),
        nonmatchings_path=asm_path
        / parse_path(yaml, "nonmatchings_path", "nonmatchings"),
        cache_path=base_path / parse_path(yaml, "cache_path", ".splache"),
        create_undefined_funcs_auto=parse_opt(
            yaml, "create_undefined_funcs_auto", bool, True
        ),
        undefined_funcs_auto_path=asm_path
        / parse_path(yaml, "undefined_funcs_auto_path", "undefined_funcs_auto.txt"),
        create_undefined_syms_auto=parse_opt(
            yaml, "create_undefined_syms_auto", bool, True
        ),
        undefined_syms_auto_path=asm_path
        / parse_path(yaml, "undefined_syms_auto_path", "undefined_syms_auto.txt"),
        extensions_path=parse_optional_path(yaml, "extensions_path", base_path),
        lib_path=base_path / parse_path(yaml, "lib_path", "lib"),
        elf_section_list_path=parse_optional_path(
            yaml, "elf_section_list_path", base_path
        ),
        subalign=parse_opt(yaml, "subalign", int, 16),
        auto_all_sections=parse_opt(
            yaml, "auto_all_sections", list, [".data", ".rodata", ".bss"]
        ),
        ld_script_path=base_path / parse_path(yaml, "ld_script_path", f"{basename}.ld"),
        ld_symbol_header_path=parse_optional_path(
            yaml, "ld_symbol_header_path", base_path
        ),
        ld_discard_section=parse_opt(yaml, "ld_discard_section", bool, True),
        ld_section_labels=parse_opt(
            yaml,
            "ld_section_labels",
            list,
            [".text", ".data", ".rodata", ".bss"],
        ),
        create_c_files=parse_opt(yaml, "create_c_files", bool, True),
        auto_decompile_empty_functions=parse_opt(
            yaml, "auto_decompile_empty_functions", bool, True
        ),
        do_c_func_detection=parse_opt(yaml, "do_c_func_detection", bool, True),
        c_newline=parse_opt(yaml, "c_newline", str, comp.c_newline),
        symbol_name_format=parse_opt(yaml, "symbol_name_format", str, "$VRAM"),
        symbol_name_format_no_rom=parse_opt(
            yaml, "symbol_name_format", str, "$VRAM_$SEG"
        ),
        find_file_boundaries=parse_opt(yaml, "find_file_boundaries", bool, True),
        migrate_rodata_to_functions=parse_opt(
            yaml, "migrate_rodata_to_functions", bool, True
        ),
        asm_inc_header=parse_opt(yaml, "asm_inc_header", str, comp.asm_inc_header),
        asm_function_macro=parse_opt(
            yaml, "asm_function_macro", str, comp.asm_function_macro
        ),
        asm_data_macro=parse_opt(yaml, "asm_data_macro", str, comp.asm_data_macro),
        asm_end_label=parse_opt(yaml, "asm_end_label", str, comp.asm_end_label),
        mnemonic_ljust=parse_opt(yaml, "mnemonic_ljust", int, 11),
        rom_address_padding=parse_opt(yaml, "rom_address_padding", bool, False),
        mips_abi_gpr=parse_opt_within(
            yaml,
            "mips_abi_gpr",
            str,
            ["numeric", "o32", "n32", "n64"],
            "o32",
        ),
        mips_abi_float_regs=parse_opt_within(
            yaml,
            "mips_abi_float_regs",
            str,
            ["numeric", "o32", "n32", "n64"],
            "numeric",
        ),
        add_set_gp_64=parse_opt(yaml, "add_set_gp_64", bool, True),
        create_asm_dependencies=parse_opt(yaml, "create_asm_dependencies", bool, False),
        header_encoding=parse_opt(yaml, "header_encoding", str, "ASCII"),
        gfx_ucode=parse_opt_within(
            yaml,
            "gfx_ucode",
            str,
            ["f3d", "f3db", "f3dex", "f3dexb", "f3dex2"],
            "f3dex2",
        ),
        use_legacy_include_asm=parse_opt(yaml, "use_legacy_include_asm", bool, False),
    )


def initialize(
    config: Dict,
    config_paths: list[str],
    modes: Optional[List[str]] = None,
    verbose=False,
):
    global opts

    if not modes:
        modes = ["all"]

    opts = parse_yaml(
        config["options"], config["basename"], config_paths, modes, verbose
    )
