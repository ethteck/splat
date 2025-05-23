from dataclasses import dataclass
import os
from pathlib import Path
from typing import cast, Dict, List, Literal, Mapping, Optional, Set, Type, TypeVar

from . import compiler
from .compiler import Compiler


@dataclass
class SplatOpts:
    # Debug / logging
    verbose: bool
    dump_symbols: bool
    modes: List[str]

    # Project configuration

    # Determines the base path of the project. Everything is relative to this path
    base_path: Path
    # Determines the path to the target binary
    target_path: Path
    # Path to the final elf target
    elf_path: Optional[Path]
    # Determines the platform of the target binary
    platform: str
    # Determines the compiler used to compile the target binary
    compiler: Compiler
    # Determines the endianness of the target binary
    endianness: Literal["big", "little"]
    # Determines the default section order of the target binary
    # this can be overridden per-segment
    section_order: List[str]
    # Determines the code that is inserted by default in generated .c files
    generated_c_preamble: str
    # Determines the code that is inserted by default in generated .s files
    generated_s_preamble: str
    # Determines whether to use .o as the suffix for all binary files?... TODO document
    use_o_as_suffix: bool
    # the value of the $gp register to correctly calculate offset to %gp_rel relocs
    gp: Optional[int]
    # Checks and errors if there are any non consecutive segment types
    check_consecutive_segment_types: bool
    # Disable checks on `platform` option.
    is_unsupported_platform: bool
    # Allows to take precedence over the splat builtin platform segments via splat extension.
    allow_segment_overrides: bool

    # Paths
    asset_path: Path
    # Determines the path to the symbol addresses file(s)
    # A symbol_addrs file is to be updated/curated manually and contains addresses of symbols
    # as well as optional metadata such as rom address, type, and more
    #
    # It's possible to use more than one file by supplying a list instead of a string
    symbol_addrs_paths: List[Path]
    reloc_addrs_paths: List[Path]
    # Determines the path to the project build directory
    build_path: Path
    # Determines the path to the source code directory
    src_path: Path
    # Determines the path to the asm code directory
    asm_path: Path
    # Determines the path to the asm data directory
    data_path: Path
    # Determines the path to the asm nonmatchings directory
    nonmatchings_path: Path
    # Determines the path to the asm matchings directory (used alongside `disassemble_all` to organize matching functions from nonmatching functions)
    matchings_path: Path
    # Determines the path to the cache file (used when supplied --use-cache via the CLI)
    cache_path: Path
    # Tells splat to consider `hasm` files to be relative to `src_path` instead of `asm_path`.
    hasm_in_src_path: bool

    # Determines whether to create an automatically-generated undefined functions file
    # this file stores all functions that are referenced in the code but are not defined as seen by splat
    create_undefined_funcs_auto: bool
    # Determines the path to the undefined_funcs_auto file
    undefined_funcs_auto_path: Path

    # Determines whether to create an automatically-generated undefined symbols file
    # this file stores all symbols that are referenced in the code but are not defined as seen by splat
    create_undefined_syms_auto: bool
    # Determines the path to the undefined_symbols_auto file
    undefined_syms_auto_path: Path

    # Determines the path in which to search for custom splat extensions
    extensions_path: Optional[Path]

    # Determines the path to library files that are to be linked into the target binary
    lib_path: Path

    # TODO document
    elf_section_list_path: Optional[Path]

    # Linker script
    # Determines the default subalign value to be specified in the generated linker script
    subalign: Optional[int]
    # Determines whether to emit the subalign directive in the generated linker script
    emit_subalign: bool
    # The following option determines a list of sections for which automatic linker script entries should be added
    auto_link_sections: List[str]
    # Determines the desired path to the linker script that splat will generate
    ld_script_path: Path
    # Determines the desired path to the linker symbol header,
    # which exposes externed definitions for all segment ram/rom start/end locations
    ld_symbol_header_path: Optional[Path]
    # Determines whether to add a discard section with a wildcard to the linker script
    ld_discard_section: bool
    # A list of sections to preserve during link time. It can be useful to preserve debugging sections
    ld_sections_allowlist: List[str]
    # A list of sections to discard during link time. It can be useful to avoid using the wildcard discard. Note that this option does not turn off `ld_discard_section`
    ld_sections_denylist: List[str]
    # Determines whether to add wildcards for section linking in the linker script (.rodata* for example)
    ld_wildcard_sections: bool
    # Determines whether to use `follows_vram` (segment option) and
    # `vram_symbol` / `follows_classes` (vram_class options) to calculate vram addresses in the linker script.
    # If disabled, this uses the plain integer values for vram addresses defined in the yaml.
    ld_use_symbolic_vram_addresses: bool
    # Change linker script generation to allow partially linking segments. Requires both `ld_partial_scripts_path` and `ld_partial_build_segments_path` to be set.
    ld_partial_linking: bool
    # Folder were each intermediary linker script will be written to.
    ld_partial_scripts_path: Optional[Path]
    # Folder where the built partially linked segments will be placed by the build system.
    ld_partial_build_segments_path: Optional[Path]
    # Generate a dependency file for every linker script generated. Dependency files will have the same path and name as the corresponding linker script, but changing the extension to `.d`. Requires `elf_path` to be set.
    ld_dependencies: bool
    # Legacy linker script generation does not impose the section_order specified in the yaml options or per-segment options.
    ld_legacy_generation: bool
    # If enabled, the end symbol for each segment will be placed before the alignment directive for the segment
    segment_end_before_align: bool
    # Controls the style of the auto-generated segment symbols in the linker script. Possible values: splat, makerom
    segment_symbols_style: str
    # Specifies the starting offset for rom address symbols in the linker script.
    ld_rom_start: int
    # The value passed to the FILL statement on each segment. `None` disables using FILL statements on the linker script. Defaults to a fill value of 0.
    ld_fill_value: Optional[int]
    # Allows to control if `bss` sections (and derivatived sections) will be put on a `NOLOAD` segment on the generated linker script or not.
    ld_bss_is_noload: bool
    # Aligns the start of the segment to the given value
    ld_align_segment_start: Optional[int]
    # Allows to toggle aligning the `*_VRAM_END` linker symbol for each segment.
    ld_align_segment_vram_end: bool
    # Allows to toggle aligning the `*_END` linker symbol for each section of each section.
    ld_align_section_vram_end: bool
    # If enabled, the generated linker script will have a linker symbol for each data file
    ld_generate_symbol_per_data_segment: bool
    # Sets the default option for the `bss_contains_common` attribute of all segments.
    ld_bss_contains_common: bool

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
    # Determines whether to detect and hint to the user about possible rodata sections corresponding to a text section
    pair_rodata_to_text: bool
    # Determines whether to attempt to automatically migrate rodata into functions
    # (only works in certain circumstances)
    migrate_rodata_to_functions: bool
    # Determines the header to be used in every asm file that's included from c files
    asm_inc_header: str
    # Determines the macro used to declare functions in asm files
    asm_function_macro: str
    # Determines the macro used to declare symbols in the middle of functions in asm files (which may be alternative entries)
    asm_function_alt_macro: str
    # Determines the macro used to declare jumptable labels in asm files
    asm_jtbl_label_macro: str
    # Determines the macro used to declare data symbols in asm files
    asm_data_macro: str
    # Determines the macro used at the end of a function, such as endlabel or .end
    asm_end_label: str
    # Determines the macro used to declare ehtable labels in asm files
    asm_ehtable_label_macro: str
    # Toggles the .size directive emitted by the disassembler
    asm_emit_size_directive: Optional[bool]
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
    # Determines whether functions inside c files should have named registers
    named_regs_for_c_funcs: bool
    # Determines whether to add ".set gp=64" to asm/hasm files
    add_set_gp_64: bool
    # Generate .asmproc.d dependency files for each C file which still reference functions in assembly files
    create_asm_dependencies: bool
    # Global option for rodata string encoding. This can be overriden per segment
    string_encoding: Optional[str]
    # Global option for data string encoding. This can be overriden per segment
    data_string_encoding: Optional[str]
    # Global option for the rodata string guesser. 0 disables the guesser completely.
    rodata_string_guesser_level: Optional[int]
    # Global option for the data string guesser. 0 disables the guesser completely.
    data_string_guesser_level: Optional[int]
    # Global option for allowing data symbols using addends on symbol references. It can be overriden per symbol
    allow_data_addends: bool
    # Tells the disassembler to try disassembling functions with unknown instructions instead of falling back to disassembling as raw data
    disasm_unknown: bool
    # Tries to detect redundant and unreferenced functions ends and merge them together. This option is ignored if the compiler is not set to IDO.
    detect_redundant_function_end: bool
    # Don't skip disassembling already matched functions and migrated sections
    disassemble_all: bool
    # Emit a full `.s` file for each `c`/`cpp` segment besides the generated `nonmatchings` individual functions
    make_full_disasm_for_code: bool
    # Allow specifying that the global memory range may be larger than what was automatically detected.
    # Useful for projects where splat is used in multiple individual files, meaning the expected global segment may not be properly detected because each instance of splat can't see the info from other files.
    global_vram_start: Optional[int]
    global_vram_end: Optional[int]
    # For `c` segments (functions under the nonmatchings folder).
    # If True then use the `%gp_rel` explicit relocation parameter on instructions that use the $gp register,
    # otherwise strip the `%gp_rel` parameter entirely and convert those instructions into macro instructions that may not assemble to the original
    # bytes. In the latter case, it is the user's responsability to provide the symbol's information to the assembler so it can assemble the
    # instruction with the proper relocation.
    use_gp_rel_macro_nonmatching: bool
    # Does the same as `use_gp_rel_macro_nonmatching`, except it is only applied to `asm` and `hasm` segments.
    use_gp_rel_macro: bool
    # Allows emitting suggestions for where the rodata may start by examining the data section.
    suggestion_rodata_section_start: bool

    ################################################################################
    # N64-specific options
    ################################################################################
    # Determines the encoding of the header
    header_encoding: str
    # Determines the type gfx ucode (used by gfx segments)
    # Valid options are ['f3d', 'f3db', 'f3dex', 'f3dexb', 'f3dex2']
    gfx_ucode: str
    # Use named libultra symbols by default. Those will need to be added to a linker script manually by the user
    libultra_symbols: bool
    # Use named libultra symbols by default. Those will need to be added to a linker script manually by the user
    ique_symbols: bool
    # Use named hardware register symbols by default. Those will need to be added to a linker script manually by the user
    hardware_regs: bool
    # Append the image type to the output file extension
    image_type_in_extension: bool

    ################################################################################
    # Compiler-specific options
    ################################################################################
    # Determines whether to use a legacy INCLUDE_ASM macro format in c files
    # only applies to GCC/SN64
    use_legacy_include_asm: bool

    # Returns whether the given mode is currently enabled
    def is_mode_active(self, mode: str) -> bool:
        return mode in self.modes or "all" in self.modes


opts: SplatOpts


T = TypeVar("T")


class OptParser:
    _read_opts: Set[str]

    def __init__(self, yaml: Mapping[str, object]) -> None:
        self._yaml = yaml
        self._read_opts = set()

    def parse_opt(self, opt: str, t: Type[T], default: Optional[T] = None) -> T:
        if opt not in self._yaml:
            if default is not None:
                return default
            raise ValueError(f"Missing required option {opt}")
        self._read_opts.add(opt)
        value = self._yaml[opt]
        if isinstance(value, t):
            return value
        if t is float and isinstance(value, int):
            return cast(T, float(value))
        raise ValueError(f"Expected {opt} to have type {t}, got {type(value)}")

    def parse_optional_opt(self, opt: str, t: Type[T]) -> Optional[T]:
        if opt not in self._yaml:
            return None
        return self.parse_opt(opt, t)

    def parse_optional_opt_with_default(
        self, opt: str, t: Type[T], default: Optional[T]
    ) -> Optional[T]:
        if opt not in self._yaml:
            return default
        self._read_opts.add(opt)
        value = self._yaml[opt]
        if value is None or isinstance(value, t):
            return value
        if t is float and isinstance(value, int):
            return cast(T, float(value))
        raise ValueError(f"Expected {opt} to have type {t}, got {type(value)}")

    def parse_opt_within(
        self, opt: str, t: Type[T], within: List[T], default: Optional[T] = None
    ) -> T:
        value = self.parse_opt(opt, t, default)
        if value not in within:
            raise ValueError(f"Invalid value for {opt}: {value}")
        return value

    def parse_path(
        self, base_path: Path, opt: str, default: Optional[str] = None
    ) -> Path:
        return Path(os.path.normpath(base_path / self.parse_opt(opt, str, default)))

    def parse_optional_path(self, base_path: Path, opt: str) -> Optional[Path]:
        if opt not in self._yaml:
            return None
        return self.parse_path(base_path, opt)

    def parse_path_list(self, base_path: Path, opt: str, default: str) -> List[Path]:
        paths = self.parse_opt(opt, object, default)

        if isinstance(paths, str):
            return [base_path / paths]
        elif isinstance(paths, list):
            return [base_path / path for path in paths]
        else:
            raise ValueError(f"Expected str or list for '{opt}', got {type(paths)}")

    def check_no_unread_opts(self) -> None:
        opts = [opt for opt in self._yaml if opt not in self._read_opts]
        if opts:
            raise ValueError(f"Unrecognized YAML option(s): {', '.join(opts)}")


def _parse_yaml(
    yaml: Dict,
    config_paths: List[Path],
    modes: List[str],
    verbose: bool = False,
    disasm_all: bool = False,
    make_full_disasm_for_code: bool = False,
) -> SplatOpts:
    p = OptParser(yaml)

    basename = p.parse_opt("basename", str)
    is_unsupported_platform = p.parse_opt("is_unsupported_platform", bool, False)

    if is_unsupported_platform:
        platform = p.parse_opt("platform", str)
    else:
        platform = p.parse_opt_within("platform", str, ["n64", "psx", "ps2", "psp"])

    comp = compiler.for_name(p.parse_opt("compiler", str, "IDO"))

    base_path = Path(
        os.path.normpath(config_paths[0].parent / p.parse_opt("base_path", str))
    )
    asm_path: Path = p.parse_path(base_path, "asm_path", "asm")

    asm_emit_size_directive = p.parse_optional_opt("asm_emit_size_directive", bool)
    # If option not provided then use the compiler default
    if asm_emit_size_directive is None:
        asm_emit_size_directive = comp.asm_emit_size_directive

    def parse_endianness() -> Literal["big", "little"]:
        endianness = p.parse_opt_within(
            "endianness",
            str,
            ["big", "little"],
            "little" if platform in ["psx", "ps2", "psp"] else "big",
        )

        if endianness == "big":
            return "big"
        elif endianness == "little":
            return "little"
        else:
            raise ValueError(f"Invalid endianness: {endianness}")

    default_ld_bss_is_noload = True
    if platform == "psx":
        default_ld_bss_is_noload = False

    default_add_set_gp_64 = True
    if platform in ("psx", "ps2"):
        default_add_set_gp_64 = False

    ret = SplatOpts(
        verbose=verbose,
        dump_symbols=p.parse_opt("dump_symbols", bool, False),
        modes=modes,
        base_path=base_path,
        target_path=p.parse_path(base_path, "target_path"),
        elf_path=p.parse_optional_path(base_path, "elf_path"),
        platform=platform,
        is_unsupported_platform=is_unsupported_platform,
        allow_segment_overrides=p.parse_opt("allow_segment_overrides", bool, False),
        compiler=comp,
        endianness=parse_endianness(),
        section_order=p.parse_opt(
            "section_order", list, [".text", ".data", ".rodata", ".bss"]
        ),
        generated_c_preamble=p.parse_opt(
            "generated_c_preamble", str, '#include "common.h"'
        ),
        generated_s_preamble=p.parse_opt("generated_s_preamble", str, ""),
        use_o_as_suffix=p.parse_opt("o_as_suffix", bool, False),
        gp=p.parse_optional_opt("gp_value", int),
        check_consecutive_segment_types=p.parse_opt(
            "check_consecutive_segment_types", bool, True
        ),
        asset_path=p.parse_path(base_path, "asset_path", "assets"),
        symbol_addrs_paths=p.parse_path_list(
            base_path, "symbol_addrs_path", "symbol_addrs.txt"
        ),
        reloc_addrs_paths=p.parse_path_list(
            base_path, "reloc_addrs_path", "reloc_addrs.txt"
        ),
        build_path=p.parse_path(base_path, "build_path", "build"),
        src_path=p.parse_path(base_path, "src_path", "src"),
        asm_path=asm_path,
        data_path=p.parse_path(asm_path, "data_path", "data"),
        nonmatchings_path=p.parse_path(asm_path, "nonmatchings_path", "nonmatchings"),
        matchings_path=p.parse_path(asm_path, "matchings_path", "matchings"),
        cache_path=p.parse_path(base_path, "cache_path", ".splache"),
        hasm_in_src_path=p.parse_opt("hasm_in_src_path", bool, False),
        create_undefined_funcs_auto=p.parse_opt(
            "create_undefined_funcs_auto", bool, True
        ),
        undefined_funcs_auto_path=p.parse_path(
            base_path, "undefined_funcs_auto_path", "undefined_funcs_auto.txt"
        ),
        create_undefined_syms_auto=p.parse_opt(
            "create_undefined_syms_auto", bool, True
        ),
        undefined_syms_auto_path=p.parse_path(
            base_path, "undefined_syms_auto_path", "undefined_syms_auto.txt"
        ),
        extensions_path=p.parse_optional_path(base_path, "extensions_path"),
        lib_path=p.parse_path(base_path, "lib_path", "lib"),
        elf_section_list_path=p.parse_optional_path(base_path, "elf_section_list_path"),
        subalign=p.parse_optional_opt_with_default("subalign", int, 16),
        emit_subalign=p.parse_opt("emit_subalign", bool, True),
        auto_link_sections=p.parse_opt(
            "auto_link_sections", list, [".data", ".rodata", ".bss"]
        ),
        ld_script_path=p.parse_path(base_path, "ld_script_path", f"{basename}.ld"),
        ld_symbol_header_path=p.parse_optional_path(base_path, "ld_symbol_header_path"),
        ld_discard_section=p.parse_opt("ld_discard_section", bool, True),
        ld_sections_allowlist=p.parse_opt("ld_sections_allowlist", list, []),
        ld_sections_denylist=p.parse_opt("ld_sections_denylist", list, []),
        ld_wildcard_sections=p.parse_opt("ld_wildcard_sections", bool, False),
        ld_use_symbolic_vram_addresses=p.parse_opt(
            "ld_use_symbolic_vram_addresses", bool, True
        ),
        ld_partial_linking=p.parse_opt("ld_partial_linking", bool, False),
        ld_partial_scripts_path=p.parse_optional_path(
            base_path, "ld_partial_scripts_path"
        ),
        ld_partial_build_segments_path=p.parse_optional_path(
            base_path, "ld_partial_build_segments_path"
        ),
        ld_dependencies=p.parse_opt("ld_dependencies", bool, False),
        ld_legacy_generation=p.parse_opt("ld_legacy_generation", bool, False),
        segment_end_before_align=p.parse_opt("segment_end_before_align", bool, False),
        segment_symbols_style=p.parse_opt_within(
            "segment_symbols_style", str, ["splat", "makerom"], "splat"
        ),
        ld_rom_start=p.parse_opt("ld_rom_start", int, 0),
        ld_fill_value=p.parse_optional_opt_with_default("ld_fill_value", int, 0),
        ld_bss_is_noload=p.parse_opt(
            "ld_bss_is_noload", bool, default_ld_bss_is_noload
        ),
        ld_align_segment_start=p.parse_optional_opt_with_default(
            "ld_align_segment_start", int, None
        ),
        ld_align_segment_vram_end=p.parse_opt("ld_align_segment_vram_end", bool, True),
        ld_align_section_vram_end=p.parse_opt("ld_align_section_vram_end", bool, True),
        ld_generate_symbol_per_data_segment=p.parse_opt(
            "ld_generate_symbol_per_data_segment", bool, False
        ),
        ld_bss_contains_common=p.parse_opt("ld_bss_contains_common", bool, False),
        create_c_files=p.parse_opt("create_c_files", bool, True),
        auto_decompile_empty_functions=p.parse_opt(
            "auto_decompile_empty_functions", bool, True
        ),
        do_c_func_detection=p.parse_opt("do_c_func_detection", bool, True),
        c_newline=p.parse_opt("c_newline", str, comp.c_newline),
        symbol_name_format=p.parse_opt("symbol_name_format", str, "$VRAM"),
        symbol_name_format_no_rom=p.parse_opt(
            "symbol_name_format_no_rom", str, "$VRAM_$SEG"
        ),
        find_file_boundaries=p.parse_opt("find_file_boundaries", bool, True),
        pair_rodata_to_text=p.parse_opt("pair_rodata_to_text", bool, True),
        migrate_rodata_to_functions=p.parse_opt(
            "migrate_rodata_to_functions", bool, True
        ),
        asm_inc_header=p.parse_opt("asm_inc_header", str, comp.asm_inc_header),
        asm_function_macro=p.parse_opt(
            "asm_function_macro", str, comp.asm_function_macro
        ),
        asm_function_alt_macro=p.parse_opt(
            "asm_function_alt_macro", str, comp.asm_function_alt_macro
        ),
        asm_jtbl_label_macro=p.parse_opt(
            "asm_jtbl_label_macro", str, comp.asm_jtbl_label_macro
        ),
        asm_data_macro=p.parse_opt("asm_data_macro", str, comp.asm_data_macro),
        asm_end_label=p.parse_opt("asm_end_label", str, comp.asm_end_label),
        asm_ehtable_label_macro=p.parse_opt(
            "asm_ehtable_label_macro", str, comp.asm_ehtable_label_macro
        ),
        asm_emit_size_directive=asm_emit_size_directive,
        mnemonic_ljust=p.parse_opt("mnemonic_ljust", int, 11),
        rom_address_padding=p.parse_opt("rom_address_padding", bool, False),
        mips_abi_gpr=p.parse_opt_within(
            "mips_abi_gpr",
            str,
            ["numeric", "32", "o32", "n32", "n64"],
            "o32",
        ),
        mips_abi_float_regs=p.parse_opt_within(
            "mips_abi_float_regs",
            str,
            ["numeric", "32", "o32", "n32", "n64"],
            "numeric",
        ),
        named_regs_for_c_funcs=p.parse_opt("named_regs_for_c_funcs", bool, True),
        add_set_gp_64=p.parse_opt("add_set_gp_64", bool, default_add_set_gp_64),
        create_asm_dependencies=p.parse_opt("create_asm_dependencies", bool, False),
        string_encoding=p.parse_optional_opt("string_encoding", str),
        data_string_encoding=p.parse_optional_opt("data_string_encoding", str),
        rodata_string_guesser_level=p.parse_optional_opt(
            "rodata_string_guesser_level", int
        ),
        data_string_guesser_level=p.parse_optional_opt(
            "data_string_guesser_level", int
        ),
        allow_data_addends=p.parse_opt("allow_data_addends", bool, True),
        header_encoding=p.parse_opt("header_encoding", str, "ASCII"),
        gfx_ucode=p.parse_opt_within(
            "gfx_ucode",
            str,
            ["f3d", "f3db", "f3dex", "f3dexb", "f3dex2"],
            "f3dex2",
        ),
        libultra_symbols=p.parse_opt("libultra_symbols", bool, False),
        ique_symbols=p.parse_opt("ique_symbols", bool, False),
        hardware_regs=p.parse_opt("hardware_regs", bool, False),
        image_type_in_extension=p.parse_opt("image_type_in_extension", bool, False),
        use_legacy_include_asm=p.parse_opt("use_legacy_include_asm", bool, False),
        disasm_unknown=p.parse_opt("disasm_unknown", bool, False),
        detect_redundant_function_end=p.parse_opt(
            "detect_redundant_function_end", bool, True
        ),
        # Setting either option will produce a full disassembly,
        # but we still have to check the yaml option first to avoid leaving option unparsed,
        # because splat would complain about an unrecognized yaml option otherwise.
        disassemble_all=p.parse_opt("disassemble_all", bool, False) or disasm_all,
        make_full_disasm_for_code=p.parse_opt("make_full_disasm_for_code", bool, False)
        or make_full_disasm_for_code,
        global_vram_start=p.parse_optional_opt("global_vram_start", int),
        global_vram_end=p.parse_optional_opt("global_vram_end", int),
        use_gp_rel_macro_nonmatching=p.parse_opt(
            "use_gp_rel_macro_nonmatching", bool, True
        ),
        use_gp_rel_macro=p.parse_opt("use_gp_rel_macro", bool, True),
        suggestion_rodata_section_start=p.parse_opt(
            "suggestion_rodata_section_start", bool, True
        ),
    )
    p.check_no_unread_opts()
    return ret


def initialize(
    config: Dict,
    config_paths: List[Path],
    modes: Optional[List[str]] = None,
    verbose=False,
    disasm_all=False,
    make_full_disasm_for_code=False,
):
    global opts

    if not modes:
        modes = ["all"]

    opts = _parse_yaml(
        config["options"],
        config_paths,
        modes,
        verbose,
        disasm_all,
        make_full_disasm_for_code,
    )
