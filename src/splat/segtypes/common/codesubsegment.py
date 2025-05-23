from pathlib import Path
from typing import Optional, List

import spimdisasm
import rabbitizer

from ...util import options, symbols, log

from .code import CommonSegCode

from ..segment import Segment, parse_segment_vram

from ...disassembler.disassembler_section import DisassemblerSection, make_text_section


# abstract class for c, asm, data, etc
class CommonSegCodeSubsegment(Segment):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        vram = parse_segment_vram(self.yaml)
        if vram is not None:
            self.vram_start = vram

        self.str_encoding: Optional[str] = (
            self.yaml.get("str_encoding", None) if isinstance(self.yaml, dict) else None
        )

        self.spim_section: Optional[DisassemblerSection] = None
        self.instr_category = rabbitizer.InstrCategory.CPU
        if options.opts.platform == "ps2":
            self.instr_category = rabbitizer.InstrCategory.R5900
        elif options.opts.platform == "psx":
            self.instr_category = rabbitizer.InstrCategory.R3000GTE
        elif options.opts.platform == "psp":
            self.instr_category = rabbitizer.InstrCategory.R4000ALLEGREX

        self.detect_redundant_function_end: Optional[bool] = (
            self.yaml.get("detect_redundant_function_end", None)
            if isinstance(self.yaml, dict)
            else None
        )

        self.is_hasm = False
        self.use_gp_rel_macro = options.opts.use_gp_rel_macro

    @property
    def needs_symbols(self) -> bool:
        return True

    def get_linker_section(self) -> str:
        return ".text"

    def configure_disassembler_section(
        self, disassembler_section: DisassemblerSection
    ) -> None:
        "Allows to configure the section before running the analysis on it"

        section = disassembler_section.get_section()

        section.isHandwritten = self.is_hasm
        section.instrCat = self.instr_category
        section.detectRedundantFunctionEnd = self.detect_redundant_function_end
        section.setGpRelHack(not self.use_gp_rel_macro)

    def scan_code(self, rom_bytes, is_hasm=False):
        self.is_hasm = is_hasm

        if self.is_auto_segment:
            return

        if not isinstance(self.rom_start, int):
            log.error(
                f"Segment '{self.name}' (type '{self.type}') requires a rom_start. Got '{self.rom_start}'"
            )

        # Supposedly logic error, not user error
        assert isinstance(self.rom_end, int), self.rom_end

        # Supposedly logic error, not user error
        segment_rom_start = self.get_most_parent().rom_start
        assert isinstance(segment_rom_start, int), segment_rom_start

        if not isinstance(self.vram_start, int):
            log.error(
                f"Segment '{self.name}' (type '{self.type}') requires a vram address. Got '{self.vram_start}'"
            )

        self.spim_section = make_text_section(
            self.rom_start,
            self.rom_end,
            self.vram_start,
            self.name,
            rom_bytes,
            segment_rom_start,
            self.get_exclusive_ram_id(),
        )

        assert self.spim_section is not None

        self.configure_disassembler_section(self.spim_section)

        self.spim_section.analyze()
        self.spim_section.set_comment_offset(self.rom_start)

        for func in self.spim_section.get_section().symbolList:
            assert isinstance(func, spimdisasm.mips.symbols.SymbolFunction)

            self.process_insns(func)

    def process_insns(
        self,
        func_spim: spimdisasm.mips.symbols.SymbolFunction,
    ):
        assert isinstance(self.parent, CommonSegCode)
        assert func_spim.vram is not None
        assert func_spim.vramEnd is not None
        assert self.spim_section is not None
        self.parent: CommonSegCode = self.parent

        symbols.create_symbol_from_spim_symbol(
            self.get_most_parent(), func_spim.contextSym
        )

        # Gather symbols found by spimdisasm and create those symbols in splat's side
        for referenced_vram in func_spim.referencedVrams:
            context_sym = self.spim_section.get_section().getSymbol(
                referenced_vram, tryPlusOffset=False
            )
            if context_sym is not None:
                symbols.create_symbol_from_spim_symbol(
                    self.get_most_parent(), context_sym
                )

        # Main loop
        for i, insn in enumerate(func_spim.instructions):
            if options.opts.platform == "ps2":
                from .c import CommonSegC
                from rabbitizer import TrinaryValue

                if isinstance(self, CommonSegC):
                    insn.flag_r5900UseDollar = TrinaryValue.FALSE
                else:
                    insn.flag_r5900UseDollar = TrinaryValue.TRUE
                insn.flag_r5900DisasmAsData = TrinaryValue.TRUE

            instr_offset = i * 4

            # update pointer accesses from this function
            if instr_offset in func_spim.instrAnalyzer.symbolInstrOffset:
                sym_address = func_spim.instrAnalyzer.symbolInstrOffset[instr_offset]

                context_sym = self.spim_section.get_section().getSymbol(sym_address)
                if context_sym is not None:
                    symbols.create_symbol_from_spim_symbol(
                        self.get_most_parent(), context_sym
                    )

    def print_file_boundaries(self):
        if not self.show_file_boundaries or not self.spim_section:
            return

        assert isinstance(self.rom_start, int)

        for in_file_offset in self.spim_section.get_section().fileBoundaries:
            if not self.parent.reported_file_split:
                self.parent.reported_file_split = True

                # Look up for the last symbol in this boundary
                sym_addr = 0
                for sym in self.spim_section.get_section().symbolList:
                    symOffset = (
                        sym.inFileOffset - self.spim_section.get_section().inFileOffset
                    )
                    if in_file_offset == symOffset:
                        break
                    sym_addr = sym.vram

                print(
                    f"\nSegment {self.name}, symbol at vram {sym_addr:X} ends with extra nops, indicating a likely file split."
                )
                print(
                    "File split suggestions for this segment will follow in config yaml format:"
                )
            print(f"      - [0x{self.rom_start+in_file_offset:X}, {self.type}]")

    def should_scan(self) -> bool:
        return (
            options.opts.is_mode_active("code")
            and self.rom_start is not None
            and self.rom_end is not None
        )

    def should_split(self) -> bool:
        return (
            self.extract and options.opts.is_mode_active("code") and self.should_scan()
        )  # only split if the segment was scanned first

    def should_self_split(self) -> bool:
        return self.should_split()

    def get_asm_file_header(self) -> List[str]:
        ret = []

        ret.append('.include "macro.inc"')
        ret.append("")

        ret.extend(self.get_asm_file_extra_directives())

        preamble = options.opts.generated_s_preamble
        if preamble:
            ret.append(preamble)
            ret.append("")

        ret.append(self.get_section_asm_line())
        ret.append("")

        return ret

    def get_asm_file_extra_directives(self) -> List[str]:
        ret = []

        ret.append(".set noat")  # allow manual use of $at
        ret.append(".set noreorder")  # don't insert nops after branches
        if options.opts.add_set_gp_64:
            ret.append(".set gp=64")  # allow use of 64-bit general purpose registers
        ret.append("")

        return ret

    def asm_out_path(self) -> Path:
        return options.opts.asm_path / self.dir / f"{self.name}.s"

    def out_path(self) -> Optional[Path]:
        return self.asm_out_path()

    def split_as_asm_file(self, out_path: Optional[Path]):
        if self.spim_section is None:
            return

        if not out_path:
            return

        out_path.parent.mkdir(parents=True, exist_ok=True)

        self.print_file_boundaries()

        with open(out_path, "w", newline="\n") as f:
            # Write `.text` contents
            for line in self.get_asm_file_header():
                f.write(line + "\n")
            f.write(self.spim_section.disassemble())

    # Same as above but write all sections from siblings
    def split_as_asmtu_file(self, out_path: Optional[Path]):
        if self.spim_section is None:
            return

        if not out_path:
            return

        out_path.parent.mkdir(parents=True, exist_ok=True)

        self.print_file_boundaries()

        with open(out_path, "w", newline="\n") as f:
            # Write `.text` contents
            for line in self.get_asm_file_header():
                f.write(line + "\n")
            f.write(self.spim_section.disassemble())

            # Disassemble the siblings to this file by respecting the `section_order`
            for sect in self.section_order:
                if sect == self.get_linker_section_linksection():
                    continue

                sibling = self.siblings.get(sect)
                if sibling is None:
                    continue

                if (
                    isinstance(sibling, CommonSegCodeSubsegment)
                    and sibling.spim_section is not None
                    and not sibling.should_self_split()
                ):
                    f.write("\n")
                    f.write(f"{sibling.get_section_asm_line()}\n\n")
                    f.write(sibling.spim_section.disassemble())

            # Another loop to check anything that somehow may not be present on the `section_order`
            for sect, sibling in self.siblings.items():
                if sect == self.get_linker_section_linksection():
                    continue

                if sect in self.section_order:
                    # Already handled on the above loop
                    continue

                if (
                    isinstance(sibling, CommonSegCodeSubsegment)
                    and sibling.spim_section is not None
                    and not sibling.should_self_split()
                ):
                    f.write("\n")
                    f.write(f"{sibling.get_section_asm_line()}\n\n")
                    f.write(sibling.spim_section.disassemble())
