from dataclasses import dataclass
from typing import List, Optional
import typing
from util import options
from segtypes.common.code import CommonSegCode
from collections import OrderedDict
import re

from segtypes.segment import Segment
from util.compiler import SN64
from util.symbols import Instruction, Symbol
from util import log

import tools.spimdisasm.spimdisasm as spimdisasm

# abstract class for c, asm, data, etc
class CommonSegCodeSubsegment(Segment):
    double_mnemonics = ["ldc1", "sdc1"]
    word_mnemonics = ["addiu", "sw", "lw", "jtbl"]
    float_mnemonics = ["lwc1", "swc1"]
    short_mnemonics = ["addiu", "lh", "sh", "lhu"]
    byte_mnemonics = ["lb", "sb", "lbu"]

    @property
    def needs_symbols(self) -> bool:
        return True

    def get_linker_section(self) -> str:
        return ".text"

    def scan_code(self, rom_bytes, is_asm=False):
        self.textSection = spimdisasm.mips.sections.SectionText(
            self.context,
            self.vram_start,
            self.name,
            rom_bytes[self.rom_start : self.rom_end],
        )
        self.textSection.analyze()
        self.textSection.setCommentOffset(self.rom_start)

        for func in self.textSection.symbolList:
            assert isinstance(func, spimdisasm.mips.symbols.SymbolFunction)

            self.process_insns(func, self.rom_start, is_asm=is_asm)

        # Process jumptable labels and pass them to pyMipsDisas
        self.gather_jumptable_labels(rom_bytes)
        for jtblLabelVram in self.parent.jtbl_glabels_to_add:
            romAddr = self.ram_to_rom(jtblLabelVram)
            # TODO: what should we do when this is None?
            if romAddr is not None:
                self.context.addJumpTableLabel(
                    jtblLabelVram,
                    f"L{jtblLabelVram:X}_{romAddr:X}",
                    isAutogenerated=True,
                )

    def process_insns(
        self,
        funcSpimDisasm: spimdisasm.mips.symbols.SymbolFunction,
        rom_addr: int,
        is_asm=False,
    ):
        assert isinstance(self.parent, CommonSegCode)
        assert funcSpimDisasm.vram is not None
        assert funcSpimDisasm.vramEnd is not None
        self.parent: CommonSegCode = self.parent

        funcSym = self.parent.create_symbol(
            funcSpimDisasm.vram, type="func", define=True
        )
        funcSym.given_name = funcSpimDisasm.name

        # Gather symbols found by spimdisasm and create those symbols in splat's side
        for referencedVram in funcSpimDisasm.referencedVRams:
            contextSym = self.context.getAnySymbol(referencedVram)
            if contextSym is not None:
                if contextSym.type == spimdisasm.common.SymbolSpecialType.branchlabel:
                    continue
                symType = None
                if contextSym.type == spimdisasm.common.SymbolSpecialType.jumptable:
                    symType = "jtbl"
                    self.parent.jumptables[referencedVram] = (
                        funcSpimDisasm.vram,
                        funcSpimDisasm.vramEnd,
                    )
                sym = self.parent.create_symbol(
                    referencedVram, type=symType, reference=True
                )
                sym.given_name = contextSym.name

        for labelOffset in funcSpimDisasm.localLabels:
            labelVram = funcSpimDisasm.vram + labelOffset
            label_sym = self.parent.get_symbol(
                labelVram, type="label", reference=True, local_only=True
            )

            if label_sym is not None:
                contextSym = self.context.getGenericLabel(labelVram)
                if contextSym is not None:
                    contextSym.name = label_sym.name
            else:
                self.parent.labels_to_add.add(labelVram)

        # Main loop
        for i, insn in enumerate(funcSpimDisasm.instructions):
            mnemonic = insn.getOpcodeName().lower()
            instrOffset = i * 4
            insn_address = funcSym.vram_start + instrOffset

            funcSym.insns.append(Instruction(insn, mnemonic, rom_addr))
            rom_addr += 4

            if mnemonic == "jr":
                # Record potential jtbl jumps
                rs = insn.getRegisterName(insn.rs)
                if rs not in ["$ra", "$31"]:
                    self.parent.jtbl_jumps[insn_address] = rs

            # update pointer accesses from this function
            if instrOffset in funcSpimDisasm.pointersPerInstruction:
                symAddress = funcSpimDisasm.pointersPerInstruction[instrOffset]

                contextSym = self.context.getAnySymbol(symAddress)
                if contextSym is not None:
                    sym = self.parent.create_symbol(
                        symAddress, offsets=True, reference=True
                    )
                    sym.given_name = contextSym.name

                    if (
                        mnemonic
                        in self.double_mnemonics
                        + self.word_mnemonics
                        + self.float_mnemonics
                        + self.short_mnemonics
                        + self.byte_mnemonics
                    ):
                        self.update_access_mnemonic(sym, mnemonic)

                    if self.parent:
                        self.parent.check_rodata_sym(funcSpimDisasm.vram, sym)

    def update_access_mnemonic(self, sym: Symbol, mnemonic: str):
        if not sym.access_mnemonic:
            sym.access_mnemonic = mnemonic
        elif sym.access_mnemonic == "addiu":
            sym.access_mnemonic = mnemonic
        elif sym.access_mnemonic in self.double_mnemonics:
            return
        elif (
            sym.access_mnemonic in self.float_mnemonics
            and mnemonic in self.double_mnemonics
        ):
            sym.access_mnemonic = mnemonic
        elif sym.access_mnemonic in self.short_mnemonics:
            return
        elif sym.access_mnemonic in self.byte_mnemonics:
            return
        else:
            sym.access_mnemonic = mnemonic

    def printFileBoundaries(self):
        if not options.find_file_boundaries():
            return

        for inFileOffset in self.textSection.fileBoundaries:
            if (inFileOffset % 16) != 0:
                continue

            if not self.parent.reported_file_split:
                self.parent.reported_file_split = True

                # Look up for the last function in this boundary
                func_addr = 0
                for func in self.textSection.symbolList:
                    funcOffset = func.inFileOffset - self.textSection.inFileOffset
                    if inFileOffset == funcOffset:
                        break
                    func_addr = func.vram

                print(
                    f"Segment {self.name}, function at vram {func_addr:X} ends with extra nops, indicating a likely file split."
                )
                print(
                    "File split suggestions for this segment will follow in config yaml format:"
                )
            print(f"      - [0x{self.rom_start+inFileOffset:X}, asm]")

    def gather_jumptable_labels(self, rom_bytes):
        # TODO: use the seg_symbols for this
        # jumptables = [j.type == "jtbl" for j in self.seg_symbols]
        for jumptable in self.parent.jumptables:
            start, end = self.parent.jumptables[jumptable]
            rom_offset = self.rom_start + jumptable - self.vram_start

            if rom_offset <= 0:
                return

            while rom_offset:
                word = rom_bytes[rom_offset : rom_offset + 4]
                word_int = int.from_bytes(word, options.get_endianess())
                if word_int >= start and word_int <= end:
                    self.parent.jtbl_glabels_to_add.add(word_int)
                else:
                    break

                rom_offset += 4

    def should_scan(self) -> bool:
        return (
            options.mode_active("code")
            and self.rom_start != "auto"
            and self.rom_end != "auto"
        )

    def should_split(self) -> bool:
        return self.extract and options.mode_active("code")
