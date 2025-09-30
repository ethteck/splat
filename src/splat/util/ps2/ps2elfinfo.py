#! /usr/bin/env python3

from __future__ import annotations

import dataclasses
from pathlib import Path
import spimdisasm
from spimdisasm.elf32 import Elf32File, Elf32Constants, Elf32SectionHeaderFlag, Elf32ObjectFileType
from typing import Optional

from .. import log


ELF_SECTION_MAPPING: dict[str, str] = {
    ".text": "asm",
    ".data": "data",
    ".rodata": "rodata",
    ".bss": "bss",
    ".sbss": "sbss",
    ".gcc_except_table": "gcc_except_table",
    ".lit4": "lit4",
    ".lit8": "lit8",
    ".ctor": "ctor",
    ".vtables": "vtables",
    ".vutext": "textbin", # No "proper" support yet
    ".vudata": "databin", # No "proper" support yet
}


@dataclasses.dataclass
class Ps2Elf:
    entrypoint: int
    segs: list[FakeSegment]
    size: int
    compiler: str
    elf_section_names: list[str]
    # gp: Optional[int] # TODO

    @staticmethod
    def get_info(elf_path: Path, elf_bytes: bytes) -> Optional[Ps2Elf]:
        # Avoid spimdisasm from complaining about unknown sections.
        spimdisasm.common.GlobalConfig.QUIET = True

        elf = Elf32File(elf_bytes)
        if elf.header.type != Elf32ObjectFileType.EXEC.value:
            log.write("Elf file is not an EXEC type.", status="warn")
            return None
        if elf.header.machine != 8:
            # 8 corresponds to EM_MIPS
            # We only care about mips binaries.
            log.write("Elf file is not a MIPS binary.", status="warn")
            return None
        if Elf32Constants.Elf32HeaderFlag._5900 not in elf.elfFlags:
            log.write("Missing 5900 flag", status="warn")
            return None

        entrypoint = elf.header.entry
        start = 0
        segs = [FakeSegment("cod", 0, start, [])]

        # TODO: check `.comment` section for any compiler info
        compiler = "EEGCC"

        elf_section_names = []

        previous_type = Elf32Constants.Elf32SectionHeaderType.PROGBITS
        do_new_segs = False
        for section in elf.sectionHeaders:
            if section.size == 0:
                continue

            name = elf.shstrtab[section.name]
            if name == ".mwcats":
                compiler = "MWCCPS2"
                continue

            flags, _unknown_flags = Elf32SectionHeaderFlag.parseFlags(section.flags)
            if Elf32SectionHeaderFlag.ALLOC not in flags:
                continue

            typ = Elf32Constants.Elf32SectionHeaderType.fromValue(section.type)
            is_nobits = typ == Elf32Constants.Elf32SectionHeaderType.NOBITS
            if typ == Elf32Constants.Elf32SectionHeaderType.PROGBITS:
                if previous_type == Elf32Constants.Elf32SectionHeaderType.NOBITS:
                    do_new_segs = True
                pass
            elif typ == Elf32Constants.Elf32SectionHeaderType.NOBITS:
                pass
            elif typ == Elf32Constants.Elf32SectionHeaderType.MIPS_REGINFO:
                continue
            else:
                log.write(f"Unknown section type '{typ}' ({name}) found in the elf", status="warn")
                return None

            start = align_up(start, section.addralign)
            size = align_up(section.size, section.addralign)

            if do_new_segs:
                segs.append(FakeSegment(name, 0, start, []))

            splat_segment_type = ELF_SECTION_MAPPING.get(name)
            if splat_segment_type is None:
                # Let's infer based on the section's flags
                if is_nobits:
                    splat_segment_type = "bss"
                elif Elf32SectionHeaderFlag.EXECINSTR in flags:
                    splat_segment_type = "asm"
                elif Elf32SectionHeaderFlag.WRITE in flags:
                    splat_segment_type = "data"
                else:
                    # Whatever...
                    splat_segment_type = "rodata"

            if name.startswith("."):
                elf_section_names.append(name)

            new_section = ElfSection(
                name,
                splat_segment_type,
                section.addr,
                start,
                size,
                is_nobits,
            )
            segs[-1].sections.append(new_section)
            if is_nobits:
                segs[-1].bss_size += size
            else:
                start += size

            print(name, section.addralign)

            previous_type = typ

        # There are some games where they just squashed most sections into a
        # single one, making the elf_section_names list pretty useless.
        # We try to detect this and provide a default list if that's the case,
        # hoping for the best.
        if len(elf_section_names) < 4:
            elf_section_names = [
                ".text",
                # ".vutext",
                ".data",
                # ".vudata",
                ".rodata",
                ".gcc_except_table",
                ".lit8",
                ".lit4",
                ".sdata",
                ".sbss",
                ".bss",
                # ".vubss",
            ]

        # Fixup vram address of segments
        for seg in segs:
            seg.vram = seg.sections[0].vram

        return Ps2Elf(
            entrypoint,
            segs,
            start,
            compiler,
            elf_section_names,
        )



@dataclasses.dataclass
class FakeSegment:
    name: str
    vram: int
    start: int
    sections: list[ElfSection]
    bss_size: int = 0


@dataclasses.dataclass
class ElfSection:
    name: str
    splat_segment_type: str
    vram: int
    start: int
    size: int
    is_nobits: bool


def align_up(number: int, align: int) -> int:
    mod = number % align
    if mod == 0:
        return number
    return number + (align - mod)
