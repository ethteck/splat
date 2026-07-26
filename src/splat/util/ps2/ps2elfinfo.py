#! /usr/bin/env python3

from __future__ import annotations

import dataclasses
from pathlib import Path
import spimdisasm
from spimdisasm.elf32 import (
    Elf32File,
    Elf32Constants,
    Elf32SectionHeaderFlag,
    Elf32ObjectFileType,
)
from typing import Optional

from .. import log


ELF_SECTION_MAPPING: dict[str, str] = {
    ".text": "asm",
    ".data": "data",
    ".rodata": "rodata",
    ".bss": "bss",
    ".sdata": "sdata",
    ".sbss": "sbss",
    ".gcc_except_table": "gcc_except_table",
    ".lit4": "lit4",
    ".lit8": "lit8",
    ".ctor": "ctor",
    ".vtables": "vtables",
    ".vutext": "textbin",  # No "proper" support yet
    ".vudata": "databin",  # No "proper" support yet
}

# Section to not put into the elf_section_names list, because splat doesn't
# know have support for them yet.
ELF_SECTIONS_IGNORE: set[str] = {
    ".vutext",
    ".vudata",
    ".vubss",
}

ELF_SMALL_SECTIONS: set[str] = {
    ".lit4",
    ".lit8",
    ".sdata",
    ".srdata",
    ".sbss",
}


@dataclasses.dataclass
class Ps2Elf:
    entrypoint: int
    segs: list[FakeSegment]
    size: int
    compiler: str
    elf_section_names: list[tuple[str, bool]]
    gp: Optional[int]
    ld_gp_expression: Optional[str]

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

        if elf.reginfo is not None and elf.reginfo.gpValue != 0:
            gp = elf.reginfo.gpValue
        else:
            gp = None
        first_small_section_info: Optional[tuple[str, int]] = None

        first_segment_name = "cod"
        segs = [FakeSegment(first_segment_name, 0, 0, [])]

        # TODO: check `.comment` section for any compiler info
        compiler = "EEGCC"

        elf_section_names: list[tuple[str, bool]] = []

        first_offset: Optional[int] = None
        rom_size = 0

        previous_type = Elf32Constants.Elf32SectionHeaderType.PROGBITS
        do_new_segs = False

        # Loop over all the sections.
        # Treat every normal elf section as part as the "main" segment.
        # If we see a PROGBITS after a NOBITS then we shift the behavior into
        # putting every new elf section into their own segment, this can happen
        # when the elf contains a few special sections like `.mfifo`.
        section_headers = sorted(elf.sectionHeaders, key=lambda x: x.offset)
        for section in section_headers:
            if section.size == 0:
                # Skip over empty sections
                continue

            name = elf.shstrtab[section.name]
            if name == ".mwcats":
                compiler = "MWCCPS2"
                continue

            flags, _unknown_flags = Elf32SectionHeaderFlag.parseFlags(section.flags)
            # if _unknown_flags != 0:
            #     print(name, f"0x{_unknown_flags:08X}")
            if Elf32SectionHeaderFlag.ALLOC not in flags:
                # We don't care about non-alloc sections
                continue

            # We want PROGBITS (actual data) and NOBITS (bss and similar)
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
                log.write(
                    f"Unknown section type '{typ}' ({name}) found in the elf",
                    status="warn",
                )
                return None

            if first_offset is None:
                first_offset = section.offset

            if first_small_section_info is None and name in ELF_SMALL_SECTIONS:
                first_small_section_info = (name, section.addr)

            start = section.offset - first_offset
            size = section.size

            if do_new_segs:
                segs.append(FakeSegment(name.lstrip("."), 0, start, []))

            # Try to map this section to something splat can understand.
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
                valid_for_splat = (
                    name in ELF_SECTION_MAPPING
                    and name not in ELF_SECTIONS_IGNORE
                    and not do_new_segs
                )
                elf_section_names.append((name, valid_for_splat))

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
                rom_size = start + size

            previous_type = typ

        # There are some games where they just squashed most sections into a
        # single one, making the elf_section_names list pretty useless.
        # We try to detect this and provide a default list if that's the case,
        # hoping for the best.
        if len(elf_section_names) < 4:
            elf_section_names = [
                (".text", True),
                (".vutext", False),
                (".data", True),
                (".vudata", False),
                (".rodata", True),
                (".gcc_except_table", True),
                (".lit8", True),
                (".lit4", True),
                (".sdata", True),
                (".sbss", True),
                (".bss", True),
                (".vubss", False),
            ]

        # Fixup vram address of segments
        for seg in segs:
            seg.vram = seg.sections[0].vram

        ld_gp_expression = None
        if gp is not None and first_small_section_info is not None:
            section_name, section_address = first_small_section_info
            if gp > section_address:
                diff = gp - section_address
                ld_gp_expression = f"{first_segment_name}_{section_name.strip('.').upper()}_START + 0x{diff:04X}"

        return Ps2Elf(
            elf.header.entry,
            segs,
            rom_size,
            compiler,
            elf_section_names,
            gp,
            ld_gp_expression,
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
