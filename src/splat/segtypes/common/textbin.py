from pathlib import Path
import re
from typing import Optional, TextIO

from ...util import log, options

from .segment import CommonSegment


class CommonSegTextbin(CommonSegment):
    def __init__(
        self,
        rom_start: Optional[int],
        rom_end: Optional[int],
        type: str,
        name: str,
        vram_start: Optional[int],
        args: list,
        yaml,
    ):
        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            args=args,
            yaml=yaml,
        )
        self.use_src_path: bool = isinstance(yaml, dict) and yaml.get(
            "use_src_path", False
        )

    @staticmethod
    def is_text() -> bool:
        return True

    def get_linker_section(self) -> str:
        return ".text"

    def get_section_flags(self) -> Optional[str]:
        return "ax"

    def out_path(self) -> Optional[Path]:
        if self.use_src_path:
            return options.opts.src_path / self.dir / f"{self.name}.s"

        return options.opts.data_path / self.dir / f"{self.name}.s"

    def bin_path(self) -> Path:
        typ = self.type
        if typ.startswith("."):
            typ = typ[1:]

        return options.opts.asset_path / self.dir / f"{self.name}.{typ}.bin"

    def write_bin(self, rom_bytes):
        binpath = self.bin_path()
        binpath.parent.mkdir(parents=True, exist_ok=True)

        assert isinstance(self.rom_start, int)
        assert isinstance(self.rom_end, int)

        binpath.write_bytes(rom_bytes[self.rom_start : self.rom_end])

        self.log(f"Wrote {self.name} to {binpath}")

    def write_asm_contents(self, rom_bytes, f: TextIO):
        binpath = self.bin_path()
        asm_label = options.opts.asm_function_macro
        if not self.is_text():
            asm_label = options.opts.asm_data_macro

        assert isinstance(self.rom_start, int)
        assert isinstance(self.rom_end, int)

        f.write(f"{self.get_section_asm_line()}\n\n")

        sym_name = None
        sym_name_end = None
        sym_size_matches = None

        # Check if there's a symbol at this address
        vram = self.rom_to_ram(self.rom_start)
        if vram is not None:
            sym = self.get_symbol(vram, in_segment=True)
            if sym is not None:
                sym.defined = True
                sym_name = sym.name
                sym_name_end = sym.given_name_end
                if (
                    sym.given_size is None
                    or sym.given_size == self.rom_end - self.rom_start
                ):
                    sym_size_matches = self.rom_end - self.rom_start

        if sym_name is None:
            # Normalize stuff like slashes and such.
            n = regex_sym_name_normalizer.sub("_", self.name)
            if self.is_text():
                suffix = "textbin"
            elif self.is_data():
                suffix = "databin"
            elif self.is_rodata():
                suffix = "rodatabin"
            else:
                suffix = "incbin"
            sym_name = f"__{n}_{suffix}"

        if options.opts.asm_nonmatching_label_macro != "":
            siz = f", 0x{sym_size_matches:X}" if sym_size_matches is not None else ""
            f.write(f"{options.opts.asm_nonmatching_label_macro} {sym_name}{siz}\n\n")

        f.write(f"{asm_label} {sym_name}\n")
        if asm_label == ".globl":
            if self.is_text():
                f.write(f".ent {sym_name}\n")
            f.write(f"{sym_name}:\n")

        f.write(f'.incbin "{binpath.as_posix()}"\n')

        if options.opts.asm_emit_size_directive:
            f.write(f".size {sym_name}, . - {sym_name}\n")

        if self.is_text() and options.opts.asm_end_label != "":
            f.write(f"{options.opts.asm_end_label} {sym_name}\n")
        elif options.opts.asm_data_end_label != "":
            f.write(f"{options.opts.asm_data_end_label} {sym_name}\n")

        if sym_name_end is not None and sym_size_matches is not None:
            f.write(f"{asm_label} {sym_name_end}\n")
            if asm_label == ".globl":
                f.write(f"{sym_name_end}:\n")

            if self.is_text() and options.opts.asm_end_label != "":
                f.write(f"{options.opts.asm_end_label} {sym_name_end}\n")
            elif options.opts.asm_data_end_label != "":
                f.write(f"{options.opts.asm_data_end_label} {sym_name_end}\n")

    def split(self, rom_bytes):
        if self.rom_end is None:
            log.error(
                f"segment {self.name} needs to know where it ends; add a position marker [0xDEADBEEF] after it"
            )

        self.write_bin(rom_bytes)

        s_path = self.out_path()
        assert s_path is not None

        if s_path.exists():
            return

        s_path.parent.mkdir(parents=True, exist_ok=True)

        with s_path.open("w") as f:
            f.write('.include "macro.inc"\n\n')
            preamble = options.opts.generated_s_preamble
            if preamble:
                f.write(preamble + "\n")

            self.write_asm_contents(rom_bytes, f)

            for sect in self.section_order:
                if sect == self.get_linker_section_linksection():
                    continue

                sibling = self.siblings.get(sect)
                if sibling is None:
                    continue

                # We check against CommonSegTextbin instead of the specific type because the other incbins inherit from this class
                if isinstance(sibling, CommonSegTextbin):
                    f.write("\n")
                    sibling.write_asm_contents(rom_bytes, f)

    def should_scan(self) -> bool:
        return self.rom_start is not None and self.rom_end is not None

    def should_split(self) -> bool:
        return (
            self.extract and self.should_scan()
        )  # only split if the segment was scanned first


regex_sym_name_normalizer = re.compile(r"[^0-9a-zA-Z_]")
