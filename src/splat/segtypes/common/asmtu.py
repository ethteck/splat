from pathlib import Path
from typing import Optional, TextIO

from ...util import log, options

from .asm import CommonSegAsm
from .codesubsegment import CommonSegCodeSubsegment


class CommonSegAsmtu(CommonSegAsm):
    def split(self, rom_bytes: bytes):
        if self.rom_start == self.rom_end:
            return

        if self.spim_section is None:
            return

        out_path = self.out_path()
        assert out_path is not None, str(self)

        out_path.parent.mkdir(parents=True, exist_ok=True)

        self.print_file_boundaries()

        with open(out_path, "w", newline="\n") as f:
            # Write `.text` contents
            for line in self.get_file_header():
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
                    and not sibling.should_split()
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
                    and not sibling.should_split()
                ):
                    f.write("\n")
                    f.write(f"{sibling.get_section_asm_line()}\n\n")
                    f.write(sibling.spim_section.disassemble())
