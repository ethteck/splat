"""Win32 .bss segment — emits a NOLOAD reservation."""

from pathlib import Path
from typing import Optional

from ..common.segment import CommonSegment
from ...util import options


class Win32SegBss(CommonSegment):
    """Uninitialised data segment (`.bss`).

    Emits a `.section .bss, "wa"` block with a single `.space N`
    directive — the loader zero-fills these bytes at map time, so
    they have no on-file representation. `reserved_size` resolves to
    the YAML's `bss_size:` value if set, else `vram_end - vram_start`,
    else zero (in which case the segment is degenerate and the create-
    config layer skips it)."""

    @staticmethod
    def is_noload() -> bool:
        return True

    def get_linker_section(self) -> str:
        return ".bss"

    def get_section_flags(self) -> Optional[str]:
        return "wa"

    def out_path(self) -> Path:
        return options.opts.data_path / self.dir / f"{self.name}.s"

    @property
    def reserved_size(self) -> int:
        if isinstance(self.yaml, dict):
            sz = self.yaml.get("bss_size")
            if sz is not None:
                return int(sz)
        if self.vram_start is not None and self.vram_end is not None:
            return self.vram_end - self.vram_start
        return 0

    def should_split(self) -> bool:
        return self.extract and options.opts.is_mode_active("code")

    def split(self, rom_bytes: bytes):
        path = self.out_path()
        path.parent.mkdir(parents=True, exist_ok=True)

        size = self.reserved_size
        with path.open("w", encoding="utf-8", newline="\n") as f:
            preamble = options.opts.generated_s_preamble
            if preamble:
                f.write(preamble + "\n\n")
            f.write(self.get_section_asm_line() + "\n\n")
            f.write(f".global {self.name}\n")
            f.write(f"{self.name}:\n")
            if size > 0:
                f.write(f"    .space 0x{size:X}\n")

        self.log(f"Wrote {self.name} to {path}")
