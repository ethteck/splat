"""Capstone-backed disassembler used by the win32 platform.

The MIPS disassembler stack (spimdisasm/rabbitizer) is incompatible with x86,
so win32 segments do not flow through `CommonSegCodeSubsegment`. This module
exposes a tiny façade: configure a Capstone engine once, hand it out to
segtypes for them to decode byte ranges, and surface known section names.
"""

from typing import Optional, Set

from . import disassembler
from ..util import log


class CapstoneDisassembler(disassembler.Disassembler):
    CAPSTONE_MIN = (5, 0, 0)

    def __init__(self):
        self._md = None

    def configure(self):
        # Defer engine creation to `get_engine()` — at this point in startup
        # the target hasn't been parsed yet, so we don't yet know whether
        # it's PE32 (CS_MODE_32) or PE32+ (CS_MODE_64).
        try:
            import capstone  # noqa: F401 — just verify availability
        except ImportError:
            log.error(
                "The win32 platform requires the optional 'capstone' dependency. "
                "Install it with: pip install 'splat64[win32]'"
            )

    def check_version(self, skip_version_check: bool, splat_version: str):
        try:
            import capstone
        except ImportError:
            log.error(
                "The win32 platform requires the optional 'capstone' dependency. "
                "Install it with: pip install 'splat64[win32]'"
            )

        if not skip_version_check:
            cs_version = getattr(capstone, "__version__", None)
            if cs_version is not None:
                parts = []
                for chunk in cs_version.split("."):
                    digits = "".join(c for c in chunk if c.isdigit())
                    parts.append(int(digits) if digits else 0)
                while len(parts) < 3:
                    parts.append(0)
                if tuple(parts[:3]) < self.CAPSTONE_MIN:
                    log.error(
                        f"splat {splat_version} requires at least capstone "
                        f"{self.CAPSTONE_MIN}, but {cs_version} is installed"
                    )
            log.write(
                f"splat {splat_version} (powered by capstone {cs_version or '?'})"
            )

    def get_engine(self):
        if self._md is not None:
            return self._md

        import capstone
        from ..platforms import win32 as win32_platform

        arch = capstone.CS_ARCH_X86
        # Honour the parsed PE's bitness when the platform module has been
        # initialized; otherwise default to PE32 (32-bit).
        if win32_platform.info.is_pe32_plus:
            mode = capstone.CS_MODE_64
        else:
            mode = capstone.CS_MODE_32

        md = capstone.Cs(arch, mode)
        md.detail = True
        md.syntax = capstone.CS_OPT_SYNTAX_INTEL
        self._md = md
        return md

    def known_types(self) -> Set[str]:
        # Mirror the standard primitive type names that the spimdisasm
        # backend exposes so symbol_addrs files written for win32 binaries
        # can use the same `type:u32` / `type:asciz` vocabulary.
        return {
            "u8",
            "u16",
            "u32",
            "u64",
            "s8",
            "s16",
            "s32",
            "s64",
            "f32",
            "f64",
            "char",
            "char*",
            "asciz",
        }


def get_capstone_disassembler() -> Optional["CapstoneDisassembler"]:
    """Return the active CapstoneDisassembler if one is wired up, else None."""
    from . import disassembler_instance

    inst = disassembler_instance.get_instance()
    if isinstance(inst, CapstoneDisassembler):
        return inst
    return None
