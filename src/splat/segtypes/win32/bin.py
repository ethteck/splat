"""Win32 binary blob segment — reuse the common bin segment for things like
.rsrc / .reloc / .idata / coff_symtab / signature where the section's
bytes are structured loader-time data rather than meaningful code or
labelled pointers. Splat writes the raw bytes to a `.bin` file under
asset_path; the linker layout (or the win32_reassemble post-process)
incorporates them at the right rom_start without any decoding pass."""

from ..common.bin import CommonSegBin


class Win32SegBin(CommonSegBin):
    """Win32-specific marker class — same behaviour as CommonSegBin,
    re-exported so YAML `type: bin` resolves through the win32
    segtype lookup. Used for .rsrc / .reloc / .idata / coff_symtab /
    signature segments produced by create_win32_config."""

    pass
