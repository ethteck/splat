"""Win32 .rodata segment — read-only initialized data."""

from .data import Win32SegData


class Win32SegRodata(Win32SegData):
    """Read-only initialised data segment (`.rodata`).

    Inherits everything from Win32SegData but defaults `DETECT_STRINGS`
    + `HEURISTIC_POINTERS` to True since constants in read-only memory
    are overwhelmingly NUL-terminated strings or function-pointer
    tables. Maps to the assembly `.rodata` section with `"a"` flags
    (allocated, no write) so the assembler places them correctly even
    when the linker script doesn't merge `.rdata` and `.rodata`."""

    LINKER_SECTION = ".rodata"
    SECTION_FLAGS = "a"
    DETECT_STRINGS = True
    HEURISTIC_POINTERS = True

    @staticmethod
    def is_data() -> bool:
        return False

    @staticmethod
    def is_rodata() -> bool:
        return True
