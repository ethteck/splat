"""`type: asm` alias for the win32 text segment.

Lets win32 YAML use the more conventional `asm` segtype name (matching the
other platforms) instead of `text`. Same behaviour as `Win32SegText`."""

from .text import Win32SegText


class Win32SegAsm(Win32SegText):
    """Alias for Win32SegText so YAML can use `type: asm` (the
    convention on other splat platforms) instead of `type: text`.
    No behavioural difference."""

    pass
