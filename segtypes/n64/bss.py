from pathlib import Path
from typing import Optional
from segtypes.n64.code import N64SegCode

class N64SegBss(N64SegCode):
    def out_path(self) -> Optional[Path]:
        return None

    def scan(self, rom_bytes: bytes):
        pass

    def split(self, rom_bytes: bytes):
        pass

    def get_linker_entries(self):
        from segtypes.linker_entry import LinkerEntry

        if self.c_sibling:
            path = self.c_sibling.out_path()
        else:
            path = self.out_path()

        return [LinkerEntry(self, [path], path, ".bss")]
