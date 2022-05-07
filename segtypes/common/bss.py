from segtypes.common.data import CommonSegData
from util import options, log


class CommonSegBss(CommonSegData):
    def get_linker_section(self) -> str:
        return ".bss"

    def scan(self, rom_bytes: bytes):
        pass

    def split(self, rom_bytes: bytes):
        pass

    def get_linker_entries(self) -> "List[LinkerEntry]":
        from segtypes.linker_entry import LinkerEntry

        if self.sibling:
            path = self.sibling.out_path()
        else:
            path = self.out_path()

        print(self.out_path())

        return [LinkerEntry(self, [path], path, self.get_linker_section())]
