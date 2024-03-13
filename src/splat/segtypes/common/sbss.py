from .bss import CommonSegBss


class CommonSegSbss(CommonSegBss):
    def get_linker_section(self) -> str:
        return ".sbss"
