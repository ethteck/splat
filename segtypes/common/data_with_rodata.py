from pathlib import Path

from util import options
from segtypes.common.data import CommonSegData

class CommonSegData_with_rodata(CommonSegData):
    def get_linker_section_order(self) -> str:
        return ".rodata"

    def asm_out_path(self) -> Path:
        return options.opts.data_path / self.dir / f"{self.name}.data.s"
