from pathlib import Path

from util import options
from segtypes.common.rodata import CommonSegRodata


class CommonSegData_within_rodata(CommonSegRodata):
    def get_linker_section_order(self) -> str:
        return ".data"

    def asm_out_path(self) -> Path:
        return options.opts.data_path / self.dir / f"{self.name}.rodata.s"
