from typing import Optional, Union

from pathlib import Path

from ...util import options
from ..common.lib import CommonSegment
from ..segment import parse_segment_vram


class CommonSegO(CommonSegment):
    def __init__(
        self,
        rom_start: Optional[int],
        rom_end: Optional[int],
        type: str,
        name: str,
        vram_start: Optional[int],
        args: list,
        yaml: Union[dict, list],
        bss_size: Optional[int] = None,
    ):
        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            args=args,
            yaml=yaml,
            bss_size=bss_size,
        )

        vram = parse_segment_vram(self.yaml)
        if vram is not None:
            self.vram_start = vram

        if yaml and isinstance(yaml, dict):
            self.section = yaml.get("section", ".text")
        else:
            if len(args) > 0:
                self.section = args[0]
            else:
                self.section = ".text"

        self.extract = False

    def get_linker_section(self) -> str:
        return self.section

    def out_path(self) -> Optional[Path]:
        out_path = options.opts.o_path / f"{self.name}"
        return out_path
