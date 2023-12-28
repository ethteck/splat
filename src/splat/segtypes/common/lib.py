from pathlib import Path
from typing import Optional, List

from ...util import log, options

from ..linker_entry import LinkerEntry, LinkerWriter
from .segment import CommonSegment

from ..segment import Segment


class LinkerEntryLib(LinkerEntry):
    def __init__(
        self,
        segment: Segment,
        src_paths: List[Path],
        object_path: Path,
        section_order: str,
        section_link: str,
        noload: bool,
    ):
        super().__init__(
            segment, src_paths, object_path, section_order, section_link, noload
        )
        self.object_path = object_path

    def emit_entry(self, linker_writer: LinkerWriter):
        self.emit_path(linker_writer)


class CommonSegLib(CommonSegment):
    def __init__(
        self,
        rom_start: Optional[int],
        rom_end: Optional[int],
        type: str,
        name: str,
        vram_start: Optional[int],
        args: list,
        yaml,
    ):
        super().__init__(
            rom_start,
            rom_end,
            type,
            name,
            vram_start,
            args=args,
            yaml=yaml,
        )

        if isinstance(yaml, dict):
            log.error("Error: 'dict' not currently supported for 'lib' segment")
            return
        if len(args) < 1:
            log.error(f"Error: {self.name} is missing object file")
            return

        self.extract = False

        if len(args) > 1:
            self.object, self.section = args[0], args[1]
        else:
            self.object, self.section = args[0], ".text"

    def get_linker_section(self) -> str:
        return self.section

    def get_linker_entries(self) -> List[LinkerEntry]:
        path = options.opts.lib_path / self.name

        object_path = Path(f"{path}.a:{self.object}.o")

        return [
            LinkerEntryLib(
                self,
                [path],
                object_path,
                self.get_linker_section_order(),
                self.get_linker_section_linksection(),
                self.is_noload(),
            )
        ]
