from typing import Union, List, Tuple
from pathlib import Path
from util import options
from segtypes.segment import Segment
from segtypes.n64.code import Subsegment

# clean 'foo/../bar' to 'bar'
def clean_up_path(path: Path) -> Path:
    return path.resolve().relative_to(options.get_base_path().resolve())

def path_to_object_path(path: Path) -> Path:
    path = options.get_build_path() / path.with_suffix(path.suffix + ".o").relative_to(options.get_base_path())
    return clean_up_path(path)

class LinkerEntry:
    def __init__(self, segment_or_subsegment: Union[Segment, Subsegment], src_paths: List[Path], object_path: Path, section: str):
        self.segment_or_subsegment = segment_or_subsegment
        self.src_paths = [clean_up_path(p) for p in src_paths]
        self.object_path = path_to_object_path(object_path)
        self.section = section

    def segment(self) -> Segment:
        if isinstance(self.segment_or_subsegment, Segment):
            return self.segment_or_subsegment
        else:
            parent = self.segment_or_subsegment.parent
            assert isinstance(parent, Segment)
            return parent

class LinkerWriterFacade:
    def __init__(self, shiftable: bool):
        self.shiftable = shiftable
        self.entries: List[LinkerEntry] = []

    def add(self, segment: Segment):
        self.entries.extend(segment.get_linker_entries())

    def save_linker_script(self, path: Path):
        pass

    def save_symbol_header(self, path: Path):
        pass

class LinkerWriter(LinkerWriterFacade):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.buffer: List[str] = []
        self.symbols: List[str] = []

        self._writeln("SECTIONS")
        self._writeln("{")

    def add(self, segment: Segment):
        entries = segment.get_linker_entries()
        self.entries.extend(entries)

        self._begin_segment(segment)

        do_next = False
        for i, entry in enumerate(entries):
            if entry.section == "linker": # TODO: isinstance is preferable
                self._writeln("}")
                self._begin_segment(entry.segment_or_subsegment)

            start = entry.segment_or_subsegment.rom_start
            if isinstance(start, int):
                # Create new sections for non-0x10 alignment (hack)
                if start % 0x10 != 0 and i != 0 or do_next:
                    self._writeln("}")
                    self._begin_segment(entry.segment_or_subsegment)
                    do_next = False

                if start % 0x10 != 0 and i != 0:
                    do_next = True

            # TEMP? use entry.segment_or_subsegment.name
            import re
            path_cname = re.sub(r"[^0-9a-zA-Z_]", "_", str(entry.object_path))
            self._write_symbol(path_cname, ".")

            if entry.section != "linker":
                self._writeln(f"{entry.object_path}({entry.section});")

        self._end_segment(segment)

    def save_linker_script(self, path: Path):
        self._writeln("/DISCARD/ :")
        self._writeln("{")
        self._writeln("*(*);")
        self._writeln("}")

        self._writeln("}") # SECTIONS

        with path.open("w") as f:
            for s in self.buffer:
                f.write(s)
                f.write("\n")

    def save_symbol_header(self, path: Path):
        with path.open("w") as f:
            f.write("#ifndef _HEADER_SYMBOLS_H_\n")
            f.write("#define _HEADER_SYMBOLS_H_\n\n")
            for symbol in self.symbols:
                f.write(f"extern Addr {symbol};\n")
            f.write("\n#endif\n")

    def _writeln(self, line: str):
        self.buffer.append(line)

    def _write_symbol(self, symbol: str, value: Union[str, int]):
        if isinstance(value, int):
            value = f"0x{value:X}"

        self._writeln(f"{symbol} = {value};")
        self.symbols.append(symbol)

    def _begin_segment(self, segment: Union[Segment, Subsegment]):
        # force location if not shiftable/auto
        if not self.shiftable and isinstance(segment.rom_start, int):
            self._writeln(f". = 0x{segment.rom_start:X};")

        vram = segment.vram_start
        vram_str = f"0x{vram:X}" if isinstance(vram, int) else ""

        self._write_symbol(f"{segment.name}_ROM_START", ".")
        self._write_symbol(f"{segment.name}_VRAM", f"ADDR(.{segment.name})")
        self._writeln(f".{segment.name} {vram_str} : AT({segment.name}_ROM_START) SUBALIGN({segment.subalign}) {{")

    def _end_segment(self, segment: Union[Segment, Subsegment]):
        self._writeln("}")

        # force end if not shiftable/auto
        if not self.shiftable and isinstance(segment.rom_end, int):
            self._write_symbol(f"{segment.name}_ROM_END", segment.rom_end)
        else:
            self._write_symbol(f"{segment.name}_ROM_END", ".")
