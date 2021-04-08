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

def write_file_if_different(path: Path, new_content: str):
    if path.exists():
        old_content = path.read_text()
    else:
        old_content = ""

    if old_content != new_content:
        with path.open("w") as f:
            f.write(new_content)

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

        self._indent_level = 0

        self._writeln("SECTIONS")
        self._begin_block()

    def add(self, segment: Segment):
        entries = segment.get_linker_entries()
        self.entries.extend(entries)

        self._begin_segment(segment)

        do_next = False
        for i, entry in enumerate(entries):
            if entry.section == "linker": # TODO: isinstance is preferable
                self._end_block()
                self._begin_segment(entry.segment_or_subsegment)

            start = entry.segment_or_subsegment.rom_start
            if isinstance(start, int):
                # Create new sections for non-0x10 alignment (hack)
                if start % 0x10 != 0 and i != 0 or do_next:
                    self._end_block()
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
        self._begin_block()
        self._writeln("*(*);")
        self._end_block()

        self._end_block() # SECTIONS

        assert self._indent_level == 0

        write_file_if_different(path, "\n".join(self.buffer) + "\n")

    def save_symbol_header(self, path: Path):
        write_file_if_different(path,
            "#ifndef _HEADER_SYMBOLS_H_\n"
            "#define _HEADER_SYMBOLS_H_\n"
            "\n"
            + "".join(f"extern Addr {symbol};\n" for symbol in self.symbols) +
            "\n"
            "#endif\n"
        )

    def _writeln(self, line: str):
        if len(line) == 0:
            self.buffer.append(line)
        else:
            self.buffer.append("    " * self._indent_level + line)

    def _begin_block(self):
        self._writeln("{")
        self._indent_level += 1

    def _end_block(self):
        self._indent_level -= 1
        self._writeln("}")

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
        self._writeln(f".{segment.name} {vram_str} : AT({segment.name}_ROM_START) SUBALIGN({segment.subalign})")
        self._begin_block()

    def _end_segment(self, segment: Union[Segment, Subsegment]):
        self._end_block()

        # force end if not shiftable/auto
        if not self.shiftable and isinstance(segment.rom_end, int):
            self._write_symbol(f"{segment.name}_ROM_END", segment.rom_end)
        else:
            self._write_symbol(f"{segment.name}_ROM_END", ".")

        self._writeln("")
