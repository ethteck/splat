from typing import TYPE_CHECKING, Union, Optional, List, Literal
from pathlib import Path
from util import log
from util import options
import re
import sys

# circular import
if TYPE_CHECKING:
    from segtypes.linker_entry import LinkerEntry

RomAddr = Union[int, Literal["auto"]]

def parse_segment_start(segment: Union[dict, list]) -> RomAddr:
    if isinstance(segment, dict):
        s = segment.get("start", "auto")
    else:
        s = segment[0]

    if s == "auto":
        return "auto"
    else:
        return int(s)

def parse_segment_type(segment: Union[dict, list]) -> str:
    if isinstance(segment, dict):
        return str(segment["type"])
    else:
        return str(segment[1])


def parse_segment_name(segment: Union[dict, list], segment_class) -> str:
    if isinstance(segment, dict) and "name" in segment:
        return str(segment["name"])
    elif isinstance(segment, list) and len(segment) >= 3 and isinstance(segment[2], str):
        return segment[2]
    else:
        return str(segment_class.get_default_name(parse_segment_start(segment)))


def parse_segment_vram(segment: Union[dict, list]) -> Optional[int]:
    if isinstance(segment, dict) and "vram" in segment:
        return int(segment["vram"])
    else:
        return None


def parse_segment_subalign(segment: Union[dict, list]) -> int:
    default = options.get_subalign()
    if isinstance(segment, dict):
        return int(segment.get("subalign", default))
    return default


class Segment:
    require_unique_name = True

    def __init__(self, segment: Union[dict, list], next_segment: Union[dict, list]):
        self.rom_start = parse_segment_start(segment)
        self.rom_end = parse_segment_start(next_segment)
        self.type = parse_segment_type(segment)
        self.name = parse_segment_name(segment, self.__class__)
        self.dir = Path(segment.get("dir", "")) if isinstance(segment, dict) else Path()
        self.vram_start = parse_segment_vram(segment)
        self.extract = bool(segment.get("extract", True)) if isinstance(segment, dict) else True
        self.config = segment
        self.subalign = parse_segment_subalign(segment)

        if self.rom_start == "auto":
            self.extract = False

        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.did_run = False

        if isinstance(self.rom_start, int) and isinstance(self.rom_end, int):
            if self.rom_start > self.rom_end:
                print(f"Error: segments out of order - ({self.name} starts at 0x{self.rom_start:X}, but next segment starts at 0x{self.rom_end:X})")
                sys.exit(1)

    @property
    def size(self) -> Optional[int]:
        if isinstance(self.rom_start, int) and isinstance(self.rom_end, int):
            return self.rom_end - self.rom_start
        else:
            return None

    @property
    def vram_end(self) -> Optional[int]:
        if self.vram_start is not None and self.size is not None:
            return self.vram_start + self.size
        else:
            return None

    def contains_vram(self, vram: int) -> bool:
        if self.vram_start is not None and self.vram_end is not None:
            return vram >= self.vram_start and vram < self.vram_end
        else:
            return False

    def contains_rom(self, rom: int) -> bool:
        if isinstance(self.rom_start, int) and isinstance(self.rom_end, int):
            return rom >= self.rom_start and rom < self.rom_end
        else:
            return False

    def rom_to_ram(self, rom_addr: int) -> Optional[int]:
        if not self.contains_rom(rom_addr) and rom_addr != self.rom_end:
            return None

        if self.vram_start is not None and isinstance(self.rom_start, int):
            return self.vram_start + rom_addr - self.rom_start
        else:
            return None

    def ram_to_rom(self, ram_addr: int) -> Optional[int]:
        if not self.contains_vram(ram_addr) and ram_addr != self.vram_end:
            return None

        if self.vram_start is not None and isinstance(self.rom_start, int):
            return self.rom_start + ram_addr - self.vram_start
        else:
            return None

    def should_run(self):
        return self.extract and options.mode_active(self.type)

    def split(self, rom_bytes: bytes):
        pass

    def postsplit(self, segments: List[Union[dict, list]]):
        pass

    def cache(self):
        return (self.config, self.rom_end)

    def get_linker_entries(self) -> 'List[LinkerEntry]':
        return []

    def log(self, msg):
        if options.get("verbose", False):
            log.write(f"{self.type} {self.name}: {msg}")

    def warn(self, msg: str):
        self.warnings.append(msg)

    def error(self, msg: str):
        self.errors.append(msg)

    def max_length(self):
        return None

    def is_name_default(self):
        return self.name == self.get_default_name(self.rom_start)

    def unique_id(self):
        return self.type + "_" + self.name

    def status(self):
        if len(self.errors) > 0:
            return "error"
        elif len(self.warnings) > 0:
            return "warn"
        elif self.did_run:
            return "ok"
        else:
            return "skip"

    @staticmethod
    def get_default_name(addr) -> str:
        return "{:X}".format(addr)
