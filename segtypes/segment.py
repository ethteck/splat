from typing import Union, Optional, List, Literal
from pathlib import Path, PurePath
from util import log
from util import options
import re
import sys

RomAddr = Union[int, Literal["auto"]]

default_subalign = 16

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
    default = int(options.get("subalign", default_subalign))
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
        self.dir = str(segment.get("dir", ".")) if isinstance(segment, dict) else "."
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
        if not self.contains_rom(rom_addr):
            return None

        if self.vram_start is not None and isinstance(self.rom_start, int):
            return self.vram_start + rom_addr - self.rom_start
        else:
            return None

    def ram_to_rom(self, ram_addr: int) -> Optional[int]:
        if not self.contains_vram(ram_addr):
            return None

        if self.vram_start is not None and isinstance(self.rom_start, int):
            return self.rom_start + ram_addr - self.vram_start
        else:
            return None

    @staticmethod
    def create_split_dir(base_path, subdir):
        out_dir = Path(base_path, subdir)
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir

    @staticmethod
    def create_parent_dir(base_path, filename):
        out_dir = Path(base_path, filename).parent
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir

    def should_run(self):
        return self.extract and options.mode_active(self.type)

    def split(self, rom_bytes: bytes, base_path):
        pass

    def postsplit(self, segments: List[Union[dict, list]]):
        pass

    def cache(self):
        return (self.config, self.rom_end)

    def get_ld_section(self):
        replace_ext = bool(options.get("ld_o_replace_extension", True))
        vram_or_rom = self.rom_start if self.vram_start is None else self.vram_start
        subalign_str = f"SUBALIGN({self.subalign})"

        linker_rom_start = f"0x{self.rom_start:X}" if isinstance(self.rom_start, int) else "."

        s = (
            f"SPLAT_BEGIN_SEG({self.name}, {linker_rom_start}, 0x{vram_or_rom:X}, {subalign_str})\n"
        )

        i = 0
        do_next = False
        for subdir, path, obj_type, start in self.get_ld_files():
            # Manual linker segment creation
            if obj_type == "linker":
                s += (
                    "}\n"
                    f"SPLAT_BEGIN_SEG({path}, 0x{start:X}, 0x{self.rom_to_ram(start):X}, {subalign_str})\n"
                )

            # Create new sections for non-0x10 alignment (hack)
            if start % 0x10 != 0 and i != 0 or do_next:
                tmp_sect_name = path.replace(".", "_")
                tmp_sect_name = tmp_sect_name.replace("/", "_")
                s += (
                    "}\n"
                    f"SPLAT_BEGIN_SEG({tmp_sect_name}, 0x{start:X}, 0x{self.rom_to_ram(start):X}, {subalign_str})\n"
                )
                do_next = False

            if start % 0x10 != 0 and i != 0:
                do_next = True

            path_cname = re.sub(r"[^0-9a-zA-Z_]", "_", path)
            s += f"    {path_cname} = .;\n"

            if subdir == options.get("assets_dir"):
                path = PurePath(path)
            else:
                path = PurePath(subdir) / PurePath(path)

            # Remove leading ..s
            while path.parts[0] == "..":
                path = path.relative_to("..")

            path = path.with_suffix(".o" if replace_ext else path.suffix + ".o")

            if obj_type != "linker":
                s += f"    BUILD_DIR/{path}({obj_type});\n"
            i += 1

        s += (
            f"SPLAT_END_SEG({self.name}, 0x{self.rom_end:X})\n"
        )

        return s

    def get_ld_section_name(self):
        return f"data_{self.rom_start:X}"

    # returns list of (basedir, filename, obj_type)
    def get_ld_files(self):
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
