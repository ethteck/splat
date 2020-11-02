import os
from pathlib import Path, PurePath
import re


def parse_segment_start(segment):
    return segment[0] if "start" not in segment else segment["start"]


def parse_segment_type(segment):
    if type(segment) is dict:
        return segment["type"]
    else:
        return segment[1]


def parse_segment_name(segment, segment_class):
    if type(segment) is dict and "name" in segment:
        return segment["name"]
    elif type(segment) is list and len(segment) >= 3 and type(segment[2]) is str:
        return segment[2]
    else:
        return segment_class.get_default_name(parse_segment_start(segment))


def parse_segment_vram(segment):
    if type(segment) is dict:
        return segment.get("vram", 0)
    else:
        if len(segment) >= 3 and type(segment[-1]) is int:
            return segment[-1]
        else:
            return 0


class N64Segment:
    require_unique_name = True

    def __init__(self, segment, next_segment, options):
        self.rom_start = parse_segment_start(segment)
        self.rom_end = parse_segment_start(next_segment)
        self.type = parse_segment_type(segment)
        self.name = parse_segment_name(segment, self.__class__)
        self.vram_addr = parse_segment_vram(segment)
        self.ld_name_override = segment.get(
            "ld_name", None) if type(segment) is dict else None
        self.options = options

    def check(self):
        if self.rom_start > self.rom_end:
            print(f"WARNING: {self.type} {self.name} is out-of-order")
        elif self.max_length():
            expected_len = int(self.max_length())
            actual_len = self.rom_end - self.rom_start
            if actual_len > expected_len:
                print(f"WARNING: {self.type} {self.name} should end at 0x{self.rom_start + expected_len:X}, but it ends at 0x{self.rom_end:X} (hint: add a 'bin' segment after {self.name})")

    @property
    def rom_length(self):
        return self.rom_end - self.rom_start

    def create_split_dir(self, base_path, subdir):
        out_dir = Path(base_path, subdir)
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir

    def create_parent_dir(self, base_path, filename):
        out_dir = Path(base_path, filename).parent
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir

    def should_run(self):
        return self.type in self.options["modes"] or "all" in self.options["modes"]

    def split(self, rom_bytes, base_path):
        pass

    def postsplit(self, segments):
        pass

    def get_ld_section(self):
        replace_ext = self.options.get("ld_o_replace_extension", True)
        sect_name = self.ld_name_override if self.ld_name_override else self.get_ld_section_name()
        vram_or_rom = self.rom_start if self.vram_addr == 0 else self.vram_addr

        s = (
            f"/* 0x{self.vram_addr:08X} {self.rom_start:X}-{self.rom_end:X} (len {self.rom_length:X}) */\n"
            "#ifdef SHIFT\n"
            f"{sect_name}_ROM_START = __romPos;\n"
            "#else\n"
            f"{sect_name}_ROM_START = 0x{self.rom_start:X};\n"
            "#endif\n"
            f"{sect_name}_VRAM = ADDR(.{sect_name});\n"
            f".{sect_name} 0x{vram_or_rom:X} : AT({sect_name}_ROM_START) {{\n"
        )

        for subdir, path, obj_type in self.get_ld_files():
            path = PurePath(subdir) / PurePath(path)
            path = path.with_suffix(
                ".o" if replace_ext else path.suffix + ".o")

            s += f"    BUILD_DIR/{path}({obj_type});\n"

        s += (
            "}\n"
            "#ifdef SHIFT\n"
            f"{sect_name}_ROM_END = __romPos + SIZEOF(.{sect_name});\n"
            f"__romPos += SIZEOF(.{sect_name});\n"
            "#else\n"
            f"{sect_name}_ROM_END = 0x{self.rom_end:X};\n"
            f"__romPos += 0x{self.rom_length:X};\n"
            "#endif\n"
        )

        return s

    def get_ld_section_name(self):
        return f"data_{self.rom_start:X}"

    # returns list of (basedir, filename, obj_type)

    def get_ld_files(self):
        return []

    def log(self, msg):
        if self.options.get("verbose", False):
            print(msg)

    def max_length(self):
        return None

    def is_name_default(self):
        return self.name == self.get_default_name(self.rom_end)

    @staticmethod
    def get_default_name(addr):
        return "{:X}".format(addr)
