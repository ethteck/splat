import os
from pathlib import Path


def parse_segment_start(segment):
    return segment[0] if "start" not in segment else segment["start"]

def parse_segment_type(segment):
    if type(segment) is dict:
        return segment["type"]
    else:
        return segment[1]


def parse_segment_name(segment, segment_class):
    if type(segment) is dict:
        return segment["name"]
    else:
        if len(segment) >= 3 and type(segment[2]) is str:
            return segment[2]
        else:
            return segment_class.get_default_name(parse_segment_start(segment))


def parse_segment_vram(segment):
    if type(segment) is dict:
        if "vram" in segment:
            return segment["vram"]
        else:
            return 0
    else:
        if len(segment) >=3 and type(segment[-1]) is int:
            return segment[-1]
        else:
            return 0


class N64Segment:
    def __init__(self, segment, next_segment, options):
        self.rom_start = parse_segment_start(segment)
        self.rom_end = parse_segment_start(next_segment)
        self.type = parse_segment_type(segment)
        self.name = parse_segment_name(segment, self.__class__)
        self.vram_addr = parse_segment_vram(segment)
        self.options = options


    def get_length(self):
        return self.rom_end - self.rom_start

    def create_split_dir(self, base_path, subdir):
        out_dir = Path(base_path, subdir)
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir

    def create_parent_dir(self, base_path, filename):
        out_dir = Path(base_path, filename).parent
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir

    def split(self, rom_bytes, base_path):
        pass

    def get_ld_section(self):
        pass

    @staticmethod
    def get_default_name(addr):
        return "{:X}".format(addr)
