import os
from pathlib import Path

class N64Segment:
    def __init__(self, rom_start, rom_end, segtype, name, ram_addr=None):
        self.rom_start = rom_start
        self.rom_end = rom_end
        self.type = segtype
        self.name = name
        self.ram_addr = ram_addr
    
    def get_length(self):
        return self.rom_end - self.rom_start

    def create_split_dir(self, base_path, subdir):
        out_dir = Path(base_path, subdir)
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir
    
    def seg_split(self, rom_bytes, base_path):
        pass

    def get_ld_section(self):
        pass
