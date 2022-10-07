import struct

from segtypes.gc.segment import GCSegment
from pathlib import Path
from util import options


# Represents the info for either a directory or a file within a GameCube disc image's file system.
class GCFSTEntry:
    def __init__(
        self,
        flags: bool,
        name_offset,
        offset,
        length
    ):
        self.flags = flags
        self.name_offset = name_offset
        self.offset = offset
        self.length = length
        
        self.name = ""
        self.parent = None
        self.children = []
        

    def populate_children_recursive(self, root_dir: "GCFSTEntry", offset, fst_bytes, string_table_bytes):
        # Root has no name, so only grab the name if we're not the root directory.
        if root_dir != self:
            self.parent = root_dir
            self.read_name(string_table_bytes)
            print(self.name)
        print(f'0x{self.length:X}')
        
        # Entry is a file, nothing more necessary right now.
        if self.flags == False:
            return
            
        for i in range(self.length - 1):
            current_offset = offset + ((i + 1) * 0x0C)
            print(f"{i}: 0x{current_offset:X}")
            
            new_entry = GCFSTEntry(
                bool(fst_bytes[current_offset + 0x0000]),
                struct.unpack('>I', fst_bytes[current_offset : current_offset + 0x0004])[0] & 0x00FFFFFF,
                struct.unpack('>I', fst_bytes[current_offset + 0x0004 : current_offset + 0x0008])[0],
                struct.unpack('>I', fst_bytes[current_offset + 0x0008 : current_offset + 0x000C])[0]
            )
            
            self.children.append(new_entry)
            new_entry.populate_children_recursive(self, current_offset, fst_bytes, string_table_bytes)

    
    # Reads the name of this FST entry from the given bytes array.
    def read_name(self, string_table_bytes):
        offset = 0
        chars = []
        
        for offset in range(len(string_table_bytes) - self.name_offset):
            cur_char = chr(string_table_bytes[self.name_offset + offset])
            if cur_char == '\0':
                break
            
            chars.append(cur_char)
            
        self.name = "".join(chars)
        
    
    # Builds this entry's full path within the filesystem from its parents' names.
    def get_full_name(self):
        path_components = []
        
        entry = self
        while (entry.parent != None):
            path_components.insert(0, entry.name)
            entry = entry.parent
            
        return Path("".join(path_components, "/"))


    # Emits this entry to the filesystem.
    def emit(self, filesystem_dir: Path, iso_bytes):
        full_path = filesystem_dir / self.get_full_name()
        
        # If this is a directory, we just need to make the directory on disk.
        if self.flags == True:
            full_path.mkdir(parents=True, exist_ok=True)
            return
            
        file_bytes = iso_bytes[self.offset : self.offset + self.length]
        with open(full_path, "wb") as f:
            f.write(file_bytes)
            
            
    def emit_recursive(self, filesystem_dir: Path, iso_bytes):
        # Don't emit if this is the root directory.
        if self.parent != None:
            self.emit()
        
        for e in self.children:
            e.emit_recursive(filesystem_dir, iso_bytes)


# Splits the ISO into its component parts - header info, apploader, DOL, FST metadata, and the individual files in the filesystem.
def split_iso(iso_bytes):
    split_sys_info(iso_bytes)
    split_content(iso_bytes)


# Splits the header info, apploader, DOL, and FST metadata from the ISO.
def split_sys_info(iso_bytes):
    sys_path = options.opts.filesystem_path / "sys"
    sys_path.mkdir(parents=True, exist_ok=True)
        
    # Split boot.info. Always at 0x0000 and 0x0440 bytes long.
    with open(sys_path / "boot.bin", "wb") as f:
        f.write(iso_bytes[0x0000:0x0440])
    
    # Split bi2.info. Always at 0x0440 and 0x2000 bytes long.
    with open(sys_path / "bi2.bin", "wb") as f:
        f.write(iso_bytes[0x0440:0x2440])
    
    # Split apploader.img. Always at 0x2440 and size is listed at 0x0400.
    apploader_size = struct.unpack('>I', iso_bytes[0x0400:0x0404])[0]
    with open(sys_path / "apploader.img", "wb") as f:
        f.write(iso_bytes[0x2440:0x2440 + apploader_size])
    
    # Split main.dol. Offset specified explicitly at 0x0420, but size must be calculated.
    dol_offset = struct.unpack('>I', iso_bytes[0x0420:0x0424])[0]
    fst_offset = struct.unpack('>I', iso_bytes[0x0424:0x0428])[0]
    
    dol_size = fst_offset - dol_offset
    with open(sys_path / "main.dol", "wb") as f:
        f.write(iso_bytes[dol_offset:dol_offset + dol_size])
    
    # Split fst.bin. Offset specified at 0x0424 and size specified at 0x402C.
    fst_size = struct.unpack('>I', iso_bytes[0x0428:0x042C])[0]
    with open(sys_path / "fst.bin", "wb") as f:
        f.write(iso_bytes[fst_offset:fst_offset + fst_size])


# Splits the ISO's filesystem into individual files.
def split_content(iso_bytes):
    fst_path = options.opts.filesystem_path / "sys" / "fst.bin"
    assert fst_path.is_file()
    
    fst_bytes = fst_path.read_bytes()
    fst_root_entry = populate_filesystem(fst_bytes)
    
    fst_root_entry.emit_recursive(options.opts.filesystem_path / "files", iso_bytes)


# Loads the FST data needed to split the filesystem.
def populate_filesystem(fst_bytes):
    root_dir = GCFSTEntry(
        bool(fst_bytes[0x0000]),
        struct.unpack('>I', bytes([0, *fst_bytes[0x0001:0x0004]]))[0],
        struct.unpack('>I', fst_bytes[0x0004:0x0008])[0],
        struct.unpack('>I', fst_bytes[0x0008:0x000C])[0]
    )
    
    string_table_bytes = fst_bytes[root_dir.length * 0x0C : len(fst_bytes)]
    
    root_dir.populate_children_recursive(root_dir, 0, fst_bytes, string_table_bytes)
    return root_dir

