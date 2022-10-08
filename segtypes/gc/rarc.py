import struct

from segtypes.gc.segment import GCSegment
from pathlib import Path
from util import options

from enum import IntEnum


# Represents the RARC archive format used by first-party Nintendo games.
class GcSegRarc(GCSegment):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        
    def split(file_bytes):
        archive = GCRARCArchive(file_bytes)
        archive.build_hierarchy(file_bytes)
        
        archive.emit(file_bytes)
    

class GCRARCArchive:
    def __init__(
        self,
        file_bytes
    ):
        self.magic = struct.unpack('>I', file_bytes[0x0000:0x0004])[0]
        self.file_size = struct.unpack('>I', file_bytes[0x0004:0x0008])[0]
        self.data_header_offset = struct.unpack('>I', file_bytes[0x0008:0x000C])[0]
        self.file_data_offset = struct.unpack('>I', file_bytes[0x000C:0x0010])[0] + 0x0020
        self.total_file_data_size = struct.unpack('>I', file_bytes[0x0010:0x0014])[0]
        
        self.mram_preload_size = struct.unpack('>I', file_bytes[0x0014:0x0018])[0]
        self.aram_preload_size = struct.unpack('>I', file_bytes[0x0018:0x001C])[0]
        
        self.data_header = GCRARCDataHeader(self.data_header_offset, file_bytes)
        self.nodes = []
        
        
    def build_hierarchy(self, file_bytes):
        string_table_offset = self.data_header.string_table_offset
        string_table_size = self.data_header.string_table_size
        
        string_table_bytes = file_bytes[string_table_offset : string_table_offset + string_table_size]
        
        # Load the file entries into their corresponding nodes.
        for i in range(self.data_header.node_count):
            offset = self.data_header.node_offset + i * 0x10
            
            new_node = GCRARCNode(offset, file_bytes, string_table_bytes)
            new_node.get_entries(self.data_header.file_entry_offset, file_bytes, string_table_bytes)
            
            self.nodes.append(new_node)
            
        # Now, organize the nodes into a hierarchy.
        for n in self.nodes:
            for e in n.entries:
               # We're only looking for directory nodes, so ignore files.
               if e.flags & int(GCRARCFlags.IS_FILE) != 0x00:
                   continue
               
               if e.name == "." or e.name == "..":
                   continue
               
               # This is the node that the current entry corresponds to.
               dir_node = self.nodes[e.data_offset]
               
               # Set up hierarchy relationship.
               dir_node.parent = n
               n.children.append(dir_node)
        
    
    def emit(self, file_bytes):
        self.nodes[0].emit_to_filesystem_recursive(self.file_data_offset, file_bytes)
        

class GCRARCDataHeader:
    def __init__(
        self,
        offset,
        file_bytes
    ):
        self.node_count = struct.unpack('>I', file_bytes[offset + 0x0000 : offset + 0x0004])[0]
        self.node_offset = struct.unpack('>I', file_bytes[offset + 0x0004 : offset + 0x0008])[0] + 0x0020
        
        self.file_entry_count = struct.unpack('>I', file_bytes[offset + 0x0008 : offset + 0x000C])[0]
        self.file_entry_offset = struct.unpack('>I', file_bytes[offset + 0x000C : offset + 0x0010])[0] + 0x0020
        
        self.string_table_size = struct.unpack('>I', file_bytes[offset + 0x0010 : offset + 0x0014])[0]
        self.string_table_offset = struct.unpack('>I', file_bytes[offset + 0x0014 : offset + 0x0018])[0] + 0x0020
        
        self.next_free_file_id = struct.unpack('>H', file_bytes[offset + 0x0018 : offset + 0x001A])[0]
        self.sync_file_ids_to_indices = bool(file_bytes[offset + 0x001A])
        
        
class GCRARCNode:
    def __init__(
        self,
        offset,
        file_bytes,
        string_table_bytes
    ):
        self.resource_type = file_bytes[offset + 0x0000 : offset + 0x0004].decode("utf-8")
        self.name_offset = struct.unpack('>I', file_bytes[offset + 0x0004 : offset + 0x0008])[0]
        self.name_hash = struct.unpack('>H', file_bytes[offset + 0x0008 : offset + 0x000A])[0]
        self.file_entry_count = struct.unpack('>H', file_bytes[offset + 0x000A : offset + 0x000C])[0]
        self.first_file_entry_index = struct.unpack('>I', file_bytes[offset + 0x000C : offset + 0x0010])[0]
        
        self.name = read_name(self.name_offset, string_table_bytes)
        self.entries = []
        
        self.parent = None
        self.children = []
        
        
    def get_entries(self, file_entry_offset, file_bytes, string_table_bytes):
        for i in range(self.file_entry_count):
            entry_offset = file_entry_offset + (self.first_file_entry_index + i) * 0x14
            
            new_entry = GCRARCFileEntry(entry_offset, file_bytes, string_table_bytes)
            new_entry.parent_node = self
            
            self.entries.append(new_entry)
            

    def emit_to_filesystem_recursive(self, file_data_offset, file_bytes):
      #test_path = Path("E:/Github/splat/arctest") / self.get_full_directory_path()
      test_path.mkdir(parents=True, exist_ok=True)
      
      for n in self.children:
         n.emit_to_filesystem_recursive(file_data_offset, file_bytes)
         
      for e in self.entries:
         e.emit_to_filesystem(file_data_offset, file_bytes)

    
    def print_recursive(self, level):
        print(("  " * level) + self.name)
        
        for n in self.children:
            n.print_recursive(level + 1)
            
            
    def get_full_directory_path(self):
        path_components = []
        
        node = self
        while (True):
            path_components.insert(0, node.name)
            node = node.parent
            
            if node == None:
                break
            
        return Path("/".join(path_components))


class GCRARCFileEntry:
    def __init__(
        self,
        offset,
        file_bytes,
        string_table_bytes
    ):
        self.file_id = struct.unpack('>H', file_bytes[offset + 0x0000 : offset + 0x0002])[0]
        self.name_hash = struct.unpack('>H', file_bytes[offset + 0x0002 : offset + 0x0004])[0]
        self.flags = file_bytes[offset + 0x0004]
        self.name_offset = struct.unpack('>I', file_bytes[offset + 0x0004 : offset + 0x0008])[0] & 0x00FFFFFF
        self.data_offset = struct.unpack('>I', file_bytes[offset + 0x0008 : offset + 0x000C])[0]
        self.data_size = struct.unpack('>I', file_bytes[offset + 0x000C : offset + 0x0010])[0]
        
        self.name = read_name(self.name_offset, string_table_bytes)
        self.parent_node = None
        
        
    def emit_to_filesystem(self, file_data_offset, file_bytes):
        if self.flags & int(GCRARCFlags.IS_DIR) != 0x00:
            return
        
        #test_path = Path("E:/Github/splat/arctest") / self.get_full_file_path()
        
        file_data = file_bytes[file_data_offset + self.data_offset : file_data_offset + self.data_offset + self.data_size]
        with open(test_path, "wb") as f:
            f.write(file_data)
        
        
    def emit_config(self):
        pass
        
        
    def get_full_file_path(self):
        path_components = [ self.name ]
        
        node = self.parent_node
        while (True):
            path_components.insert(0, node.name)
            node = node.parent
            
            if node == None:
                break
            
        return Path("/".join(path_components))
        


class GCRARCFlags(IntEnum):
    IS_FILE = 0x01
    IS_DIR = 0x02
    IS_COMPRESSED = 0x04
    PRELOAD_TO_MRAM = 0x10
    PRELOAD_TO_ARAM = 0x20
    LOAD_FROM_DVD = 0x40
    IS_YAZ0_COMPRESSED = 0x80


def read_name(name_offset, string_table_bytes):
    offset = 0
    bytes = []
    
    for offset in range(len(string_table_bytes) - name_offset):
        cur_byte = string_table_bytes[name_offset + offset]
        if cur_byte == 0x00:
            break
        
        bytes.append(cur_byte)
    
    return bytearray(bytes).decode("shift-jis")

