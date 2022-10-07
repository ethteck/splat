import struct

from segtypes.gc.segment import GCSegment
from pathlib import Path
from util import options


def split_iso(iso_bytes):
    split_sys_info(iso_bytes)


def split_sys_info(iso_bytes):
    sys_path = options.opts.filesystem_path / "sys"
    sys_path.mkdir(parents=True, exist_ok=True)
        
    # Split boot.info. Always at 0x0000 and 0x0440 bytes long.
    with open(sys_path / "boot.bin", "wb") as f:
        f.write(iso_bytes[0x0000:0x0440])
    
    # Split bi2.info. Always at 0x0440 and 0x2000 bytes long.
    with open(sys_path / "bi2.bin", "wb") as f:
        f.write(iso_bytes[0x0440:0x2440])
    
    # Split apploader.img. Always at 0x2440, and size is listed at 0x0400.
    apploader_size = struct.unpack('>I', iso_bytes[0x0400:0x0404])
    with open(sys_path / "apploader.img", "wb") as f:
        f.write(iso_bytes[0x2440:0x2440 + apploader_size])
    
    # Split main.dol. Offset specified explicitly at 0x0420, but size must be calculated.
    dol_offset = struct.unpack('>I', iso_bytes[0x0420:0x0424])
    fst_offset = struct.unpack('>I', iso_bytes[0x0424:0x0428])
    
    dol_size = fst_offset - dol_offset
    with open(sys_path / "main.dol", "wb") as f:
        f.write(iso_bytes[dol_offset:dol_offset + dol_size])
    
    # Split fst.bin. Offset specified at 0x0424 and size specified at 0x402C.
    fst_size = struct.unpack('>I', iso_bytes[0x0428:0x042C])
    with open(sys_path / "fst.bin", "wb") as f:
        f.write(iso_bytes[fst_offset:fst_offset + fst_size])
