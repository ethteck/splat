import struct

from segtypes.gc.segment import GCSegment
from pathlib import Path
from util import options


class GcSegBi2(GCSegment):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def split(self, bi2_bytes):
        lines = []

        # Gathering variables
        debug_monitor_size = struct.unpack(">I", bi2_bytes[0x00:0x04])
        simulated_memory_size = struct.unpack(">I", bi2_bytes[0x04:0x08])

        argument_offset = struct.unpack(">I", bi2_bytes[0x08:0x0C])

        debug_flag = struct.unpack(">I", bi2_bytes[0x0C:0x10])

        track_offset = struct.unpack(">I", bi2_bytes[0x10:0x14])
        track_size = struct.unpack(">I", bi2_bytes[0x14:0x18])

        country_code_bi2 = struct.unpack(">I", bi2_bytes[0x18:0x1C])

        unk_int = struct.unpack(">I", bi2_bytes[0x1C:0x20])
        unk_int_2 = struct.unpack(">I", bi2_bytes[0x20:0x24])

        # Outputting .s file
        lines.append(f"# GameCube disc image bi2 data, located at 0x440 in the disc.\n")
        lines.append(f"# Generated by splat.\n\n")

        lines.append(f".section .data\n\n")

        lines.append(f"debug_monitor_size: .long 0x{debug_monitor_size[0]:08X}\n")
        lines.append(
            f"simulated_memory_size: .long 0x{simulated_memory_size[0]:08X}\n\n"
        )

        lines.append(f"argument_offset: .long 0x{argument_offset[0]:08X}\n\n")

        lines.append(f"debug_flag: .long 0x{debug_flag[0]:08X}\n\n")

        lines.append(f"track_offset: .long 0x{track_offset[0]:08X}\n")
        lines.append(f"track_size: .long 0x{track_size[0]:08X}\n\n")

        lines.append(f"country_code_bi2: .long 0x{country_code_bi2[0]:08X}\n\n")

        lines.append(f"ukn_int_bi2: .long 0x{unk_int[0]:08X}\n")
        lines.append(f"ukn_int_bi2_2: .long 0x{unk_int_2[0]:08X}\n\n")

        lines.append(f".fill 0x00001FDC\n\n")

        out_path = self.out_path()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with open(out_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        return

    def should_split(self) -> bool:
        return True

    def out_path(self) -> Path:
        return options.opts.asm_path / "sys/bi2.s"
