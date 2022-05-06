#!/usr/bin/env python3
#
#   Test file for pygfxd, test.bin should be valid F3DEX2 gbi commands
#

import sys
from pygfxd import *

if __name__ == '__main__':

    def macro_fn():
        gfxd_puts("    ")
        gfxd_macro_dflt()
        gfxd_puts(",\n")
        return 0

    all_vertices = set()

    def vtx_callback(seg, count):
        gfxd_printf(f"D_{seg:08X}")
        all_vertices.add(seg)
        return 1

    outb = bytes([0] * 4096)

    input_file = open("test.bin","rb")
    gfxd_input_fd(input_file)

    gfxd_output_fd(sys.stdout)
    # outbuf = gfxd_output_buffer(outb, len(outb))

    gfxd_macro_fn(macro_fn)

    gfxd_target(gfxd_f3dex2)
    gfxd_endian(GfxdEndian.big, 4)

    gfxd_vtx_callback(vtx_callback)

    gfxd_puts("Gfx %s[] = {\n" % "ok")

    gfxd_execute()

    gfxd_puts("};\n")

    # print(gfxd_buffer_to_string(outbuf))

    print("Found Vtx segments:")
    print([f'D_{seg:08X}' for seg in all_vertices])
