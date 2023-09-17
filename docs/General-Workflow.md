This describes an example of how to iteratively edit the splat segments config, when decompiling

# 1 Initially

Assuming that after you split segments you start from a code segment which subsegments include
```yaml
- [0x42100, bin]
```

# 2 Disassemble text, data, rodata

To start decompiling this subsegment, replace it with
```yaml
- [0x42100, c, energy_orb_wave]
- [0x42200, data, energy_orb_wave]
- [0x42300, rodata, energy_orb_wave]
```

This will disassemble `0x42100-0x42200` to individual `.s` files for each function found

It will also write `energy_orb_wave.data.s` and `energy_orb_wave.rodata.s` (using information gained during the disassembly of the functions)

And if the project uses asm-processor, write a .c with `GLOBAL_ASM()` to include all disassembled functions.

Figuring out the data and rodata addresses is to be done manually. Just disassembling the whole segment may help:
```yaml
- [0x42100, c, energy_orb_wave]
```
to locate data

# 3 Decompile text

This involved back and forth between `.c` and `.s` files:

- editing the `data.s`, `rodata.s` files to add/fixup symbols at the proper locations
- decompiling functions, declaring symbols (`extern`s) in the `.c`

The linker script links
- `.text` (only) from the .o built from `energy_orb_wave.c`
- `.data` (only) from the .o built from `energy_orb_wave.data.s`
- `.rodata` (only) from the .o built from `energy_orb_wave.rodata.s`

.data (respectively .rodata) is not linked from the .o built from `energy_orb_wave.c`, because the subsegments include segments with the `data` (respectively `rodata`) segment type

# 4 Decompile data

Move (decompile) data/rodata to the .c, using structs or relying on strings used in the code, or other things

Again, the .data/.rodata sections from the .o built from the .c will not be linked as long as there are any `data`/`rodata` subsegment in the code segment (and not just for `energy_orb_wave`, any other subsegment too)

To link the .data/.rodata from the .o built from the .c (instead of from the .s files), the subsegments should be changed from

```yaml
- [0x42100, c, energy_orb_wave]
- [0x42200, data, energy_orb_wave]
- [0x42300, rodata, energy_orb_wave]
```

to

```yaml
- [0x42100, c, energy_orb_wave]
- [0x42200, .data, energy_orb_wave]
- [0x42300, .rodata, energy_orb_wave]
```

If using `auto_all_section` and there is no other `data`/`.data`/`rodata`/`.rodata` in the subsegments in the code segment, the subsegments can also be changed to

```yaml
- [0x42100, c, energy_orb_wave]
- [0x42200]
```

# 5 Done!

`.text`, `.data` and `.rodata` are linked from the .o built from `energy_orb_wave.c` which now has everything to match when building

The assembly files (functions .s, data.s and rodata.s files) can be deleted

# BSS

Note: this explanation lacks .bss handling