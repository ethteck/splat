This describes an example of how to iteratively edit the splat segments config, when decompiling

(If you have no idea what this is about, please head over to the [Quickstart](https://github.com/ethteck/splat/wiki/Quickstart) to get an initial configuration for your ROM.)

# 1 Initially

Assuming that after succesfully following the [Quickstart](https://github.com/ethteck/splat/wiki/Quickstart), you get an initial configuration like the one below:
```yaml
- name: main
  type: code
  start: 0x1060
  vram: 0x80070C60
  follows_vram: entry
  bss_size: 0x3AE70
  subsegments:
      - [0x1060, asm]
      # ... a lot of additional `asm` sections
      # This section is found out to contain __osViSwapContext
      - [0x25C20, asm, "energy_orb_wave"]
      # ... a lot of addtiional `asm` sections
      - [0x2E450, data]

      - [0x3E330, rodata]
      # ... a lot of addtional `rodata` sections
      - { start: 0x3F1B0, type: bss, vram: 0x800E9C20 }

- [0x3F1B0, bin]
```

## 1.1 Match rodata to asm sections

In order to simplify decompilation, it's good practice to start pairing `rodata` sections with `asm` sections.

`splat` gives hints about what `rodata` is used in which `asm` segment.

The hint look like:
```
Rodata segment '3EE10' may belong to the text segment 'energy_orb_wave'
    Based on the usage from the function func_0xXXXXXXXX to the symbol D_800AEA10
```

To pair these two sections, simply add the name of the suggested text (`asm`) segment to the `rodata` segment:

```yaml
- [0x3EE10, rodata, "energy_orb_wave"]
```

### Useful knowledge about splitting

#### Multiple `rodata`
Using the following configuration:
```yaml
# ...
- [0x3E900, rodata]
- [0x3E930, rodata]
# ...
```

`splat` outputs a hint that doesn't immediately seem to make sense:

```
Rodata segment '3E900' may belong to the text segment '16100'
    Based on the usage from the function func_80085DA0 to the symbol jtbl_800AE500

Rodata segment '3E930' may belong to the text segment '16100'
    Based on the usage from the function func_800862C0 to the symbol jtbl_800AE530
```

This hint tells you that `splat` thinks one text (`asm`) segment seems to have two `rodata` sections. This usually means that there should not be a split at `0x3E930`, since one text segment should only have one `rodata` segment. 

To fix this, simply remove the second split from the configuration:
```yaml
# ...
- [0x3E900, rodata, "16100"]
# begone!
# ...

```

### Multiple `asm` referring to the same `rodata`

**TODO**
Sometimes the opposite from above is true, and you should try to split the `asm` segment to make sure two files are not paired with the same `rodata`.

# 2 Disassemble text, data, rodata

Let's say you want to start decompiling the subsegment at `0x25C20` (`energy_orb_wave`). Start by replacing the `asm` type with `c`.

```yaml
- [0x25C20, c, energy_orb_wave]
# ... 
- [0x3EE10, rodata, energy_orb_wave]
```

This will disassemble `0x25C20` to individual `.s` files for each function found. The output will be located in `asm/energy_orb_wave` (depending on the `asm_path` setting, found in the configuration).

It will also generate `asm/energy_orb_wave.data.s` (if it is paired with a `data` segment), and `energy_orb_wave.rodata.s` (using information gained during the disassembly of the functions).

Finally, it will generate a C file at `src/energy_orb_wave` (depending on the `src_path` setting, found in the configuration) containing `GLOBAL_ASM()` and `GLOBAL_RODATA()` macro's to include all disassembled functions. (This macro is ultimately handled by the build system, which is out of the scope of `splat`)

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