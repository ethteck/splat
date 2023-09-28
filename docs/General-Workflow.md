This describes an example of how to iteratively edit the splat segments config, when decompiling

# 1 Initial configuration

After successfully following the [Quickstart](https://github.com/ethteck/splat/wiki/Quickstart), you should have an initial configuration like the one below:

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

## 1.1 Match `rodata` to `asm` sections

It's good practice to start pairing `rodata` sections with `asm` sections _before_ changing the `asm` sections into `c` files. This is because rodata may need to be explicitly included within the `c` file (via `INCLUDE_RODATA` macro).

`splat` provides hints about which `rodata` segments are referenced in which `asm` segments based on references to these symbols within the disassembled functions.

These look like:

```
Rodata segment '3EE10' may belong to the text segment 'energy_orb_wave'
    Based on the usage from the function func_0xXXXXXXXX to the symbol D_800AEA10
```

To pair these two sections, simply add the _name_ of the suggested text (`asm`) segment to the `rodata` segment:

```yaml
- [0x3EE10, rodata, "energy_orb_wave"]
```

### Troubleshooting

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

This hint tells you that `splat` believes one text (`asm`) segment references two `rodata` sections. This usually means that either the `rodata` should not be split at `0x3E930`, or that there is a missing split in the `asm` at `0x16100`, as a text segment can only have one `rodata` segment.

If we assume that the split is incorrect, we can simply remove the extraneous split:

```yaml
# ...
- [0x3E900, rodata, "16100"]
# - [0x3E930, rodata]
# ...
```

**NOTE:** Splat uses heuristics to determine `rodata` and `asm` splits and is not perfect - false positives are possible and, if in doubt, double-check the assembly yourself before changing the splits.


### Multiple `asm` referring to the same `rodata`

Sometimes the opposite is true, and `splat` believes two `asm` segments belong to a single `rodata` segment. In this case, you can split the `asm` segment to make sure two files are not paired with the same `rodata`. Note that this too can be a false positive.


# 2 Disassemble text, data, rodata

Let's say you want to start decompiling the subsegment at `0x25C20` (`energy_orb_wave`). Start by replacing the `asm` type with `c`, and then re-run splat.

```yaml
- [0x25C20, c, energy_orb_wave]
# ...
- [0x3EE10, rodata, energy_orb_wave]
```

This will disassemble `0x25C20` to individual `.s` files for each function found. By default, the output will be located in `asm/nonmatchings/energy_orb_wave/function_name.s`. This path can be changed via the `asm_path` setting.

Splat will also generate `asm/energy_orb_wave.data.s` (if it is paired with a `data` segment), and `energy_orb_wave.rodata.s` (using information gained during the disassembly of the functions).

Finally, splat will generate a C file, by default, at `src/energy_orb_wave.c` (`src_path` can be configured) containing `GLOBAL_ASM()` and `GLOBAL_RODATA()` macros to include all disassembled functions.

These macros must be defined in an included header, which splat currently does not produce. For an example, see the [include.h](https://github.com/AngheloAlf/drmario64/blob/master/include/include_asm.h) for Dr. Mario.

Figuring out the data and rodata addresses must be done manually. Simply disassembling the whole segment may help:

```yaml
- [0x42100, c, energy_orb_wave]
```

# 3 Decompile text

This involved back and forth between `.c` and `.s` files:

- editing the `data.s`, `rodata.s` files to add/fixup symbols at the proper locations
- decompiling functions, declaring symbols (`extern`s) in the `.c`

The linker script links
- `.text` (only) from the .o built from `energy_orb_wave.c`
- `.data` (only) from the .o built from `energy_orb_wave.data.s`
- `.rodata` (only) from the .o built from `energy_orb_wave.rodata.s`

# 4 Decompile data

TODO: `mention migrate_rodata_to_functions: yes` functionality.

Move (decompile) data to the .c file, using structs or relying on strings used in the code.

To link the .data/.rodata from the .o built from the .c (instead of from the .s files), the subsegments should be changed from:

```yaml
- [0x42100, c, energy_orb_wave]
- [0x42200, data, energy_orb_wave]     #  extract data at this ROM address as energy_orb_wave.data.s
- [0x42300, rodata, energy_orb_wave]   # extract rodata at this ROM address as energy_orb_wave.rodata.s
```

to:

```yaml
- [0x42100, c, energy_orb_wave]
- [0x42200, .data, energy_orb_wave]    # take the .data section from the compiled c file named energy_orb_wave
- [0x42300, .rodata, energy_orb_wave]  # take the .rodata section from the compiled c file named energy_orb_wave
```

If using `auto_all_section` and there are no other `data`/`.data`/`rodata`/`.rodata` in the subsegments in the code segment, the subsegments can also be changed to

```yaml
- [0x42100, c, energy_orb_wave]
- [0x42200]
```

# 5 Decompile bss

`bss` works in a similar way to data/rodata however, usually, `bss` is discarded from the final binary which makes it somewhat tricker to migrate.

The `bss` segment will create assembly files that are full of `space`. The `.bss` segment will link the `.bss` section of the referenced `c` file.

# 6 Done!

`.text`, `.data`, `.rodata` and `.bss` are linked from the .o built from `energy_orb_wave.c` which now has everything to match when building

The assembly files (functions .s, data.s and rodata.s files) can be deleted
