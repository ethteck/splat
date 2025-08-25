# Segments

The configuration file for **splat** consists of a number of well-defined segments.

Most segments can be defined as a either a dictionary or a list, however the list syntax is only suitable for simple cases as it does not allow for specifying many of the options a segment type has to offer.

Splat segments' behavior generally falls under two categories: extraction and linking. Some segments will only do extraction, some will only do linking, some both, and some neither. Generally, segments will describe both extraction and linking behavior. Additionally, a segment type whose name starts with a dot (.) will only focus on linking.

## `asm`

**Description:**

Segments designated Assembly, `asm`, will be disassembled via [spimdisasm](https://github.com/Decompollaborate/spimdisasm) and enriched with Symbols based on the contents of the `symbol_addrs` configuration.

**Example:**

```yaml
# as list
- [0xABC, asm, filepath1]
- [0xABC, asm, dir1/filepath2]  # this will create filepath2.s inside a directory named dir1

# as dictionary
- name: filepath
  type: asm
  start: 0xABC
```

### `hasm`

**Description:**

Hand-written Assembly, `hasm`, similar to `asm` except it will not overwrite any existing files. Useful when assembly has been manually edited.

**Example:**

```yaml
# as list
- [0xABC, hasm, filepath]

# as dictionary
- name: filepath
  type: hasm
  start: 0xABC
```

### `asmtu`

**Description:**

Allows disassembling every section of an object that share the same name into the same assembly file.
This is a better parallel to how an object is compiled from a [TU](https://en.wikipedia.org/wiki/Translation_unit_(programming)) than disassembling each section to individual assembly files.

This is specially useful when dealing with symbols that may not be globally visible (locally binded symbols), because those symbols should be visible to the whole TU but disassembling each section individually disallows this visibility.

This segment requires that every other segment that shares the same name must have their segment type be prefixed with a dot.

```yaml
    subsegments:
      # ...
      - [0x000100, asmtu, code/allai]
      # ...
      - [0x324680, .data, code/allai] # Note `.data` instead of `data`
      # ...
      - [0x350100, .rodata, code/allai]
      # ...
      - { type: .bss, vram: 0x004B10C8, name: code/allai }
      # ...
```

## `bin`

**Description:**

The `bin`(ary) segment type is for raw data, or data where the type is yet to be determined, data will be written out as raw `.bin` files.

**Example:**

```yaml
# as list
- [0xABC, bin, filepath]

# as dictionary
- name: filepath
  type: bin
  start: 0xABC
```

## `code`

**Description:**

The 'code' segment type, `code` is a group that can have many `subsegments`. Useful to group sections of code together (e.g. all files part of the same overlay).

**Example:**

```yaml
# must be a dictionary
- name:  main
  type:  code
  start: 0x00001000
  vram:  0x80125900
  subsegments:
    - [0x1000, asm, entrypoint]
    - [0x1050, c, main]
```

## `c`

**Description:**

The C code segments have two behaviors:

- If the target `.c` file does not exist, a new file will be generated with macros to include the original assembly (macros differ for IDO vs GCC compiler).
- Otherwise the target `.c` file is scanned to determine what assembly needs to be extracted from the ROM.

Assembly that is extracted due to a `c` segment will be written to a `nonmatchings` folder, with one function per file.

**Example:**

```yaml
# as list
- [0xABC, c, filepath]

# as dictionary
- name: filepath
  type: c
  start: 0xABC
```

## `header`

**Description:**

This is platform specific; parses the data and interprets as a header for e.g. N64 or PS1 elf.

**Example:**

```yaml
# as list
- [0xABC, header, filepath]

# as dictionary
- name: filepath
  type: header
  start: 0xABC
```

## `cpp`

The `cpp` segment behaves the same as the `c` segment but uses the .cpp file extension (for C++ source files).

## `data`

**Description:**

Data located in the ROM. Extracted as assembly; integer, float and string types will be attempted to be inferred by the disassembler.

**Example:**

```yaml
# as list
- [0xABC, data, filepath]

# as dictionary
- name: filepath
  type: data
  start: 0xABC
```

This will created `filepath.data.s` within the `asm` folder.

## `.data`

**Description:**

Data located in the ROM that is linked from a C file. Use the `.data` segment to tell the linker to pull the `.data` section from the compiled object of corresponding `c` segment.

**Example:**

```yaml
# as list
- [0xABC, .data, filepath]

# as dictionary
- name: filepath
  type: .data
  start: 0xABC
```

**NOTE:** `splat` will not generate any `.data.s` files for these `.` (dot) sections.

## `sdata` / `.sdata`

The `sdata` and `.sdata` segments behaves the same as the `data` and `.data` segments, but supports "small data" linker sections.

## `rodata`

**Description:**

Read-only data located in the ROM, e.g. floats, strings and jump tables. Extracted as assembly; integer, float and string types will be attempted to be inferred by the disassembler.

**Example:**

```yaml
# as list
- [0xABC, rodata, filepath]

# as dictionary
- name: filepath
  type: rodata
  start: 0xABC
```

This will created `filepath.rodata.s` within the `asm` folder.

## `.rodata`

**Description:**

Read-only data located in the ROM, linked to a C file. Use the `.rodata` segment to tell the linker to pull the `.rodata` section from the compiled object of corresponding `c` segment.

**Example:**

```yaml
# as list
- [0xABC, .rodata, filepath]

# as dictionary
- name: filepath
  type: .rodata
  start: 0xABC
```

## `.rdata`

The `.rdata` segment behaves the same as the `.rodata` segment but supports rodata linker sections that happened to be named `.rdata` rather than `.rodata`.

**NOTE:** `splat` will not generate any `.rodata.s` files for these `.` (dot) sections.

## `bss`

**Description:**

`bss` is where variables are placed that have been declared but are not given an initial value. These sections are usually discarded from the final binary (although PSX binaries seem to include them!).

Note that the `bss_size` option needs to be set at segment level for `bss` segments to work correctly.

**Example:**

```yaml
- { start: 0x7D1AD0, type: bss, name: filepath, vram: 0x803C0420 }
```

## `.bss`

**Description:**

Links the `.bss` section of the associated `c` file.

**Example:**

```yaml
- { start: 0x7D1AD0, type: .bss, name: filepath, vram: 0x803C0420 }
```

## `sbss` / `.sbss`

The `sbss` and `.sbss` segments behaves the same as the `bss` and `.bss` segments, but supports "small bss" linker sections.

## `lib`

The `lib` segment can be used to link to a section of an object in an existing library archive. It is purely used to configure the output linker script and does not do any extraction.

It looks for libraries in the [`lib_path`](https://github.com/ethteck/splat/wiki/Configuration#lib_path) global option.

**Example:**

```yaml
# link to .text of b_obj in a_lib
- [auto, lib, a_lib, b_obj]
```

```yaml
# link to .data of b_obj in a_lib
- [auto, lib, a_lib, b_obj, .data]
```

```yaml
# link to .text of b_obj in a_lib (dict representation)
- { type: lib, name: a_lib, object: b_obj, section: .text }
```


## `pad`

`pad` is a segment that represents a rom region that's filled with zeroes and decomping it doesn't have much value.

This segment does not generate an assembly (`.s`) or binary (`.bin`) file, it simply increments the position of the linker script, avoding to build zero-filled files.

While this kind of segment can be represented by other segment types ([`asm`](#asm), [`data`](#data), etc), it is better practice to use this segment instead to better reflect the contents of the file.

**Example:**

```yaml
- [0x00B250, pad, nops_00B250]
```

**Warning:** `pad` cannot be the last segment in your yaml, as the way it is implemented requires a linked object to follow it.
If the rom contains padding at the end, we recommend treating only the non-padded portion of the rom with splat and padding the rest during the build process.

## incbins

incbin segments correpond to a family of segments used for extracting binary blobs.

Their main advantage over the [`bin`](#bin) segment is the incbins allows to specify a specific section type instead of defaulting to simply `.data`. This is done by generating an assembly file that uses the `.incbin` asm directive to include the binary blob.

Generating assembly files enables better customization of these binaries, like allowing different sections or to define a symbol for the binary blob.

If a known symbol (via a symbol_addrs file) matches the vram of a incbin segment then it will be emitted accordingly at the top. If the symbol contains a [`name_end`](Adding-Symbols.md#name_end) property then it will be emitted after the `.incbin` (useful for Nintendo64's RSP ucodes).

Curretly there are 3 types of incbins, `textbin`, `databin` and `rodatabin`, which are intended for binary blobs of `.text`, `.data` and `.rodata` sections.

If a `textbin` section has a corresponding `databin` and/or `rodatabin` section with the same name then those will be included in the same generated assembly file.

By default the generated assembly file will be written relative to the configured [`data_path`](docs/Configuration.md#data_path). The per segment `use_src_path` option allows to tell splat that a given incbin should be relative to the [`src_path`](docs/Configuration.md#src_path) instead. This behavior can be useful to allow committing those assembly files to the repo since splat will not override them if they already exist, and still extract the binary blobs.

```yaml
- { start: 0x06C4B0, type: textbin, use_src_path: True, name: rsp/rspboot }
- [0x06C580, textbin, rsp/aspMain]

# ...

- [0x093D60, databin, rsp/aspMain]
```

## `gcc_except_table`

Used by certain compilers (like GCC) to store the Exception Handler Table (`ehtable`), used for implementing C++ exceptions.

This table contains references to addresses within functions, which normally the disassembler would automatically reject as being valid addresses. This special section bypasses that restriction by generating special labels within the functions in question. The macro used for these labels can be changed with the [`asm_ehtable_label_macro`](Configuration.md#asm_ehtable_label_macro) option.

## `eh_frame`

Used by certain compilers (like GCC) to store the Exception Handler Frame, used for implementing C++ exceptions.

This frame contains more metadata used by exceptions at runtime.

## `linker_offset`

This segment adds a symbol into the linker script at its relative section position.

A segment named "john" with type `linker_offset` will cause a generated symbol with the name `john_OFFSET` to be placed into the linker script.
This can be useful for naming and referencing certain address locations from source code.

# Platform-specific segments

## N64

### Images

**Description:**

**splat** supports most of the [N64 image formats](https://n64squid.com/homebrew/n64-sdk/textures/image-formats/):

- `i`, i.e. `i4` and `i8`
- `ia`, i.e. `ia4`, `ia8`, and `ia16`
- `ci`, i.e. `ci4` and `ci8`
- `rgb`, i.e. `rgba32` and `rgba16`

These segments will parse the image data and dump out a `png` file.

**Note:** Using the dictionary syntax allows for richer configuration.

**Example:**

```yaml
# as list
- [0xABC, i4, filename, width, height]
# as a dictionary
- name: filename
  type: i4
  start: 0xABC
  width: 64
  height: 64
  flip_x: yes
  flip_y: no
```

`ci` (paletted) segments have a `palettes: []` setting that represents the list of palettes that should be linked to the `ci`. For each linked palette, an image will be exported. The implicit value of `palettes` is a one-element list containing the name of the raster, which means palettes and rasters with the same name will automatically be linked.

Palette segments can specify a `global_id`, which can be referred to from a `ci`'s `palettes` list. The `global_id` space is searched first, and this allows cross-segment links between palettes and rasters.

We recommend using [pigment64](https://github.com/decompals/pigment64) to convert extracted images back into original formats.

### `gfx`

`gfx` can be used to extract static f3dex ["display lists"](https://hackmd.io/@Roman971/Hk01jRxRr#Static-Data) into a .gfx.inc.c file, which is meant to be `#include`d from a source c file.

These segments support an optional `data_only` attribute, which is False by default. If enabled, the extracted file will contain only the data rather than the enclosing symbol definition.

Example output with `data_only` off (default):

```c
Gfx displayList[] = {
    gsDPPipeSync(),
    gsDPSetPrimColor(0, 0, 0x80, 0x80, 0x80, 0x80),
    gsDPSetEnvColor(0x80, 0x80, 0x80, 0x80),
    gsSPEndDisplayList(),
};
```

to be used in a source c file like
```c
#include "example.gfx.inc.c"
```

Example output with `data_only` on:
```c
gsDPPipeSync(),
gsDPSetPrimColor(0, 0, 0x80, 0x80, 0x80, 0x80),
gsDPSetEnvColor(0x80, 0x80, 0x80, 0x80),
gsSPEndDisplayList(),
```

to be used in a source c file like
```c
Gfx displayList[] = {
  #include "example.gfx.inc.c"
};
```

Some may prefer to define symbol names in source c files, rather than having splat be responsible for naming these symbols, which is why this option is provided.

[Example usage](https://github.com/pmret/papermario/blob/c43d15e/ver/us/splat.yaml#L1707)

### `vtx`

`vtx` can be used to extract arrays of Vtx struct data, into a .vtx.inc.c file, which is meant to be `#include`d from a source c file.

This option also supports the `data_only` attribute. See the section on the `gfx` segment for more details.

[Example usage](https://github.com/pmret/papermario/blob/c43d15e/ver/us/splat.yaml#L1706)

### `rsp`

The `rsp` segment is used for disassembling RSP microcode. It is an extension of the `hasm` segment type and enables special instruction handling in the disassembler.

### `ipl3`

The `ipl3` segment is used for disassembling ipl3 code. It is an extension of the `hasm` segment type and opts out of standard symbol-tracking behavior, since it lives in an unconventional memory space.

### Compressed segment types

splat supports the compression types MIO0 and Yay0 with segment type names `mio0` and `yay0`, respectively. Both of these output a .bin file, which is expected to be re-compressed as part of the project's build system.
The generated linker script then will expect a .`type`.o file to exist.

For example, for a `yay0` segment named "john", splat will create a decompressed john.bin file. The build system should then compress this file into `john.Yay0.bin` and then turn that into an object named `john.Yay0.o`, which will be linked into the output rom.

We recommend using [crunch64](https://github.com/decompals/crunch64) to re-compress MIO0 and Yay0 assets that are extracted with splat.

## PS2

### `lit4`

`lit4` is a segment that only contains single-precision floats.

splat will try to disassemble all the data from this segment as individual floats whenever possible.

### `lit8`

`lit8` is a segment that only contains double-precision floats.

splat will try to disassemble all the data from this segment as individual doubles whenever possible.

### `ctor`

`ctor` is used by certain compilers (like MWCCPS2) to store pointers to functions that initialize C++ global data objects.

The disassembly of this section is tweaked to avoid confusing its data with other types of data, this is because the disassembler can sometimes get confused and disassemble a pointer as a float, string, etc.

### `vtables`

`vtables` is used by certain compilers (like MWCCPS2) to store the virtual tables of C++ classes

The disassembly of this section is tweaked to avoid confusing its data with other types of data, this is because the disassembler can sometimes get confused and disassemble a pointer as a float, string, etc.

# General segment options

All splat's segments can be passed extra options for finer configuration. Note that those extra options require to rewrite the entry using the dictionary yaml notation instead of the list one.

### `linker_section_order`

**Description:**

Allows overriding the section order used for linker script generation.

Useful when a section of a file is not between the other sections of the same type in the ROM, for example a file having its data section between other files's rodata.

Take in mind this option may need the [`check_consecutive_segment_types`](Configuration.md#check_consecutive_segment_types) yaml option to be turned off.

**Example:**

```yaml
- [0x400, data, file1]
# data ends

# rodata starts
- [0x800, rodata, file2]
- { start: 0xA00, type: data, name: file3, linker_section_order: .rodata }
- [0xC00, rodata, file4]
```

This will created `file3.data.s` within the `asm` folder, but won't be reordered in the generated linker script to be placed on the data section.

### `linker_section`

**Description:**

Allows to override the `.section` directive that will be used when generating the disassembly of the corresponding section, without needing to write an extension segment. This also affects the section name that will be used during link time.

Useful for sections with special names, like an executable section named `.start`

**Example:**

```yaml
- { start: 0x1000, type: asm, name: snmain, linker_section: .start }
- [0x1070, rdata, libc]
- [0x10A0, rdata, main_030]
```

### `ld_fill_value`

Allows to specify the value of the `FILL` statement generated for this specific top-level segment of the linker script, ignoring the global configuration.

It must be either an integer, which will be used as the parameter for the `FILL` statement, or `null`, which tells splat to not emit a `FILL` statement for this segment.

If not set, then the global configuration is used. See [ld_fill_value](Configuration.md#ld_fill_value) on the Configuration section.

Defaults to the value of the global option.

### `ld_align_segment_start`

Specify the current segment should be aligned before starting it.

This option specifies the desired alignment value, or `null` if no aligment should be imposed on the segment start.

If not set, then the global configuration is used. See [ld_align_segment_start](Configuration.md#ld_align_segment_start) on the Configuration section.

### `subalign`

Sub-alignment (in bytes) of sections.

Only works on top-level segments

`subalign` can be `null` to not force any specific alignment and use the built section's declared alignment instead.

**Example:**

```yaml
    subalign: 4
```

Defaults to the global `subalign` option.

### `suggestion_rodata_section_start`

splat is able to suggest where the rodata section may start by inspecting a corresponding data section (as long as the rodata section follows rodata and not the other way around).
Don't trust this suggestion blindly since it may be incorrect, either because the rodata section may start a lot before than what splat suggests or splat even may be completely wrong and suggest something that
actually is data as if it were rodata.

This option allows turning off the suggestion for this segment in case you have checked the suggestion is not correct. This option is inherited from the parent segment if a subsegment does not specify it.

This can be turned off [globally](Configuration.md#suggestion_rodata_section_start), but it is not recommended to globally turn it off unless you are confident you have mapped every data/rodata section of every segment.

Defaults to the global option.

**Example:**

```yaml
  - name: boot
    type: code
    start: 0x001060
    vram: 0x80000460
    suggestion_rodata_section_start: False
```

### `pair_segment`

Allows pairing sections of two different segments together.

The main purpose of this is to make the automatic rodata-to-function migration possible, since the default behavior only allows pairing different sections of the same name under the same segment only. This kind of ROM layout can be seen on some TLB games from N64 projects.

This value expects the name of the other segment that should be paired to the current one. Only one of the two to-be-paired segments should have this attribute.

**Example:**

```yaml
  - name:  init
    type:  code
    start: 0x00001000
    vram:  0x10001000
    pair_segment: init_data # This is the name of the following segment.
    subsegments:
      # -- snip --
      - [0x15550, c, libultra/audio/init_15550]
      # -- snip --

  - name:  init_data
    type:  code
    start: 0x000290D0
    vram:  0x800290D0
    bss_size: 0x16690
    # Note there's no `pair_segment: init` on this segment.
    subsegments:
      # -- snip --
      - [0x2C6B0, .rodata, libultra/audio/init_15550]
      # -- snip --
```
