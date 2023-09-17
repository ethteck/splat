The configuration file for **splat** consists of a number of well-defined segments.

Most segments can be defined as a dictionary or a list, but the list syntax is only suitable for very simple cases and doesn't allow for specifying most of the options a segment type has to offer.

Splat segments' behavior generally falls under two categories: extraction and linking. Some segments will only do extraction, some will only do linking, some both, and some neither. Generally, segments both will describe extraction and linking behavior. Additionally, a segment type whose name starts with a dot (.) will only focus on linking. 

## `asm`

**Description:**

Segments designated Assembly, `asm`, will be disassembled via Capstone and then enriched with Symbols based on the contents of `symbol_addrs`.

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

Hand-written Assembly, `hasm`, similar to `asm` except it will not overwrite any existing files.

**Example:**

```yaml
# as list
- [0xABC, hasm, filepath]

# as dictionary
- name: filepath
  type: hasm
  start: 0xABC
```

## `bin`

**Description:**

The 'binary' segment type is for 'raw' data, or data where the type is yet to be determined.

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

The 'code' segment type, `code` is a group that can have many `subsegments`.

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
- If the target `.c` file does not exist, a new file will be generated with macros to include the original Assembly (macros differ for IDO vs GCC compiler).
- Otherwise the target `.c` file is scanned to determine what assembly needs to be extracted from the ROM.

Assembly that is extracted due to a `c` segment will be written to a `nonmatching` folder, with one function per file.

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

## Images

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
