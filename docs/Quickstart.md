# Quickstart

> **Note**: This quickstart is written with N64 ROMs in mind, and the assumption that you are using Ubuntu 20.04 either natively, via WSL2 or via Docker.

For the purposes of this quickstart, we will assume that we are going to split a game called `mygame` and we have the ROM in `.z64` format named `baserom.z64`.

Create a directory for `~/mygame` and `cd` into it:

```sh
mkdir -p ${HOME}/mygame && cd ${HOME}/mygame
```

Copy the `baserom.z64` file into the `mygame` directory inside your home directory.

## System packages

### Python 3.9

Ensure you are have **Python 3.9** or higher installed:

```sh
python3 --version
Python 3.9.10
```

If you get `bash: python3: command not found` install it with the following command:

```sh
sudo apt update && sudo apt install -y python3 python3-pip
```

## Install splat

We'll install `splat` using `pip` and enable its `mips` dependencies:

```sh
python3 -m pip install -U splat64[mips]
```

## Create a config file for your baserom

`splat` has a script that will generate a `yaml` file for your ROM.

```sh
python3 -m splat create_config baserom.z64
```

The `yaml` file generated will be named based upon the name of the ROM (taken from its header). The example below is for Super Mario 64:

```yaml
$ cat supermario64.yaml
name: Super Mario 64 (North America)
sha1: 9bef1128717f958171a4afac3ed78ee2bb4e86ce
options:
  basename: supermario64
  target_path: baserom.z64
  elf_path: build/supermario64.elf
  base_path: .
  platform: n64
  compiler: IDO

  # asm_path: asm
  # src_path: src
  # build_path: build
  # create_asm_dependencies: True

  ld_script_path: supermario64.ld
  ld_dependencies: True

  find_file_boundaries: True
  header_encoding: ASCII

  o_as_suffix: True
  use_legacy_include_asm: False
  mips_abi_float_regs: o32

  asm_function_macro: glabel
  asm_jtbl_label_macro: jlabel
  asm_data_macro: dlabel

  # section_order: [".text", ".data", ".rodata", ".bss"]
  # auto_link_sections: [".data", ".rodata", ".bss"]

  symbol_addrs_path:
    - symbol_addrs.txt
  reloc_addrs_path:
    - reloc_addrs.txt

  # undefined_funcs_auto_path: undefined_funcs_auto.txt
  # undefined_syms_auto_path: undefined_syms_auto.txt

  extensions_path: tools/splat_ext

  # string_encoding: ASCII
  # data_string_encoding: ASCII
  rodata_string_guesser_level: 2
  data_string_guesser_level: 2
  # libultra_symbols: True
  # hardware_regs: True
  # gfx_ucode: # one of [f3d, f3db, f3dex, f3dexb, f3dex2]
segments:
  - name: header
    type: header
    start: 0x0

  - name: boot
    type: bin
    start: 0x40

  - name: entry
    type: code
    start: 0x1000
    vram: 0x80246000
    subsegments:
      - [0x1000, hasm]

  - name: main
    type: code
    start: 0x1050
    vram: 0x80246050
    follows_vram: entry
    bss_size: 0x2CEE0
    subsegments:
      - [0x1050, asm]
      - [0xE6430, data]
      - { start: 0xF5580, type: bss, vram: 0x8033A580 }

  - type: bin
    start: 0xF5580
    follows_vram: main
  - [0x800000]
```

This is a bare-bones configuration and there is a lot of work required to map out the different sections of the ROM.

## Run splat with your configuration

```sh
python3 -m splat split supermario64.yaml
```

The output will look something like this:

```plain_text
splat 0.22.1 (powered by spimdisasm 1.21.0)
Scanning main:   0%|                                | 0/5 [00:00<?, ?it/s]

Data segment E6430, symbol at vram 80335B60 is a jumptable, indicating the start of the rodata section _may_ be near here.
Please note the real start of the rodata section may be way before this point.
      - [0xF0B60, rodata]
Scanning F5580: 100%|███████████████████████| 5/5 [00:04<00:00,  1.06it/s]
Splitting main:   0%|                               | 0/5 [00:00<?, ?it/s]
Segment 1050, symbol at vram 80246DF8 ends with extra nops, indicating a likely file split.
File split suggestions for this segment will follow in config yaml format:
      - [0x1E70, asm]
      - [0x3C40, asm]
      - [0x45E0, asm]
      - [0x6FF0, asm]
#     < -- snip -->
      - [0xE6060, asm]
      - [0xE61F0, asm]
      - [0xE6200, asm]
      - [0xE6260, asm]
Splitting F5580: 100%|██████████████████████| 5/5 [00:03<00:00,  1.58it/s]
Linker script F5580: 100%|████████████████| 5/5 [00:00<00:00, 1580.25it/s]
Split 1 MB (11.98%) in defined segments
              header:     64 B (0.00%) 1 split, 0 cached
                 bin:     4 KB (0.05%) 1 split, 0 cached
                code:     1 MB (11.93%) 2 split, 0 cached
             unknown:     7 MB (88.02%) from unknown bin files
```

Notice that `splat` has found some potential file splits (function start/end with 16 byte alignment padded with nops) and it also suggested where the start of rodata may be.

It's up to you to figure out the layout of the ROM.

## Next Steps

The reassembly of the ROM is currently out of scope of this quickstart, as is switching out the `asm` segments for `c`.

You can find a general workflow for using `splat` at [General Workflow](https://github.com/ethteck/splat/wiki/General-Workflow)

Please feel free to improve this guide!
