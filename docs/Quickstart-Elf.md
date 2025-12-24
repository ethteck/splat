# Quickstart Elf

> [!NOTE]
> This quickstart is written with PS2 ELFs in mind, relocatable ELFs are not supported. It is also assumed that you are using Ubuntu 22.04 either natively, via WSL2 or via Docker.

For the purposes of this quickstart, we will assume that we are going to split a game called `mygame` and we have the ELF from the iso named `SLUS_XXX.YY`.

Create a directory for `~/mygame` and `cd` into it:

```sh
mkdir -p ${HOME}/mygame && cd ${HOME}/mygame
```

Copy the `SLUS_XXX.YY` file into the `mygame` directory inside your home directory.

## System packages

### Python 3.9

Ensure you are have **Python 3.9** or higher installed:

```sh
$ python3 --version
Python 3.9.10
```

If you get `bash: python3: command not found` install it with the following command:

```sh
sudo apt update && sudo apt install -y python3 python3-pip
```

### MIPS binutils

Ensure you have a MIPS binutils installed in your PC. Specifically we'll need a MIPS `objcopy`.

```sh
$ mips-linux-gnu-objcopy --version
GNU objcopy (GNU Binutils for Ubuntu) 2.38
```

If you get an error then install it with the following command:

```sh
sudo apt install binutils-mips-linux-gnu
```

## Install splat

We'll install `splat` using `pip` and enable its `mips` dependencies:

```sh
python3 -m pip install -U splat64[mips]
```

## Create a config file from your ELF

`splat` has a script that will generate a `yaml` file based in the ELF file.

```sh
python3 -m splat create_config SLUS_XXX.YY
```

This command generates a few files, from which the most important ones are the `SLUS_XXX.YY.rom` and the `SLUS_XXX.YY.yaml`.

### The generated ROM

The original ELF file contains the game code and a lot of extra metadata which we don't care about.

To get rid of the extra metadata the `create_config` script generated a ROM that only contains the game code and data, and the generated `yaml` is used to split this ROM instead of splitting the original ELF, making the splitting and build process a lot more cleaner.

To generate this ROM the `create_config` script uses `objcopy`. You can (and should) integrate this ROM generation step into your setup script / configure script. `create_config` tells you exactly what command it used to generate the ROM, which should look similar to the following:

```sh
mips-linux-gnu-objcopy -O binary --gap-fill=0x00 SLUS_XXX.YY SLUS_XXX.YY.rom
```

This approach has a few pros and cons. The biggest pro is being able to generate an ELF with proper metadata as part of your build system, making a lot easier to achieve shiftability eventually. Note only this is not enough for shiftability, other factors must be worked out, like symbol alignment, fake symbols, etc.

### The generated `yaml`

`create_config` generates a `yaml` file which describes how the ROM is structured, what parts are code, data, etc. It also includes configuration values for splat.

Below is an example of what a generated yaml may look like:

```yaml
# name: Your game name here!
sha1: 6da2d0a02aafe3bfba71ca8ba859174756ba3f5e
options:
  basename: SLUS_206.24
  target_path: SLUS_206.24.rom
  elf_path: build/SLUS_206.24.elf
  base_path: .
  platform: ps2
  compiler: EEGCC

  gp_value: 0x003A0EF0
  ld_gp_expression: cod_SBSS_START + 0x7FF0

  # asm_path: asm
  # src_path: src
  # build_path: build

  ld_script_path: SLUS_206.24.ld
  ld_dependencies: True
  ld_wildcard_sections: True
  ld_bss_contains_common: True

  create_asm_dependencies: True

  find_file_boundaries: False

  o_as_suffix: True

  symbol_addrs_path:
    - symbol_addrs.txt
  reloc_addrs_path:
    - reloc_addrs.txt

  # undefined_funcs_auto_path: undefined_funcs_auto.txt
  # undefined_syms_auto_path: undefined_syms_auto.txt

  extensions_path: tools/splat_ext

  string_encoding: ASCII
  data_string_encoding: ASCII
  rodata_string_guesser_level: 2
  data_string_guesser_level: 2

  named_regs_for_c_funcs: False

  section_order:
    - .text
    # - .vutext
    - .data
    - .rodata
    - .gcc_except_table
    - .sbss
    - .bss

  auto_link_sections:
    - .data
    - .rodata
    - .gcc_except_table
    - .sbss
    - .bss

segments:
  - name: cod
    type: code
    start: 0x000000
    vram: 0x00100000
    bss_size: 0x6907C
    subalign: null
    subsegments:
      - [0x000000, asm, cod/000000] # .text
      - [0x3209C0, textbin, cod/3209C0] # .vutext
      - [0x324680, data, cod/324680] # .data
      - [0x350100, rodata, cod/350100] # .rodata
      - [0x3B0780, gcc_except_table, cod/3B0780] # .gcc_except_table
      - { type: sbss, vram: 0x004B0880, name: cod/004B0880 } # .sbss
      - { type: bss, vram: 0x004B0F80, name: cod/004B0F80 } # .bss
  - [0x3B0864]
```

This is a bare-bones configuration and there is a lot of work required to map out the different sections of the ROM.

## Run splat with your configuration

```sh
python3 -m splat split SLUS_XXX.YY.yaml
```

The output will look something like this:

```plain_text
splat 0.36.2 (powered by spimdisasm 1.38.0)
Loading symbols (symbol_addrs): 100%|█████████████████████████| 2/2 [00:00<00:00, 9868.95it/s]
Scanning cod:   0%|                                                     | 0/1 [00:00<?, ?it/s]
Rodata segment 'cod/350100' may belong to the text segment 'cod/000000'
    Based on the usage from the function func_00102E48 to the symbol D_00450308
Scanning cod: 100%|█████████████████████████████████████████████| 1/1 [00:26<00:00, 26.62s/it]
Splitting cod: 100%|████████████████████████████████████████████| 1/1 [00:14<00:00, 14.77s/it]
Linker script cod: 100%|███████████████████████████████████████| 1/1 [00:00<00:00, 447.54it/s]
Split 3 MB (85.17%) in defined segments
                 asm:     3 MB (84.76%) 1 split, 0 cached
             textbin:    15 KB (0.40%) 1 split, 0 cached
             unknown:      0 B (0.00%) from unknown bin files
```

It's up to you to figure out the layout of the ROM, finding proper file splits.

## Next Steps

The reassembly of the ROM is currently out of scope of this quickstart, as is switching out the `asm` segments for `c` or `cpp`.

You can find a general workflow for using `splat` at [General Workflow](https://github.com/ethteck/splat/wiki/General-Workflow)

Please feel free to improve this guide!
