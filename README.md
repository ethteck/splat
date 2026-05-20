# splat

[![PyPI](https://img.shields.io/pypi/v/splat64)](https://pypi.org/project/splat64/)

A binary splitting tool to assist with decompilation and modding projects

Currently N64, PSX, PS2, PSP and Win32 PE (x86 / x86_64) binaries are supported. More platforms may come in the future.

Please check out the [wiki](https://github.com/ethteck/splat/wiki) for more information including [examples](https://github.com/ethteck/splat/wiki/Examples) of projects that use splat.

## Installing

The recommended way to install is using from the PyPi release, via `pip`:

```bash
python3 -m pip install -U splat64[mips]
```

The brackets corresponds to the optional dependencies to install while installing splat. Refer to [Optional dependencies](#optional-dependencies) to see the list of available groups.

If you use a `requirements.txt` file in your repository, then you can add this library with the following line:

```txt
splat64[mips]>=0.40.1,<1.0.0
```

### Optional dependencies

- `mips`: Required when using the N64, PSX, PS2 or PSP platforms.
- `win32`: Required when using the Win32 PE platform (pulls in Capstone for x86 / x86_64 disassembly).
- `dev`: Installs all the available dependencies groups and other packages for development.

### Gamecube / Wii

For Gamecube / Wii projects, see [decomp-toolkit](https://github.com/encounter/decomp-toolkit)!

### Win32 PE support

The `win32` platform handles PE32 (x86) and PE32+ (x86_64) binaries built by MSVC 4.x-14.x, MinGW (libgcc-linked), and Clang-LLD. Decoded directories include exports, imports, delay imports, bound imports, resources, exception/SEH tables (with unwind-info opcode lists), TLS, /GS + /SAFESEH + /guard:cf load-config, base relocations, debug (CodeView PDB GUID/age extraction), the CLR runtime header (.NET assemblies), and the deprecated COFF symbol table.

Workflow:

```bash
python -m splat.scripts.create_config my.exe       # auto-generate YAML + symbol_addrs.txt
python -m splat split my.exe.yaml                  # produce GAS-clean .s + linker script
python -m splat.scripts.win32_reassemble my.exe.yaml  # link bytes back into a PE
```

With `exact_encoding: true` on the text/data/pdata subsegments the reassembled PE is byte-identical to the original.
