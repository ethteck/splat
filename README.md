# splat

[![PyPI](https://img.shields.io/pypi/v/splat64)](https://pypi.org/project/splat64/)

A binary splitting tool to assist with decompilation and modding projects

Currently, only N64, PSX, PS2 and PSP binaries are supported. More platforms may come in the future.

Please check out the [wiki](https://github.com/ethteck/splat/wiki) for more information including [examples](https://github.com/ethteck/splat/wiki/Examples) of projects that use splat.

## Installing

The recommended way to install is using from the PyPi release, via `pip`:

```bash
python3 -m pip install -U splat64[mips]
```

The brackets corresponds to the optional dependencies to install while installing splat. Refer to [Optional dependencies](#optional-dependencies) to see the list of available groups.

If you use a `requirements.txt` file in your repository, then you can add this library with the following line:

```txt
splat64[mips]>=0.32.2,<1.0.0
```

### Optional dependencies

- `mips`: Required when using the N64, PSX, PS2 or PSP platforms.
- `dev`: Installs all the available dependencies groups and other packages for development.

### Gamecube / Wii

For Gamecube / Wii projects, see [decomp-toolkit](https://github.com/encounter/decomp-toolkit)!
