### What is splat?

**splat** is a binary splitting tool, written in Python.

It is the spiritual successor to [n64split](https://github.com/queueRAM/sm64tools/blob/master/n64split.c). Originally written to handle N64 ROMs, it also has limited support for PSX binaries.

MIPS code disassembly is handled via [spimdisasm](https://github.com/Decompollaborate/spimdisasm/).

There are a number of asset types built-in (e.g. various image formats, N64 Vtx data, etc), and it is designed to be simple to write your own custom types that can do anything you want and fit right into the splat pipeline.


### How does it work?

**splat** takes a [yaml](https://en.wikipedia.org/wiki/YAML) configuration file which tell it *where* and *how* to split a given file. Splat loads the yaml and an optional "symbol_addrs" file that can give it information about symbols that will be used during disassembly. It then runs the two main phases: scan and split. 

The scan phase is for making a first pass over the data and for doing initial disassembly. During the split phase, information gathered during the scan phase is used and files are written out to disk.

After scanning and splitting, splat will output a linker script that can be used to re-build the input file.


### Sounds great, how do I get started?

Have a look at the [Quickstart](https://github.com/ethteck/splat/wiki/Quickstart), or check out the [Examples](https://github.com/ethteck/splat/wiki/Examples) page to see projects that are using **splat**.
