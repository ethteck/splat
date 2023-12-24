# Test instructions

## basic_app

### Building the ROM

You are expected to have a mips cross compiler installed on your system
(compatible with binutils).

By default we use `mips-linux-gnu-`, but if you want to use a different
toolchain you can provide your own to `make` by passing the `CROSS=` option.
For example `make CROSS=mipsel-linux-gnu-`.

To build the ROM:

```bash
make -C test/basic_app clean
make -C test/basic_app download_kmc
make -C test/basic_app all
```

### Running the test

Run `python3 test.py`.

This script will check if the files were generated as expected or if anything
changed. Files changing may be good or bad depending on the changes made to the
repo.

If changes are expected, then follow the instructions at
[Regenerate the expected files](#regenerate-the-expected-files).

### Regenerate the expected files

You need to have built the rom first.

Run `test/test_gen_expected.sh` from the root of the repository and commit the
changes.

## Docker

There's a `Dockerfile`, but I don't know how to use Docker so I can't tell you
how to use it, shorry.
