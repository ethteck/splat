#!/bin/bash

set -e

# clean
make -C test/basic_app clean
# get compilers and tools
make -C test/basic_app download_kmc
# build
make -C test/basic_app all
# test
python3 test.py
