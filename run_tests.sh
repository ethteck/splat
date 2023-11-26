#!/bin/bash

# docker build container
docker build --tag splat-build:latest . && \
# get compilers and tools
# clean
make -C test/basic_app clean && \
# build
docker run --rm -v $(pwd):/splat -w /splat/test/basic_app splat-build sh build.sh && \
# test
python3 test.py
