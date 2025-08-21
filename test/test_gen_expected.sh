#!/bin/bash

set -e

export SPIMDISASM_ASM_GENERATED_BY="False"

# cd into the "root" of the "project"
cd test/basic_app

# Ensure we start from a clean state
rm -rf split

python3 -m splat split splat.yaml --use-cache

rm -rf expected
cp -r split expected
