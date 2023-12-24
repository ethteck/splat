#!/bin/bash

set -e

export SPIMDISASM_ASM_GENERATED_BY="False"

# Ensure we start from a clean state
rm -rf test/basic_app/split

python3 ./split.py test/basic_app/splat.yaml --use-cache

rm -rf test/basic_app/expected
cp -r test/basic_app/split test/basic_app/expected
