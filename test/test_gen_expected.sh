#!/bin/bash

set -e

export SPIMDISASM_ASM_GENERATED_BY="False"

# Ensure we start from a clean state
rm -rf test/basic_app/split

cd test/basic_app
python3 -m splat split splat.yaml --use-cache
cd ../..

rm -rf test/basic_app/expected
cp -r test/basic_app/split test/basic_app/expected
