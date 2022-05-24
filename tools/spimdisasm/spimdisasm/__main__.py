#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import pathlib

import spimdisasm


def exampleMain():
    description = "Single file disassembler example"
    parser = argparse.ArgumentParser(prog="spimdisasm", description=description)

    parser.add_argument("binary", help="Path to input binary")

    parser.add_argument("--output", help="Path to output. Use '-' to print to stdout instead. Defaults to '-'", default="-")

    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {spimdisasm.__version__}")

    parser_singleFile = parser.add_argument_group("Single file disassembly options")

    parser_singleFile.add_argument("--start", help="Raw offset of the input binary file to start disassembling. Expects an hex value", default="0")
    parser_singleFile.add_argument("--end", help="Offset end of the input binary file to start disassembling. Expects an hex value",  default="0xFFFFFF")
    parser_singleFile.add_argument("--vram", help="Set the VRAM address. Expects an hex value")

    args = parser.parse_args()

    # Context is used to store information that should be shared between file sections, such as mapping the symbol vram's to its name and more
    context = spimdisasm.common.Context()

    # Read whole binary input file
    array_of_bytes = spimdisasm.common.Utils.readFileAsBytearray(args.binary)
    inputName = pathlib.Path(args.binary).stem

    start = int(args.start, 16)
    end = int(args.end, 16)

    fileVram = None
    if args.vram is not None:
        fileVram = int(args.vram, 16)

    # Truncate binary to the requested range
    truncatedInputBytes = array_of_bytes[start:end]

    # Asume the input is a .text section. Insntance a SectionText and analyze it
    textSection = spimdisasm.mips.sections.SectionText(context, fileVram, inputName, truncatedInputBytes)
    textSection.analyze()
    textSection.setCommentOffset(start)

    # Write the processed section to a file. This method handles '-' to stdout too
    textSection.saveToFile(args.output)


if __name__ == "__main__":
    exampleMain()
