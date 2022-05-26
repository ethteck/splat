#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
from typing import TextIO

from .. import common

from . import sections
from . import symbols


def createSectionFromSplitEntry(splitEntry: common.FileSplitEntry, array_of_bytes: bytearray, outputPath: str, context: common.Context) -> sections.SectionBase:
    head, tail = os.path.split(outputPath)

    offsetStart = splitEntry.offset
    offsetEnd = splitEntry.nextOffset

    if offsetStart >= 0 and offsetEnd >= 0:
        common.Utils.printVerbose(f"Parsing offset range [{offsetStart:02X}, {offsetEnd:02X}]")
        array_of_bytes = array_of_bytes[offsetStart:offsetEnd]
    elif offsetEnd >= 0:
        common.Utils.printVerbose(f"Parsing until offset 0x{offsetEnd:02X}")
        array_of_bytes = array_of_bytes[:offsetEnd]
    elif offsetStart >= 0:
        common.Utils.printVerbose(f"Parsing since offset 0x{offsetStart:02X}")
        array_of_bytes = array_of_bytes[offsetStart:]

    vram = None
    if splitEntry.vram is not None:
        common.Utils.printVerbose(f"Using VRAM {splitEntry.vram:08X}")
        vram = splitEntry.vram

    f: sections.SectionBase
    if splitEntry.section == common.FileSectionType.Text:
        f = sections.SectionText(context, vram, tail, array_of_bytes)
    elif splitEntry.section == common.FileSectionType.Data:
        f = sections.SectionData(context, vram, tail, array_of_bytes)
    elif splitEntry.section == common.FileSectionType.Rodata:
        f = sections.SectionRodata(context, vram, tail, array_of_bytes)
    elif splitEntry.section == common.FileSectionType.Bss:
        assert isinstance(splitEntry.vram, int)
        f = sections.SectionBss(context, splitEntry.vram, splitEntry.vram + offsetEnd - offsetStart, tail)
    else:
        common.Utils.eprint("Error! Section not set!")
        exit(-1)

    f.isHandwritten = splitEntry.isHandwritten
    f.isRsp = splitEntry.isRsp

    return f

def analyzeSectionFromSplitEntry(fileSection: sections.SectionBase, splitEntry: common.FileSplitEntry):
    offsetStart = splitEntry.offset

    common.Utils.printVerbose("Analyzing")
    fileSection.analyze()
    fileSection.setCommentOffset(offsetStart)

    common.Utils.printVerbose()

    fileSection.printAnalyzisResults()

    return fileSection


def writeSection(path: str, fileSection: sections.SectionBase):
    head, tail = os.path.split(path)

    # Create directories
    if head != "":
        os.makedirs(head, exist_ok=True)

    fileSection.saveToFile(path)

    return path


def getRdataAndLateRodataForFunction(func: symbols.SymbolFunction, rodataFileList: list[sections.SectionRodata]):
    rdataList: list[symbols.SymbolBase] = []
    lateRodataList: list[symbols.SymbolBase] = []
    lateRodataSize = 0

    for rodataSection in rodataFileList:
        if len(rdataList) > 0 or len(lateRodataList) > 0:
            # We already have the rodata for this function. Stop searching
            break

        # Skip the file if there's nothing in this file refenced by the current function
        intersection = func.referencedVRams & rodataSection.symbolsVRams
        if len(intersection) == 0:
            continue

        for rodataSym in rodataSection.symbolList:
            assert rodataSym.vram is not None

            if rodataSym.vram not in intersection:
                continue

            assert rodataSym.contextSym is not None
            # We only care for rodata that's used once
            if rodataSym.contextSym.referenceCounter != 1:
                break

            # A const variable should not be placed with a function
            if rodataSym.contextSym.isMaybeConstVariable():
                break

            if rodataSym.contextSym.isLateRodata():
                lateRodataList.append(rodataSym)
                lateRodataSize += rodataSym.sizew
            else:
                rdataList.append(rodataSym)

    return rdataList, lateRodataList, lateRodataSize

def writeSplittedFunctionToFile(f: TextIO, func: symbols.SymbolFunction, rodataFileList: list[sections.SectionRodata]):
    rdataList, lateRodataList, lateRodataSize = getRdataAndLateRodataForFunction(func, rodataFileList)

    if len(rdataList) > 0:
        # Write the rdata
        f.write(".rdata" + common.GlobalConfig.LINE_ENDS)
        for sym in rdataList:
            f.write(sym.disassemble())
            f.write(common.GlobalConfig.LINE_ENDS)

    if len(lateRodataList) > 0:
        # Write the late_rodata
        f.write(".late_rodata" + common.GlobalConfig.LINE_ENDS)
        if lateRodataSize / len(func.instructions) > 1/3:
            align = 4
            firstLateRodataVram = lateRodataList[0].vram
            if firstLateRodataVram is not None and firstLateRodataVram % 8 == 0:
                align = 8
            f.write(f".late_rodata_alignment {align}" + common.GlobalConfig.LINE_ENDS)
        for sym in lateRodataList:
            f.write(sym.disassemble())
            f.write(common.GlobalConfig.LINE_ENDS)

    if len(rdataList) > 0 or len(lateRodataList) > 0:
        f.write(common.GlobalConfig.LINE_ENDS + ".text" + common.GlobalConfig.LINE_ENDS)

    # Write the function
    f.write(func.disassemble())

def writeSplitedFunction(path: str, func: symbols.SymbolFunction, rodataFileList: list[sections.SectionRodata]):
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, func.name) + ".s", "w") as f:
        writeSplittedFunctionToFile(f, func, rodataFileList)


def writeOtherRodata(path: str, rodataFileList: list[sections.SectionRodata]):
    for rodataSection in rodataFileList:
        rodataPath = os.path.join(path, rodataSection.name)
        os.makedirs(rodataPath, exist_ok=True)

        for rodataSym in rodataSection.symbolList:
            if not rodataSym.isRdata():
                continue

            rodataSymbolPath = os.path.join(rodataPath, rodataSym.name) + ".s"
            with open(rodataSymbolPath, "w") as f:
                f.write(".rdata" + common.GlobalConfig.LINE_ENDS)
                f.write(rodataSym.disassemble())
