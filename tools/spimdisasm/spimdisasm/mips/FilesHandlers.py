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


def getRdataAndLateRodataForFunction(func: symbols.SymbolFunction, rodataFileList: list[sections.SectionRodata], context: common.Context):
    rdataList: list[str] = []
    lateRodataList: list[str] = []
    lateRodataLen = 0
    firstRodata = None
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

            rodataSymbol = rodataSym.contextSym
            assert rodataSymbol is not None
            # We only care for rodata that's used once
            if rodataSymbol.referenceCounter != 1:
                break

            # A const variable should not be placed with a function
            if rodataSymbol.isMaybeConstVariable():
                break

            if firstRodata is None:
                firstRodata = rodataSection.vram

            dis = rodataSym.disassemble()
            if rodataSymbol.isLateRodata():
                lateRodataList.append(dis)
                lateRodataLen += rodataSym.sizew
            else:
                rdataList.append(dis)


            if rodataSymbol.isLateRodata():
                lateRodataList.append("\n")
            else:
                rdataList.append("\n")

    return rdataList, lateRodataList, lateRodataLen, firstRodata

def writeSplittedFunctionToFile(f: TextIO, func: symbols.SymbolFunction, rodataFileList: list[sections.SectionRodata], context: common.Context):
    rdataList, lateRodataList, lateRodataLen, firstRodata = getRdataAndLateRodataForFunction(func, rodataFileList, context)

    if len(rdataList) > 0:
        # Write the rdata
        f.write(".rdata\n")
        for x in rdataList:
            f.write(x)

    if len(lateRodataList) > 0:
        # Write the late_rodata
        f.write(".late_rodata\n")
        if lateRodataLen / len(func.instructions) > 1/3:
            align = 4
            if firstRodata is not None:
                if firstRodata % 8 == 0:
                    align = 8
            f.write(f".late_rodata_alignment {align}\n")
        for x in lateRodataList:
            f.write(x)

    if len(rdataList) > 0 or len(lateRodataList) > 0:
        f.write("\n")
        f.write(".text\n")

    # Write the function
    f.write(func.disassemble())

def writeSplitedFunction(path: str, func: symbols.SymbolFunction, rodataFileList: list[sections.SectionRodata], context: common.Context):
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, func.name) + ".s", "w") as f:
        writeSplittedFunctionToFile(f, func, rodataFileList, context)


def getOtherRodata(vram: int, nextVram: int, rodataSection: sections.SectionRodata, context: common.Context) -> tuple[str|None, list[str]]:
    rdataList: list[str] = []

    rodataSymbol = context.getGenericSymbol(vram, False)
    assert rodataSymbol is not None

    # A const variable should not be placed with a function
    if not rodataSymbol.isMaybeConstVariable():
        if rodataSymbol.referenceCounter == 1:
            #continue
            return None, []

    # print(rodataSymbol.name, rodataSymbol.referenceCounter)

    for rodataSym in rodataSection.symbolList:
        # TODO: this can be improved a bit
        assert rodataSym.vram is not None
        if rodataSym.vram < vram:
            continue
        if rodataSym.vram >= nextVram:
            break

        dis = rodataSym.disassemble()
        rdataList.append(dis)

    return rodataSymbol.name, rdataList

def writeOtherRodata(path: str, rodataFileList: list[sections.SectionRodata], context: common.Context):
    for rodataSection in rodataFileList:
        rodataPath = os.path.join(path, rodataSection.name)
        os.makedirs(rodataPath, exist_ok=True)
        sortedSymbolVRams = sorted(rodataSection.symbolsVRams)

        for vram in sortedSymbolVRams:
            nextVramIndex = sortedSymbolVRams.index(vram) + 1
            nextVram = 0xFFFFFFFF if nextVramIndex >= len(sortedSymbolVRams) else sortedSymbolVRams[nextVramIndex]

            rodataSymbolName, rdataList = getOtherRodata(vram, nextVram, rodataSection, context)
            if rodataSymbolName is None:
                continue

            rodataSymbolPath = os.path.join(rodataPath, rodataSymbolName) + ".s"

            with open(rodataSymbolPath, "w") as f:
                f.write(".rdata\n")
                for rdata in rdataList:
                    f.write(rdata)
