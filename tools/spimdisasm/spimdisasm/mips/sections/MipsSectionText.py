#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from ... import common

from .. import instructions
from .. import symbols

from ..MipsFileBase import FileBase

from . import SectionBase


class SectionText(SectionBase):
    def __init__(self, context: common.Context, vram: int|None, filename: str, array_of_bytes: bytearray):
        super().__init__(context, vram, filename, array_of_bytes, common.FileSectionType.Text)

        # TODO: do something with this information
        self.fileBoundaries: list[int] = list()

    @property
    def nFuncs(self) -> int:
        return len(self.symbolList)

    def analyze(self):
        functionEnded = False
        farthestBranch = 0
        funcsStartsList = [0]
        unimplementedInstructionsFuncList = []

        currentVram = self.getVramOffset(0)
        instrsList: list[instructions.InstructionBase] = list()
        for word in self.words:
            if self.isRsp:
                instr = instructions.wordToInstructionRsp(word)
            else:
                instr = instructions.wordToInstruction(word)

            if self.vram is not None:
                instr.vram = currentVram

            instrsList.append(instr)
            currentVram += 4

        instructionOffset = 0
        currentInstructionStart = 0
        currentFunctionSym = self.context.getFunction(self.getVramOffset(instructionOffset))

        isLikelyHandwritten = self.isHandwritten

        isInstrImplemented = True
        index = 0
        nInstr = len(instrsList)
        while index < nInstr:
            instr = instrsList[index]
            if not instr.isImplemented():
                isInstrImplemented = False

            if functionEnded:
                functionEnded = False

                isLikelyHandwritten = self.isHandwritten
                index += 1
                instructionOffset += 4
                isboundary = False
                # Loop over until we find a instruction that isn't a nop
                while index < nInstr:
                    instr = instrsList[index]
                    if instr.uniqueId != instructions.InstructionId.NOP:
                        if isboundary:
                            self.fileBoundaries.append(self.inFileOffset + index*4)
                        break
                    index += 1
                    instructionOffset += 4
                    isboundary = True

                currentInstructionStart = instructionOffset
                currentFunctionSym = self.context.getFunction(self.getVramOffset(instructionOffset))

                funcsStartsList.append(index)
                unimplementedInstructionsFuncList.append(not isInstrImplemented)
                if index >= len(instrsList):
                    break
                instr = instrsList[index]
                isInstrImplemented = instr.isImplemented()

            if not self.isRsp and not isLikelyHandwritten:
                if isinstance(instr, instructions.InstructionCoprocessor2):
                    isLikelyHandwritten = True
                elif isinstance(instr, instructions.InstructionCoprocessor0):
                    isLikelyHandwritten = True
                elif instr.isIType() and not instr.isFloatInstruction():
                    if instr.rs in (26, 27): # "$k0", "$k1"
                        isLikelyHandwritten = True
                    elif instr.rt in (26, 27): # "$k0", "$k1"
                        isLikelyHandwritten = True

            if instr.isBranch():
                branch = common.Utils.from2Complement(instr.immediate, 16) + 1
                if branch > farthestBranch:
                    # keep track of the farthest branch target
                    farthestBranch = branch
                if branch < 0:
                    if branch + index < 0:
                        # Whatever we are reading is not a valid instruction
                        break
                    # make sure to not branch outside of the current function
                    if not isLikelyHandwritten:
                        j = len(funcsStartsList) - 1
                        while j >= 0:
                            if index + branch < funcsStartsList[j]:
                                if common.GlobalConfig.TRUST_USER_FUNCTIONS or (common.GlobalConfig.DISASSEMBLE_RSP and self.isRsp):
                                    vram = self.getVramOffset(funcsStartsList[j]*4)
                                    if self.context.getFunction(vram) is not None:
                                        j -= 1
                                        continue
                                del funcsStartsList[j]
                                del unimplementedInstructionsFuncList[j-1]
                            else:
                                break
                            j -= 1

            if not (farthestBranch > 0):
                if instr.uniqueId == instructions.InstructionId.JR:
                    if instr.rs == 31: # $ra
                        functionEnded = True
                elif instr.uniqueId == instructions.InstructionId.J and (isLikelyHandwritten or (common.GlobalConfig.DISASSEMBLE_RSP and self.isRsp)):
                    functionEnded = True

            if self.vram is not None:
                if common.GlobalConfig.TRUST_USER_FUNCTIONS or (common.GlobalConfig.DISASSEMBLE_RSP and self.isRsp):
                    vram = self.getVramOffset(instructionOffset) + 8
                    funcContext = self.context.getFunction(vram)
                    if funcContext is not None:
                        if funcContext.isUserDeclared or (common.GlobalConfig.DISASSEMBLE_RSP and self.isRsp):
                            functionEnded = True

            if currentFunctionSym is not None:
                if currentFunctionSym.size > 4:
                    if instructionOffset + 8 == currentInstructionStart + currentFunctionSym.size:
                            functionEnded = True

            index += 1
            farthestBranch -= 1
            instructionOffset += 4

        unimplementedInstructionsFuncList.append(not isInstrImplemented)

        i = 0
        startsCount = len(funcsStartsList)
        for startIndex in range(startsCount):
            start = funcsStartsList[startIndex]
            hasUnimplementedIntrs = unimplementedInstructionsFuncList[startIndex]
            end = nInstr
            if startIndex + 1 < startsCount:
                end = funcsStartsList[startIndex+1]

            if start >= end:
                break

            funcName = f"func_{i}"
            if len(self.context.offsetSymbols[self.sectionType]) > 0:
                possibleFuncName = self.context.getOffsetSymbol(start*4, self.sectionType)
                if possibleFuncName is not None:
                    funcName = possibleFuncName.name

            vram = None
            if self.vram is not None:
                vram = self.getVramOffset(start*4)

                if common.GlobalConfig.DISASSEMBLE_UNKNOWN_INSTRUCTIONS or not hasUnimplementedIntrs:
                    funcSymbol = self.context.getFunction(vram)
                    if funcSymbol is None:
                        funcSymbol = self.context.addFunction(vram, None, isAutogenerated=True)
                    funcSymbol.isDefined = True
                else:
                    if vram in self.context.symbols:
                        self.context.symbols[vram].isDefined = True
                    elif common.GlobalConfig.ADD_NEW_SYMBOLS:
                        contextSym = self.context.addSymbol(vram, None)
                        contextSym.isAutogenerated = True
                        contextSym.isDefined = True

            func = symbols.SymbolFunction(self.context, self.inFileOffset + start*4, vram, funcName, instrsList[start:end])
            func.index = i
            func.pointersOffsets |= self.pointersOffsets
            func.hasUnimplementedIntrs = hasUnimplementedIntrs
            func.parent = self
            func.isRsp = self.isRsp
            func.analyze()
            self.symbolList.append(func)
            i += 1

    def printAnalyzisResults(self):
        super().printAnalyzisResults()
        if not common.GlobalConfig.PRINT_NEW_FILE_BOUNDARIES:
            return

        nBoundaries = len(self.fileBoundaries)
        if nBoundaries > 0:
            print(f"File {self.name}")
            print(f"Found {self.nFuncs} functions.")
            print(f"Found {nBoundaries} file boundaries.")

            print("\t offset, size, vram\t functions")

            for i in range(len(self.fileBoundaries)-1):
                start = self.fileBoundaries[i]
                end = self.fileBoundaries[i+1]

                functionsInBoundary = 0
                for func in self.symbolList:
                    funcOffset = func.inFileOffset - self.inFileOffset
                    if start <= funcOffset < end:
                        functionsInBoundary += 1
                fileVram = 0
                if self.vram is not None:
                    fileVram = start + self.vram
                print("\t", f"{start+self.commentOffset:06X}", f"{end-start:04X}", f"{fileVram:08X}", "\t functions:", functionsInBoundary)

            start = self.fileBoundaries[-1]
            end = self.sizew*4 + self.inFileOffset

            functionsInBoundary = 0
            for func in self.symbolList:
                if func.vram is not None and self.vram is not None:
                    funcOffset = func.vram - self.vram
                    if start <= funcOffset < end:
                        functionsInBoundary += 1
            fileVram = 0
            if self.vram is not None:
                fileVram = start + self.vram
            print("\t", f"{start+self.commentOffset:06X}", f"{end-start:04X}", f"{fileVram:08X}", "\t functions:", functionsInBoundary)

            print()
        return


    def compareToFile(self, other: FileBase):
        result = super().compareToFile(other)

        if isinstance(other, SectionText):
            result["text"] = {
                "diff_opcode": self.countDiffOpcodes(other),
                "same_opcode_same_args": self.countSameOpcodeButDifferentArguments(other),
            }

        return result

    def countDiffOpcodes(self, other: SectionText) -> int:
        result = 0
        for i in range(min(self.nFuncs, other.nFuncs)):
            func = self.symbolList[i]
            other_func = other.symbolList[i]
            assert isinstance(func, symbols.SymbolFunction)
            assert isinstance(other_func, symbols.SymbolFunction)
            result += func.countDiffOpcodes(other_func)
        return result

    def countSameOpcodeButDifferentArguments(self, other: SectionText) -> int:
        result = 0
        for i in range(min(self.nFuncs, other.nFuncs)):
            func = self.symbolList[i]
            other_func = other.symbolList[i]
            assert isinstance(func, symbols.SymbolFunction)
            assert isinstance(other_func, symbols.SymbolFunction)
            result += func.countSameOpcodeButDifferentArguments(other_func)
        return result

    def blankOutDifferences(self, other_file: FileBase) -> bool:
        if not common.GlobalConfig.REMOVE_POINTERS:
            return False

        if not isinstance(other_file, SectionText):
            return False

        was_updated = False
        for i in range(min(self.nFuncs, other_file.nFuncs)):
            func = self.symbolList[i]
            other_func = other_file.symbolList[i]
            assert isinstance(func, symbols.SymbolFunction)
            assert isinstance(other_func, symbols.SymbolFunction)
            was_updated = func.blankOutDifferences(other_func) or was_updated

        return was_updated

    def removePointers(self) -> bool:
        if not common.GlobalConfig.REMOVE_POINTERS:
            return False

        was_updated = False
        for func in self.symbolList:
            assert isinstance(func, symbols.SymbolFunction)
            was_updated = func.removePointers() or was_updated

        return was_updated

    def removeTrailingNops(self) -> bool:
        was_updated = False

        if self.nFuncs > 0:
            func = self.symbolList[-1]
            assert isinstance(func, symbols.SymbolFunction)
            func.removeTrailingNops()
            was_updated = True

        return was_updated
