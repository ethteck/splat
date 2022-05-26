#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from ... import common

from .. import instructions

from . import SymbolText


class SymbolFunction(SymbolText):
    def __init__(self, context: common.Context, inFileOffset: int, vram: int|None, name: str, instrsList: list[instructions.InstructionBase]):
        super().__init__(context, inFileOffset, vram, name, list())
        self.instructions: list[instructions.InstructionBase] = list(instrsList)

        self.pointersRemoved: bool = False

        self.localLabels: dict[int, str] = dict()
        """Branch labels found on this function.

        The key is the offset relative to the start of the function and the value is the name of the label

        If VRAM is available, then it is preferred to use `context.getGenericLabel(self.vram + branch)` to get the name of a label instead.
        """

        # TODO: this needs a better name
        self.pointersPerInstruction: dict[int, int] = dict()
        self.constantsPerInstruction: dict[int, int] = dict()
        self.branchInstructions: list[int] = list()

        # key: %hi (lui) instruction offset, value: %lo instruction offset
        self.hiToLowDict: dict[int, int] = dict()
        # key: %lo instruction offset, value: %hi (lui) instruction offset
        self.lowToHiDict: dict[int, int] = dict()

        self.luiInstructions: dict[int, instructions.InstructionBase] = dict()
        self.nonPointerLuiSet: set[int] = set()
        self.gpInstructions: dict[int, instructions.InstructionBase] = dict()

        self.pointersOffsets: set[int] = set()
        self.referencedJumpTableOffsets: set[int] = set()

        self.referencedVRams: set[int] = set()
        self.referencedConstants: set[int] = set()

        self.hasUnimplementedIntrs: bool = False

        self.isRsp: bool = False

        self.isLikelyHandwritten: bool = False

    @property
    def nInstr(self) -> int:
        return len(self.instructions)

    @property
    def vramEnd(self) -> int|None:
        if self.vram is None:
            return None
        return self.vram + self.nInstr * 4


    def _printAnalisisDebugInfo_IterInfo(self, instr: instructions.InstructionBase, register1: int|None, register2: int|None, register3: int|None, currentVram: int, trackedRegisters: dict, registersValues: dict):
        if not common.GlobalConfig.PRINT_FUNCTION_ANALYSIS_DEBUG_INFO:
            return

        print("_printAnalisisDebugInfo_IterInfo")
        print()
        print(f"vram: {currentVram:X}")
        print(instr)
        if register1 is not None:
            print(register1, instr.getRegisterName(register1))
        if register2 is not None:
            print(register2, instr.getRegisterName(register2))
        if register3 is not None:
            print(register3, instr.getRegisterName(register3))
        print(trackedRegisters)
        print({instr.getRegisterName(x): y for x, y in trackedRegisters.items()})
        # _t is shorthand of temp
        print({instr.getRegisterName(register_t): f"{vram_t:X},{offset_t:X}" for register_t, (vram_t, offset_t) in registersValues.items()})
        print()

    def _printSymbolFinderDebugInfo_DelTrackedRegister(self, instr: instructions.InstructionBase, register: int, currentVram: int|None, trackedRegisters: dict):
        if not common.GlobalConfig.PRINT_SYMBOL_FINDER_DEBUG_INFO:
            return

        if currentVram is None:
            return

        print("_printSymbolFinderDebugInfo_DelTrackedRegister")
        print()
        print(f"vram: {currentVram:X}")
        print(instr)
        print(trackedRegisters)
        print(f"deleting {register} / {instr.getRegisterName(register)}")
        print()

    def _printSymbolFinderDebugInfo_UnpairedLuis(self):
        if not common.GlobalConfig.PRINT_UNPAIRED_LUIS_DEBUG_INFO:
            return

        firstNotePrinted = False

        for instructionOffset, luiInstr in self.luiInstructions.items():
            # inFileOffset = self.inFileOffset + instructionOffset
            currentVram = self.getVramOffset(instructionOffset)
            if instructionOffset in self.nonPointerLuiSet:
                continue
            if instructionOffset in self.constantsPerInstruction:
                # print(f"{currentVram:06X} ", end="")
                # print(f"C  {self.constantsPerInstruction[instructionOffset]:8X}", luiInstr)
                pass
            else:
                if common.GlobalConfig.SYMBOL_FINDER_FILTER_LOW_ADDRESSES and luiInstr.immediate < 0x4000: # filter out stuff that may not be a real symbol
                    continue
                if common.GlobalConfig.SYMBOL_FINDER_FILTER_HIGH_ADDRESSES and luiInstr.immediate >= 0xC000: # filter out stuff that may not be a real symbol
                    continue

                # print(f"{currentVram:06X} ", end="")
                # if instructionOffset in self.pointersPerInstruction:
                #     print(f"P  {self.pointersPerInstruction[instructionOffset]:8X}", luiInstr)
                # else:
                #     print("NO         ", luiInstr)

                if instructionOffset not in self.pointersPerInstruction:
                    if not firstNotePrinted:
                        print("_printSymbolFinderDebugInfo_UnpairedLuis")
                        print(f"func: {self.name}")
                        if self.vram is not None:
                            print(f"vram: {self.vram:08X}")
                        firstNotePrinted = True

                    print(f"{currentVram:06X} ", "NO         ", luiInstr)

        if firstNotePrinted:
            print()


    def _processBranch(self, instr: instructions.InstructionBase, instructionOffset: int, currentVram: int) -> None:
        if instr.uniqueId == instructions.InstructionId.J:
            targetBranchVram = instr.getInstrIndexAsVram()
            branch = instructionOffset + targetBranchVram - currentVram
        else:
            branch = instructionOffset + instr.getBranchOffset()
            targetBranchVram = self.getVramOffset(branch)

        self.referencedVRams.add(targetBranchVram)
        labelSym = self.context.getGenericLabel(targetBranchVram)
        if labelSym is None:
            labelSym = self.context.addBranchLabel(targetBranchVram, None, isAutogenerated=True)

        labelSym.referenceCounter += 1
        self.localLabels[branch] = labelSym.getName()
        self.branchInstructions.append(instructionOffset)

    def _processSymbol(self, luiInstr: instructions.InstructionBase|None, luiOffset: int|None, lowerInstr: instructions.InstructionBase, lowerOffset: int) -> int|None:
        # lui being None means this symbol is a $gp access
        assert ((luiInstr is None and luiOffset is None) or (luiInstr is not None and luiOffset is not None))

        if lowerOffset in self.pointersPerInstruction:
            # This %lo has been processed already
            return self.pointersPerInstruction[lowerOffset]

        if luiInstr is None and common.GlobalConfig.GP_VALUE is None:
            return None

        if luiInstr is not None:
            upperHalf = luiInstr.immediate << 16
        else:
            assert common.GlobalConfig.GP_VALUE is not None
            upperHalf = common.GlobalConfig.GP_VALUE

        lowerHalf = common.Utils.from2Complement(lowerInstr.immediate, 16)
        address = upperHalf + lowerHalf
        if address in self.context.bannedSymbols:
            return None

        # filter out stuff that may not be a real symbol
        filterOut = common.GlobalConfig.SYMBOL_FINDER_FILTER_LOW_ADDRESSES and upperHalf < 0x40000000
        filterOut |= common.GlobalConfig.SYMBOL_FINDER_FILTER_HIGH_ADDRESSES and upperHalf >= 0xC0000000
        if filterOut:
            if common.GlobalConfig.SYMBOL_FINDER_FILTERED_ADDRESSES_AS_CONSTANTS:
                # Let's pretend this value is a constant
                constant = address
                self.referencedConstants.add(constant)

                self.constantsPerInstruction[lowerOffset] = constant
                if luiOffset is not None:
                    self.constantsPerInstruction[luiOffset] = constant

                    self.hiToLowDict[luiOffset] = lowerOffset
                    self.lowToHiDict[lowerOffset] = luiOffset
            return None

        patchedAddress = address
        patch = self.context.getLoPatch(lowerInstr.vram)
        if patch is not None:
            patchedAddress = patch

        self.referencedVRams.add(patchedAddress)
        contextSym = self.context.getGenericSymbol(patchedAddress)
        if contextSym is None:
            if common.GlobalConfig.ADD_NEW_SYMBOLS:
                contextSym = self.context.addSymbol(patchedAddress, None, isAutogenerated=True)
                instrType = lowerInstr.mapInstrToType()
                if instrType is not None:
                    contextSym.setTypeIfUnset(instrType)
                contextSym.referenceCounter += 1
        else:
            contextSym.referenceCounter += 1

        if lowerOffset not in self.pointersPerInstruction:
            self.pointersPerInstruction[lowerOffset] = address
        if luiOffset is not None:
            if luiOffset not in self.pointersPerInstruction:
                self.pointersPerInstruction[luiOffset] = address

            self.hiToLowDict[luiOffset] = lowerOffset
            self.lowToHiDict[lowerOffset] = luiOffset
        else:
            self.gpInstructions[lowerOffset] = lowerInstr

        return address

    def _processConstant(self, luiInstr: instructions.InstructionBase, luiOffset: int, lowerInstr: instructions.InstructionBase, lowerOffset: int) -> int|None:
        upperHalf = luiInstr.immediate << 16
        lowerHalf = lowerInstr.immediate
        constant = upperHalf | lowerHalf

        self.referencedConstants.add(constant)

        self.constantsPerInstruction[lowerOffset] = constant
        self.constantsPerInstruction[luiOffset] = constant

        self.hiToLowDict[luiOffset] = lowerOffset
        self.lowToHiDict[lowerOffset] = luiOffset

        return constant

    def _removeRegisterFromTrackers(self, instr: instructions.InstructionBase, prevInstr: instructions.InstructionBase|None, currentVram: int|None, trackedRegisters: dict, trackedRegistersAll: dict, registersValues: dict, wasRegisterValuesUpdated: bool):
        shouldRemove = False
        register = 0

        if prevInstr is not None and prevInstr.isBranchLikely():
            return

        if not instr.isFloatInstruction():
            if instr.isRType() or (instr.isBranch() and isinstance(instr, instructions.InstructionNormal)):
                # $at is a one-use register
                at = -1
                if instr.rs == 1:
                    at = instr.rs
                elif instr.rt == 1:
                    at = instr.rt

                if at in trackedRegistersAll:
                    otherInstrIndex = trackedRegistersAll[at]
                    otherInstr = self.instructions[otherInstrIndex]
                    if otherInstr.uniqueId == instructions.InstructionId.LUI:
                        self.nonPointerLuiSet.add(otherInstrIndex*4)
                    shouldRemove = True
                    register = at

            if instr.uniqueId != instructions.InstructionId.LUI and instr.modifiesRt():
                shouldRemove = True
                register = instr.rt

            if instr.modifiesRd():
                shouldRemove = True
                register = instr.rd

                # Usually array offsets use an ADDU to add the index of the array
                if instr.uniqueId == instructions.InstructionId.ADDU:
                    if instr.rd != instr.rs and instr.rd != instr.rt:
                        shouldRemove = True
                    else:
                        shouldRemove = False

        else:
            if instr.uniqueId in (instructions.InstructionId.MTC1, instructions.InstructionId.DMTC1, instructions.InstructionId.CTC1):
                # IDO usually use a register as a temp when loading a constant value
                # into the float coprocessor, after that IDO never re-uses the value
                # in that register for anything else
                shouldRemove = True
                register = instr.rt

        if shouldRemove:
            if register in trackedRegisters:
                self._printSymbolFinderDebugInfo_DelTrackedRegister(instr, register, currentVram, trackedRegisters)
                del trackedRegisters[register]
            if register in trackedRegistersAll:
                del trackedRegistersAll[register]
            if not wasRegisterValuesUpdated:
                if register in registersValues:
                    del registersValues[register]

    def _tryToSetSymbolType(self, instr: instructions.InstructionBase, instructionOffset: int, registersValues: dict[int, tuple[int, int]]):
        instrType = instr.mapInstrToType()
        if instrType is None or instr.rs not in registersValues:
            return

        address, loInstructionOffset = registersValues[instr.rs]
        if instructionOffset != loInstructionOffset:
            loInstr = self.instructions[loInstructionOffset//4]
            if loInstr.uniqueId != instructions.InstructionId.ADDIU:
                # if the instruction used to load this value wasn't an ADDIU
                # then the register has the value pointed by this address
                return

        contextSym = self.context.getSymbol(address, tryPlusOffset=False)
        if contextSym is not None:
            contextSym.setTypeIfUnset(instrType)

    def _symbolFinder(self, instr: instructions.InstructionBase, prevInstr: instructions.InstructionBase, instructionOffset: int, trackedRegisters: dict[int, int], trackedRegistersAll: dict[int, int], registersValues: dict[int, tuple[int, int]]):
        if instr.uniqueId == instructions.InstructionId.LUI:
            if not prevInstr.isBranchLikely():
                # If the previous instructions is a branch likely, then nulify
                # the effects of this instruction for future analysis
                trackedRegisters[instr.rt] = instructionOffset//4
            trackedRegistersAll[instr.rt] = instructionOffset//4
            return False

        if instr.uniqueId == instructions.InstructionId.ORI:
            # Constants
            rs = instr.rs
            if rs in trackedRegistersAll:
                luiOffset = trackedRegistersAll[rs] * 4
                luiInstr = self.instructions[luiOffset//4]
                constant = self._processConstant(luiInstr, luiOffset, instr, instructionOffset)
                if constant is not None:
                    registersValues[instr.rt] = (constant, instructionOffset)
                    return True
            return False

        if instr.uniqueId not in (instructions.InstructionId.ANDI, instructions.InstructionId.XORI, instructions.InstructionId.CACHE, instructions.InstructionId.SLTI, instructions.InstructionId.SLTIU):
            rs = instr.rs
            if rs in trackedRegisters:
                luiInstr = self.instructions[trackedRegisters[rs]]
                address = self._processSymbol(luiInstr, trackedRegisters[rs]*4, instr, instructionOffset)
                if address is not None:
                    registersValues[instr.rt] = (address, instructionOffset)
                    return True
            elif rs == 28: # $gp
                address = self._processSymbol(None, None, instr, instructionOffset)
                if address is not None:
                    registersValues[instr.rt] = (address, instructionOffset)
                    return True

        return False


    def _lookAheadSymbolFinder(self, instr: instructions.InstructionBase, instructionOffset: int, trackedRegistersOriginal: dict[int, int], trackedRegistersAllOriginal: dict[int, int], registersValuesOriginal: dict[int, tuple[int, int]]):
        trackedRegisters = dict(trackedRegistersOriginal)
        trackedRegistersAll = dict(trackedRegistersAllOriginal)
        registersValues = dict(registersValuesOriginal)

        lastInstr = self.instructions[instructionOffset//4 - 1]
        if not lastInstr.isBranch():
            return

        branchOffset = lastInstr.getBranchOffset() - 4
        branch = instructionOffset + branchOffset
        # don't check negative branches (loops) or branches outside this function
        if branchOffset <= 0 or branch//4 >= len(self.instructions):
            return

        self._removeRegisterFromTrackers(instr, None, None, trackedRegisters, trackedRegistersAll, registersValues, False)

        pairedLoFound = False
        i = 0
        while True:
            if branch//4 >= len(self.instructions):
                return

            if i >= 5:
                if instr.uniqueId == instructions.InstructionId.LUI:
                    # Continue searching until we find the corresponding lo instruction for this LUI
                    if pairedLoFound:
                        return
                else:
                    # Only check the 5 next instructions in the target branch for non LUI instructions
                    return

            wasRegisterValuesUpdated = False
            prevTargetInstr = self.instructions[branch//4 - 1]
            targetInstr = self.instructions[branch//4]

            # Usually array offsets use an ADDU to add the index of the array
            if targetInstr.uniqueId == instructions.InstructionId.ADDU and not prevTargetInstr.isBranchLikely():
                if targetInstr.rd == targetInstr.rs or targetInstr.rd == targetInstr.rt:
                    branch += 4
                    i += 1
                    continue

            if targetInstr.isIType():
                if self._symbolFinder(targetInstr, prevTargetInstr, branch, trackedRegisters, trackedRegistersAll, registersValues):
                    wasRegisterValuesUpdated = True
                    if instr.uniqueId == instructions.InstructionId.LUI and targetInstr.rs == instr.rt:
                        pairedLoFound = True
                self._tryToSetSymbolType(targetInstr, branch, registersValues)

            if prevTargetInstr.uniqueId == instructions.InstructionId.B or (prevTargetInstr.uniqueId == instructions.InstructionId.BEQ and prevTargetInstr.rt == 0 and prevTargetInstr.rs == 0):
                # TODO: Consider following branches
                # self._lookAheadSymbolFinder(targetInstr, branch, trackedRegisters, trackedRegistersAll, registersValues)
                return
            if prevTargetInstr.isJType():
                return
            if prevTargetInstr.isJump():
                return

            self._removeRegisterFromTrackers(targetInstr, prevTargetInstr, None, trackedRegisters, trackedRegistersAll, registersValues, wasRegisterValuesUpdated)

            branch += 4
            i += 1

    def _processElfRelocSymbols(self):
        if len(self.context.relocSymbols[common.FileSectionType.Text]) == 0:
            return

        # Process reloc symbols (probably from a .elf file)
        instructionOffset = 0
        inFileOffset = self.inFileOffset
        for instr in self.instructions:
            relocSymbol = self.context.getRelocSymbol(inFileOffset, common.FileSectionType.Text)
            if relocSymbol is not None:
                if relocSymbol.name.startswith("."):
                    sectType = common.FileSectionType.fromStr(relocSymbol.name)

                    if instructionOffset in self.pointersPerInstruction:
                        if instructionOffset in self.referencedJumpTableOffsets:
                            # Jump tables
                            addressOffset = self.pointersPerInstruction[instructionOffset]
                            if relocSymbol.name != ".rodata":
                                common.Utils.eprint(f"Warning. Jumptable referenced in reloc does not have '.rodata' as its name")
                            contextOffsetSym = self.context.addOffsetJumpTable(addressOffset, sectType)
                            contextOffsetSym.referenceCounter += 1
                            relocSymbol.name = contextOffsetSym.name
                            self.pointersPerInstruction[instructionOffset] = 0
                            if instructionOffset in self.lowToHiDict:
                                luiOffset = self.lowToHiDict[instructionOffset]
                                otherReloc = self.context.getRelocSymbol(self.inFileOffset+luiOffset, common.FileSectionType.Text)
                                if otherReloc is not None:
                                    otherReloc.name = relocSymbol.name
                                    self.pointersPerInstruction[luiOffset] = 0
                        else:
                            addressOffset = self.pointersPerInstruction[instructionOffset]
                            relocName = f"{relocSymbol.name}_{addressOffset:06X}"
                            # print(relocName, addressOffset, instr)
                            contextOffsetSym = common.ContextOffsetSymbol(addressOffset, relocName, sectType)
                            self.context.offsetSymbols[sectType][addressOffset] = contextOffsetSym
                            relocSymbol.name = relocName
                            self.pointersPerInstruction[instructionOffset] = 0
            inFileOffset += 4
            instructionOffset += 4


    def analyze(self):
        if not common.GlobalConfig.DISASSEMBLE_UNKNOWN_INSTRUCTIONS and self.hasUnimplementedIntrs:
            if self.vram is not None:
                offset = 0
                for instr in self.instructions:
                    currentVram = self.getVramOffset(offset)
                    contextSym = self.context.getSymbol(currentVram, False)
                    if contextSym is not None:
                        contextSym.isDefined = True

                    offset += 4
            return

        # Search for LUI instructions first
        instructionOffset = 0
        for instr in self.instructions:
            if instr.uniqueId == instructions.InstructionId.LUI:
                self.luiInstructions[instructionOffset] = instr
            if instructionOffset > 0:
                prevInstr = self.instructions[instructionOffset//4 - 1]
                if prevInstr.isJType() or prevInstr.isJump():
                    self.nonPointerLuiSet.add(instructionOffset)
            instructionOffset += 4

        trackedRegisters: dict[int, int] = dict()
        trackedRegistersAll: dict[int, int] = dict()
        # key: register, value: (vram, offset of instruction which set this value)
        registersValues: dict[int, tuple[int, int]] = dict()

        instructionOffset = 0
        for instr in self.instructions:
            currentVram = self.getVramOffset(instructionOffset)
            wasRegisterValuesUpdated = False
            self.isLikelyHandwritten |= instr.uniqueId in instructions.InstructionsNotEmitedByIDO
            prevInstr = self.instructions[instructionOffset//4 - 1]

            self._printAnalisisDebugInfo_IterInfo(instr, instr.rs, instr.rt, instr.rd, currentVram, trackedRegisters, registersValues)

            if not self.isLikelyHandwritten:
                self.isLikelyHandwritten = instr.isLikelyHandwritten()

            if not common.GlobalConfig.DISASSEMBLE_UNKNOWN_INSTRUCTIONS and not instr.isImplemented():
                # Abort analysis
                self.hasUnimplementedIntrs = True
                return

            if instr.isBranch() or (common.GlobalConfig.TREAT_J_AS_UNCONDITIONAL_BRANCH and instr.uniqueId == instructions.InstructionId.J):
                self._processBranch(instr, instructionOffset, currentVram)

            elif instr.isJType():
                target = instr.getInstrIndexAsVram()
                if not self.isRsp:
                    if target >= 0x84000000:
                        # RSP address space?
                        self.isLikelyHandwritten = True
                funcSym = self.context.getFunction(target)
                if funcSym is None:
                    if instr.uniqueId == instructions.InstructionId.J and not self.isRsp:
                        funcSym = self.context.addFakeFunction(target, f".L{target:08X}", isAutogenerated=True)
                    else:
                        funcSym = self.context.addFunction(target, f"func_{target:08X}", isAutogenerated=True)
                funcSym.referenceCounter += 1
                self.pointersPerInstruction[instructionOffset] = target

            # symbol finder
            elif instr.isIType():
                if self._symbolFinder(instr, prevInstr, instructionOffset, trackedRegisters, trackedRegistersAll, registersValues):
                    wasRegisterValuesUpdated = True
                self._tryToSetSymbolType(instr, instructionOffset, registersValues)

            elif instr.uniqueId == instructions.InstructionId.JR:
                rs = instr.rs
                if rs != 31: # $ra
                    if rs in registersValues:
                        # print(instructionOffset, rs, trackedRegisters, trackedRegistersAll, registersValues, self.pointersPerInstruction)
                        address, jmptblSeterOffset = registersValues[rs]
                        self.referencedJumpTableOffsets.add(jmptblSeterOffset)
                        self.referencedVRams.add(address)
                        self.context.addJumpTable(address, isAutogenerated=True)

            self._removeRegisterFromTrackers(instr, prevInstr, currentVram, trackedRegisters, trackedRegistersAll, registersValues, wasRegisterValuesUpdated)

            # look-ahead symbol finder
            self._lookAheadSymbolFinder(instr, instructionOffset, trackedRegisters, trackedRegistersAll, registersValues)

            instructionOffset += 4

        self._printSymbolFinderDebugInfo_UnpairedLuis()

        self._processElfRelocSymbols()


    def countDiffOpcodes(self, other: SymbolFunction) -> int:
        result = 0
        for i in range(min(self.nInstr, other.nInstr)):
            if not self.instructions[i].sameOpcode(other.instructions[i]):
                result += 1
        return result

    def countSameOpcodeButDifferentArguments(self, other: SymbolFunction) -> int:
        result = 0
        for i in range(min(self.nInstr, other.nInstr)):
            instr1 = self.instructions[i]
            instr2 = other.instructions[i]
            if instr1.sameOpcodeButDifferentArguments(instr2):
                result += 1
        return result

    def blankOutDifferences(self, other_func: SymbolFunction) -> bool:
        if not common.GlobalConfig.REMOVE_POINTERS:
            return False

        was_updated = False

        for i in range(min(self.nInstr, other_func.nInstr)):
            instr1 = self.instructions[i]
            instr2 = other_func.instructions[i]
            if instr1.sameOpcodeButDifferentArguments(instr2):
                instr1.blankOut()
                instr2.blankOut()
                was_updated = True

        return was_updated

    def removePointers(self) -> bool:
        if not common.GlobalConfig.REMOVE_POINTERS:
            return False

        was_updated = False

        for instructionOffset in self.pointersPerInstruction:
            self.instructions[instructionOffset//4].blankOut()
        was_updated = len(self.pointersPerInstruction) > 0 or was_updated

        for fileOffset in self.pointersOffsets:
            index = (fileOffset - self.inFileOffset)//4
            if index < 0:
                continue
            if index >= self.nInstr:
                continue
            self.instructions[index].blankOut()

        if common.GlobalConfig.IGNORE_BRANCHES:
            for instructionOffset in self.branchInstructions:
                self.instructions[instructionOffset//4].blankOut()
            was_updated = len(self.branchInstructions) > 0 or was_updated

        self.pointersRemoved = True

        return was_updated

    def removeTrailingNops(self) -> bool:
        was_updated = False
        first_nop = self.nInstr

        for i in range(self.nInstr-1, 0-1, -1):
            instr = self.instructions[i]
            if instr.uniqueId != instructions.InstructionId.NOP:
                if instr.uniqueId == instructions.InstructionId.JR and instr.rs == 31: #$ra
                    first_nop += 1
                break
            first_nop = i

        if first_nop < self.nInstr:
            was_updated = True
            del self.instructions[first_nop:]
        return was_updated


    def generateHiLoStr(self, instr: instructions.InstructionBase, symName: str) -> str:
        if instr.uniqueId == instructions.InstructionId.LUI:
            return f"%hi({symName})"

        # $gp
        if instr.rs == 28:
            # $gp
            if instr.rt != 28 or not instr.modifiesRt():
                return f"%gp_rel({symName})"

        return f"%lo({symName})"

    def getImmOverrideForInstruction(self, instr: instructions.InstructionBase, instructionOffset: int) -> str|None:
        if len(self.context.relocSymbols[self.sectionType]) > 0:
            # Check possible symbols using reloc information (probably from a .o elf file)
            possibleImmOverride = self.context.getRelocSymbol(self.inFileOffset + instructionOffset, self.sectionType)
            if possibleImmOverride is not None:
                auxOverride = possibleImmOverride.name
                if instr.isIType():
                    if instructionOffset in self.pointersPerInstruction:
                        addressOffset = self.pointersPerInstruction[instructionOffset]
                        auxOverride = possibleImmOverride.getNamePlusOffset(addressOffset)

                    auxOverride = self.generateHiLoStr(instr, auxOverride)
                return auxOverride

        if instr.isBranch():
            if not common.GlobalConfig.IGNORE_BRANCHES:
                if instr.uniqueId == instructions.InstructionId.J:
                    targetBranchVram = instr.getInstrIndexAsVram()
                    branch = instructionOffset + targetBranchVram - self.getVramOffset(instructionOffset)
                else:
                    branch = instructionOffset + instr.getBranchOffset()
                    targetBranchVram = self.getVramOffset(branch)
                labelSymbol = self.context.getGenericLabel(targetBranchVram)
                if labelSymbol is not None:
                    return labelSymbol.name

                # in case we don't have access to vram or this label was not in context
                if branch in self.localLabels:
                    return self.localLabels[branch]

        elif instr.isIType():
            if not self.pointersRemoved and instructionOffset in self.pointersPerInstruction:
                address = self.pointersPerInstruction[instructionOffset]

                instrVram = instr.vram
                if instr.uniqueId == instructions.InstructionId.LUI:
                    # we need to get the address of the lo instruction to get the patch
                    if instructionOffset in self.hiToLowDict:
                        loInstr = self.instructions[self.hiToLowDict[instructionOffset] // 4]
                        instrVram = loInstr.vram

                # Check for user-defined symbol patches
                patchedAddress = self.context.getLoPatch(instrVram)
                if patchedAddress is not None:
                    symbol = self.context.getGenericSymbol(patchedAddress, True, False)
                else:
                    symbol = self.context.getGenericSymbol(address, True)

                if symbol is not None:
                    return self.generateHiLoStr(instr, symbol.getSymbolPlusOffset(address))

            elif instructionOffset in self.constantsPerInstruction:
                constant = self.constantsPerInstruction[instructionOffset]

                symbol = self.context.getConstant(constant)
                if symbol is not None:
                    return self.generateHiLoStr(instr, symbol.name)

                if instr.uniqueId == instructions.InstructionId.LUI:
                    loInstr = self.instructions[self.hiToLowDict[instructionOffset] // 4]
                    if loInstr.uniqueId == instructions.InstructionId.ORI:
                        return f"(0x{constant:X} >> 16)"
                elif instr.uniqueId == instructions.InstructionId.ORI:
                    return f"(0x{constant:X} & 0xFFFF)"
                return self.generateHiLoStr(instr, f"0x{constant:X}")

            elif instr.uniqueId == instructions.InstructionId.LUI:
                return f"(0x{instr.immediate<<16:X} >> 16)"

        elif instr.isJType():
            possibleOverride = self.context.getAnySymbol(instr.getInstrIndexAsVram())
            if possibleOverride is not None:
                return possibleOverride.name

        return None

    def getLabelForOffset(self, instructionOffset: int) -> str:
        if not common.GlobalConfig.IGNORE_BRANCHES and instructionOffset != 0:
            # Skip over this function to avoid duplication

            currentVram = self.getVramOffset(instructionOffset)
            labelSym = self.context.getGenericLabel(currentVram)
            if labelSym is None and len(self.context.offsetJumpTablesLabels) > 0:
                labelSym = self.context.getOffsetGenericLabel(self.inFileOffset+instructionOffset, common.FileSectionType.Text)
            if labelSym is None and len(self.context.offsetSymbols[self.sectionType]) > 0:
                labelSym = self.context.getOffsetSymbol(self.inFileOffset+instructionOffset, common.FileSectionType.Text)

            if labelSym is not None:
                labelSym.isDefined = True
                labelSym.sectionType = self.sectionType
                if labelSym.type == common.SymbolSpecialType.function or labelSym.type == common.SymbolSpecialType.jumptablelabel:
                    return labelSym.getSymbolLabel() + common.GlobalConfig.LINE_ENDS
                return labelSym.getName() + ":" + common.GlobalConfig.LINE_ENDS

            if instructionOffset in self.localLabels:
                return self.localLabels[instructionOffset] + ":" + common.GlobalConfig.LINE_ENDS
        return ""


    def disassemble(self) -> str:
        output = ""

        if not common.GlobalConfig.DISASSEMBLE_UNKNOWN_INSTRUCTIONS:
            if self.hasUnimplementedIntrs:
                return self.disassembleAsData()

        if self.isLikelyHandwritten:
            output += "/* Handwritten function */" + common.GlobalConfig.LINE_ENDS

        output += self.getLabel()

        wasLastInstABranch = False
        instructionOffset = 0
        for instr in self.instructions:
            immOverride = self.getImmOverrideForInstruction(instr, instructionOffset)
            comment = self.generateAsmLineComment(instructionOffset, instr.instr)

            if wasLastInstABranch:
                instr.extraLjustWidthOpcode -= 1
                comment += " "

            line = instr.disassemble(immOverride)

            if wasLastInstABranch:
                instr.extraLjustWidthOpcode += 1

            label = self.getLabelForOffset(instructionOffset)
            output += f"{label}{comment}  {line}" + common.GlobalConfig.LINE_ENDS

            wasLastInstABranch = instr.isBranch() or instr.isJump()
            instructionOffset += 4

        if common.GlobalConfig.ASM_TEXT_END_LABEL:
            output += f"{common.GlobalConfig.ASM_TEXT_END_LABEL} {self.name}" + common.GlobalConfig.LINE_ENDS

        return output

    def disassembleAsData(self) -> str:
        self.words = [instr.instr for instr in self.instructions]
        return super().disassembleAsData()
