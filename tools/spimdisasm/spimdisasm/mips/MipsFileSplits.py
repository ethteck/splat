#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from .. import common

from . import sections
from . import FilesHandlers

from . import FileBase, createEmptyFile


class FileSplits(FileBase):
    def __init__(self, context: common.Context, vram: int|None, filename: str, array_of_bytes: bytearray, splitsData: common.FileSplitFormat | None = None, relocSection: sections.SectionRelocZ64|None = None):
        super().__init__(context, vram, filename, array_of_bytes, common.FileSectionType.Unknown)

        self.sectionsDict: dict[common.FileSectionType, dict[str, sections.SectionBase]] = {
            common.FileSectionType.Text: dict(),
            common.FileSectionType.Data: dict(),
            common.FileSectionType.Rodata: dict(),
            common.FileSectionType.Bss: dict(),
            common.FileSectionType.Reloc: dict(),
        }

        self.splitsDataList: list[common.FileSplitEntry] = []

        if relocSection is not None:
            relocSection.parent = self
            if relocSection.vram is None:
                relocSection.vram = self.vram
                if self.vram is not None:
                    relocStart = relocSection.textSize + relocSection.dataSize + relocSection.rodataSize
                    if relocSection.differentSegment:
                        relocStart += relocSection.bssSize
                    relocSection.vram = self.vram + relocStart
            self.sectionsDict[common.FileSectionType.Reloc][filename] = relocSection

        if splitsData is None and relocSection is None:
            self.sectionsDict[common.FileSectionType.Text][filename] = sections.SectionText(context, vram, filename, array_of_bytes)
        elif splitsData is not None and len(splitsData) > 0:
            for splitEntry in splitsData:
                self.splitsDataList.append(splitEntry)
        elif relocSection is not None:
            vram = self.vram

            start = 0
            end = 0
            for i in range(len(common.FileSections_ListBasic)):
                sectionType = common.FileSections_ListBasic[i]
                sectionSize = relocSection.sectionSizes[sectionType]

                if i != 0:
                    start += relocSection.sectionSizes[common.FileSections_ListBasic[i-1]]
                end += relocSection.sectionSizes[sectionType]

                if sectionType == common.FileSectionType.Bss:
                    # bss is after reloc when the relocation is on the same segment
                    if not relocSection.differentSegment:
                        start += relocSection.sizew * 4
                        end += relocSection.sizew * 4

                if sectionSize == 0:
                    # There's no need to disassemble empty sections
                    continue

                if self.vram is not None:
                    vram = self.vram + start
                splitEntry = common.FileSplitEntry(start, vram, filename, sectionType, end, False, False)
                self.splitsDataList.append(splitEntry)


        for splitEntry in self.splitsDataList:
            if self.vram is None:
                self.vram = splitEntry.vram

            f = FilesHandlers.createSectionFromSplitEntry(splitEntry, array_of_bytes, splitEntry.fileName, context)
            f.parent = self
            f.setCommentOffset(splitEntry.offset)

            self.sectionsDict[splitEntry.section][splitEntry.fileName] = f

    @property
    def nFuncs(self) -> int:
        nFuncs = 0
        for f in self.sectionsDict[common.FileSectionType.Text].values():
            assert(isinstance(f, sections.SectionText))
            text: sections.SectionText = f
            nFuncs += text.nFuncs
        return nFuncs

    def setVRamStart(self, vram: int):
        super().setVram(vram)
        for sectDict in self.sectionsDict.values():
            for section in sectDict.values():
                section.setVram(vram)

    def getHash(self) -> str:
        words = list()
        for sectDict in self.sectionsDict.values():
            for section in sectDict.values():
                words += section.words
        buffer = bytearray(4*len(words))
        common.Utils.beWordsToBytes(words, buffer)
        return common.Utils.getStrHash(buffer)

    def analyze(self):
        for filename, relocSection in self.sectionsDict[common.FileSectionType.Reloc].items():
            assert isinstance(relocSection, sections.SectionRelocZ64)
            for entry in relocSection.entries:
                sectionType = entry.getSectionType()
                if entry.reloc == 0:
                    continue

                for subFile in self.sectionsDict[sectionType].values():
                    subFile.pointersOffsets.add(entry.offset)

        for sectDict in self.sectionsDict.values():
            for section in sectDict.values():
                section.analyze()

    def compareToFile(self, other_file: FileBase):
        if isinstance(other_file, FileSplits):
            filesections: dict[common.FileSectionType, dict] = {
                common.FileSectionType.Text: dict(),
                common.FileSectionType.Data: dict(),
                common.FileSectionType.Rodata: dict(),
                common.FileSectionType.Bss: dict(),
                common.FileSectionType.Reloc: dict(),
            }

            for sectionType in common.FileSections_ListAll:
                for section_name, section in self.sectionsDict[sectionType].items():
                    if section_name in other_file.sectionsDict[sectionType]:
                        other_section = other_file.sectionsDict[sectionType][section_name]
                        filesections[sectionType][section_name] = section.compareToFile(other_section)
                    else:
                        filesections[sectionType][section_name] = section.compareToFile(createEmptyFile())
                for section_name, other_section in other_file.sectionsDict[sectionType].items():
                    if section_name in self.sectionsDict[sectionType]:
                        section = self.sectionsDict[sectionType][section_name]
                        if section_name not in filesections[sectionType]:
                            filesections[sectionType][section_name] = section.compareToFile(other_section)
                    else:
                        filesections[sectionType][section_name] = createEmptyFile().compareToFile(other_section)

            return {"filesections": filesections}

        return super().compareToFile(other_file)

    def blankOutDifferences(self, other_file: FileBase) -> bool:
        if not common.GlobalConfig.REMOVE_POINTERS:
            return False

        if not isinstance(other_file, FileSplits):
            return False

        was_updated = False
        for sectionType in common.FileSections_ListAll:
            for section_name, section in self.sectionsDict[sectionType].items():
                if section_name in other_file.sectionsDict[sectionType]:
                    other_section = other_file.sectionsDict[sectionType][section_name]
                    was_updated = section.blankOutDifferences(other_section) or was_updated
            for section_name, other_section in other_file.sectionsDict[sectionType].items():
                if section_name in self.sectionsDict[sectionType]:
                    section = self.sectionsDict[sectionType][section_name]
                    was_updated = section.blankOutDifferences(other_section) or was_updated

        return was_updated

    def removePointers(self) -> bool:
        if not common.GlobalConfig.REMOVE_POINTERS:
            return False

        was_updated = False
        for sectDict in self.sectionsDict.values():
            for section in sectDict.values():
                was_updated = section.removePointers() or was_updated

        return was_updated

    def saveToFile(self, filepath: str):
        for sectDict in self.sectionsDict.values():
            for name, section in sectDict.items():
                if name != "" and not filepath.endswith("/"):
                    name = " " + name
                section.saveToFile(filepath + name)
