#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

from .GlobalConfig import GlobalConfig
from .Context import Context, ContextSymbolBase
from .FileSectionType import FileSectionType


class ElementBase:
    """Represents the base class used for most file sections and symbols.
    """

    def __init__(self, context: Context, inFileOffset: int, vram: int|None, name: str, words: list[int], sectionType: FileSectionType):
        """Constructor

        Args:
            context (Context):
            inFileOffset (int): The offset of this element relative to the start of its file. It is also used to generate the first column of the disassembled line comment.
            vram (int | None): The VRAM address of this element or `None` if the VRAM is unknown.
            name (str): The name of this element.
            words (list[int]): A list of words (4 bytes) corresponding to this element.
            sectionType (FileSectionType): The section type this element corresponds to.
        """

        self.context: Context = context
        self.inFileOffset: int = inFileOffset
        self.vram: int|None = vram
        self.name: str = name
        self.words: list[int] = words
        self.sectionType: FileSectionType = sectionType

        self.commentOffset: int = 0
        "This value is added to the first column of the disassembled line comment, allowing to change this value without messing inFileOffset"

        self.index: int|None = None
        "The index of the current element inside its parent or `None` if the index is unknown"

        self.parent: ElementBase|None = None
        "For elements that are contained in other elements, like symbols inside of sections"


    @property
    def sizew(self) -> int:
        "The amount of words this element has"
        return len(self.words)

    @property
    def vramEnd(self) -> int|None:
        "The end of this element's VRAM or `None` if VRAM was not specified"
        if self.vram is None:
            return None
        return self.vram + self.sizew * 4


    def setVram(self, vram: int):
        self.vram = vram

    def setCommentOffset(self, commentOffset: int):
        self.commentOffset = commentOffset

    def getVramOffset(self, localOffset: int) -> int:
        if self.vram is None:
            return self.inFileOffset + localOffset
        return self.vram + localOffset
        # return self.vram + self.inFileOffset + localOffset


    def getLabelFromSymbol(self, sym: ContextSymbolBase|None) -> str:
        "Generates a glabel for the passed symbol, including an optional index value if it was set and it is enabled in the GlobalConfig"
        if sym is not None:
            label = sym.getSymbolLabel()
            if GlobalConfig.GLABEL_ASM_COUNT:
                if self.index is not None:
                    label += f" # {self.index}"
            label +=  GlobalConfig.LINE_ENDS
            return label
        return ""


    def analyze(self):
        """Scans the words of this element, gathering as much info as possible.

        This method should be called only once for each element.
        """
        pass


    def disassemble(self) -> str:
        """Produces a disassembly of this element.

        Elements assume the `analyze` method was already called at this point.

        This method can be called as many times as the user wants to.
        """
        return ""
