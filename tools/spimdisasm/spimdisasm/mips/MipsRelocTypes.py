#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

import enum


class RelocTypes(enum.Enum):
    INVALID      = -1

    R_MIPS_32    = 2
    R_MIPS_26    = 4
    R_MIPS_HI16  = 5
    R_MIPS_LO16  = 6


    @staticmethod
    def fromValue(value: int) -> RelocTypes:
        if value == 2:
            return RelocTypes.R_MIPS_32
        if value == 4:
            return RelocTypes.R_MIPS_26
        if value == 5:
            return RelocTypes.R_MIPS_HI16
        if value == 6:
            return RelocTypes.R_MIPS_LO16
        return RelocTypes.INVALID
