#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

import dataclasses
import enum


@enum.unique
class InstructionId(enum.Enum):
    INVALID   = -1

    SLL       = enum.auto() # Shift word Left Logical

    SRL       = enum.auto() # Shift word Right Logical
    SRA       = enum.auto() # Shift word Right Arithmetic
    SLLV      = enum.auto() # Shift word Left Logical Variable

    SRLV      = enum.auto() # Shift word Right Logical Variable
    SRAV      = enum.auto() # Shift word Right Arithmetic Variable

    JR        = enum.auto() # Jump Register
    JALR      = enum.auto() # Jump And Link Register
    JALR_RD   = enum.auto() # Jump And Link Register # Special case for rd != 31
    MOVZ      = enum.auto() # MOVe conditional on Zero
    MOVN      = enum.auto() # MOVe conditional on Not zero
    SYSCALL   = enum.auto() # SYStem CALL
    BREAK     = enum.auto() # Break

    SYNC      = enum.auto() # Sync

    MFHI      = enum.auto() # Move From HI register
    MTHI      = enum.auto() # Move To HI register
    MFLO      = enum.auto() # Move From LO register
    MTLO      = enum.auto() # Move To LO register
    DSLLV     = enum.auto() # Doubleword Shift Left Logical Variable

    DSRLV     = enum.auto() # Doubleword Shift Right Logical Variable
    DSRAV     = enum.auto() # Doubleword Shift Right Arithmetic Variable

    MULT      = enum.auto() # MULTtiply word
    MULTU     = enum.auto() # MULTtiply Unsigned word
    DIV       = enum.auto() # DIVide word
    DIVU      = enum.auto() # DIVide Unsigned word
    DMULT     = enum.auto() # Doubleword MULTiply
    DMULTU    = enum.auto() # Doubleword MULTiply Unsigned
    DDIV      = enum.auto() # Doubleword DIVide
    DDIVU     = enum.auto() # Doubleword DIVide Unsigned

    ADD       = enum.auto() # ADD word
    ADDU      = enum.auto() # ADD Unsigned word
    SUB       = enum.auto() # Subtract word
    SUBU      = enum.auto() # SUBtract Unsigned word
    AND       = enum.auto() # AND
    OR        = enum.auto() # OR
    XOR       = enum.auto() # eXclusive OR
    NOR       = enum.auto() # Not OR

    SLT       = enum.auto() # Set on Less Than
    SLTU      = enum.auto() # Set on Less Than Unsigned
    DADD      = enum.auto() # Doubleword Add
    DADDU     = enum.auto() # Doubleword Add Unsigned
    DSUB      = enum.auto() # Doubleword SUBtract
    DSUBU     = enum.auto() # Doubleword SUBtract Unsigned

    TGE       = enum.auto() # Trap if Greater or Equal
    TGEU      = enum.auto() # Trap if Greater or Equal Unsigned
    TLT       = enum.auto() # Trap if Less Than
    TLTU      = enum.auto() # Trap if Less Than Unsigned
    TEQ       = enum.auto() # Trap if EQual

    TNE       = enum.auto() # Trap if Not Equal

    DSLL      = enum.auto() # Doubleword Shift Left Logical

    DSRL      = enum.auto() # Doubleword Shift Right Logical
    DSRA      = enum.auto() # Doubleword Shift Right Arithmetic
    DSLL32    = enum.auto() # Doubleword Shift Left Logical plus 32

    DSRL32    = enum.auto() # Doubleword Shift Right Logical plus 32
    DSRA32    = enum.auto() # Doubleword Shift Right Arithmetic plus 32

    BLTZ      = enum.auto() # Branch on Less Than Zero
    BGEZ      = enum.auto() # Branch on Greater than or Equal to Zero
    BLTZL     = enum.auto() # Branch on Less Than Zero Likely
    BGEZL     = enum.auto() # Branch on Greater than or Equal to Zero Likely

    TGEI      = enum.auto()
    TGEIU     = enum.auto()
    TLTI      = enum.auto()
    TLTIU     = enum.auto()

    BLTZAL    = enum.auto()
    BGEZAL    = enum.auto()
    BLTZALL   = enum.auto()
    BGEZALL   = enum.auto()

    TEQI      = enum.auto()
    TNEI      = enum.auto()

    J         = enum.auto() # Jump
    JAL       = enum.auto() # Jump And Link
    BEQ       = enum.auto() # Branch on EQual
    BNE       = enum.auto() # Branch on Not Equal
    BLEZ      = enum.auto() # Branch on Less than or Equal to Zero
    BGTZ      = enum.auto() # Branch on Greater Than Zero

    ADDI      = enum.auto() # Add Immediate
    ADDIU     = enum.auto() # Add Immediate Unsigned Word
    SLTI      = enum.auto() # Set on Less Than Immediate
    SLTIU     = enum.auto() # Set on Less Than Immediate Unsigned
    ANDI      = enum.auto() # And Immediate
    ORI       = enum.auto() # Or Immediate
    XORI      = enum.auto() # eXclusive OR Immediate
    LUI       = enum.auto() # Load Upper Immediate

    MFC0      = enum.auto() # Move word From CP0
    DMFC0     = enum.auto() # Doubleword Move From CP0
    CFC0      = enum.auto() # Move control word From CP0

    MTC0      = enum.auto() # Move word to CP0
    DMTC0     = enum.auto() # Doubleword Move To CP0
    CTC0      = enum.auto() # Move control word To CP0

    TLBR      = enum.auto() # Read Indexed TLB Entry
    TLBWI     = enum.auto() # Write Indexed TLB Entry
    TLBWR     = enum.auto() # Write Random TLB Entry
    TLBP      = enum.auto() # Probe TLB for Matching Entry
    ERET      = enum.auto() # Return from Exception

    BC0T      = enum.auto() # Branch on FP True
    BC0F      = enum.auto() # Branch on FP False
    BC0TL     = enum.auto() # Branch on FP True Likely
    BC0FL     = enum.auto() # Branch on FP False Likely

    MFC1      = enum.auto() # Move Word From Floating-Point
    DMFC1     = enum.auto() # Doubleword Move From Floating-Point
    CFC1      = enum.auto() # Move Control Word from Floating-Point

    MTC1      = enum.auto() # Move Word to Floating-Point
    DMTC1     = enum.auto() # Doubleword Move To Floating-Point
    CTC1      = enum.auto() # Move Control Word to Floating-Point

    BC1F      = enum.auto()
    BC1T      = enum.auto()
    BC1FL     = enum.auto()
    BC1TL     = enum.auto()
    ADD_S     = enum.auto() # Floating-Point Add
    SUB_S     = enum.auto() # Floating-Point Sub
    MUL_S     = enum.auto() # Floating-Point Multiply
    DIV_S     = enum.auto() # Floating-Point Divide
    SQRT_S    = enum.auto() # Floating-Point Square Root
    ABS_S     = enum.auto() # Floating-Point Absolute Value
    MOV_S     = enum.auto() # Floating-Point Move
    NEG_S     = enum.auto() # Floating-Point Negate
    ROUND_L_S = enum.auto() # Floating-Point Round to Long Fixed-Point
    TRUNC_L_S = enum.auto() # Floating-Point Truncate to Long Fixed-Point
    CEIL_L_S  = enum.auto() # Floating-Point Ceiling Convert to Long Fixed-Point
    FLOOR_L_S = enum.auto() # Floating-Point Floor Convert to Long Fixed-Point
    ROUND_W_S = enum.auto() # Floating-Point Round to Word Fixed-Point
    TRUNC_W_S = enum.auto() # Floating-Point Truncate to Word Fixed-Point
    CEIL_W_S  = enum.auto() # Floating-Point Ceiling Convert to Word Fixed-Point
    FLOOR_W_S = enum.auto() # Floating-Point Floor Convert to Word Fixed-Point
    CVT_D_S   = enum.auto()
    CVT_W_S   = enum.auto()
    CVT_L_S   = enum.auto()
    C_F_S     = enum.auto()
    C_UN_S    = enum.auto()
    C_EQ_S    = enum.auto()
    C_UEQ_S   = enum.auto()
    C_OLT_S   = enum.auto()
    C_ULT_S   = enum.auto()
    C_OLE_S   = enum.auto()
    C_ULE_S   = enum.auto()
    C_SF_S    = enum.auto()
    C_NGLE_S  = enum.auto()
    C_SEQ_S   = enum.auto()
    C_NGL_S   = enum.auto()
    C_LT_S    = enum.auto()
    C_NGE_S   = enum.auto()
    C_LE_S    = enum.auto()
    C_NGT_S   = enum.auto()
    ADD_D     = enum.auto() # Floating-Point Add
    SUB_D     = enum.auto() # Floating-Point Sub
    MUL_D     = enum.auto() # Floating-Point Multiply
    DIV_D     = enum.auto() # Floating-Point Divide
    SQRT_D    = enum.auto() # Floating-Point Square Root
    ABS_D     = enum.auto() # Floating-Point Absolute Value
    MOV_D     = enum.auto() # Floating-Point Move
    NEG_D     = enum.auto() # Floating-Point Negate
    ROUND_L_D = enum.auto() # Floating-Point Round to Long Fixed-Point
    TRUNC_L_D = enum.auto() # Floating-Point Truncate to Long Fixed-Point
    CEIL_L_D  = enum.auto() # Floating-Point Ceiling Convert to Long Fixed-Point
    FLOOR_L_D = enum.auto() # Floating-Point Floor Convert to Long Fixed-Point
    ROUND_W_D = enum.auto() # Floating-Point Round to Word Fixed-Point
    TRUNC_W_D = enum.auto() # Floating-Point Truncate to Word Fixed-Point
    CEIL_W_D  = enum.auto() # Floating-Point Ceiling Convert to Word Fixed-Point
    FLOOR_W_D = enum.auto() # Floating-Point Floor Convert to Word Fixed-Point
    CVT_S_D   = enum.auto()
    CVT_W_D   = enum.auto()
    CVT_L_D   = enum.auto()
    C_F_D     = enum.auto()
    C_UN_D    = enum.auto()
    C_EQ_D    = enum.auto()
    C_UEQ_D   = enum.auto()
    C_OLT_D   = enum.auto()
    C_ULT_D   = enum.auto()
    C_OLE_D   = enum.auto()
    C_ULE_D   = enum.auto()
    C_SF_D    = enum.auto()
    C_NGLE_D  = enum.auto()
    C_SEQ_D   = enum.auto()
    C_NGL_D   = enum.auto()
    C_LT_D    = enum.auto()
    C_NGE_D   = enum.auto()
    C_LE_D    = enum.auto()
    C_NGT_D   = enum.auto()
    CVT_S_W   = enum.auto()
    CVT_D_W   = enum.auto()
    CVT_S_L   = enum.auto()
    CVT_D_L   = enum.auto()

    BEQL      = enum.auto() # Branch on EQual Likely
    BNEL      = enum.auto() # Branch on Not Equal Likely
    BLEZL     = enum.auto() # Branch on Less than or Equal to Zero Likely
    BGTZL     = enum.auto() # Branch on Greater Than Zero Likely

    DADDI     = enum.auto() # Doubleword add Immediate
    DADDIU    = enum.auto() # Doubleword add Immediate Unsigned
    LDL       = enum.auto() # Load Doubleword Left
    LDR       = enum.auto() # Load Doubleword Right

    LB        = enum.auto() # Load Byte
    LH        = enum.auto() # Load Halfword
    LWL       = enum.auto() # Load Word Left
    LW        = enum.auto() # Load Word
    LBU       = enum.auto() # Load Byte Insigned
    LHU       = enum.auto() # Load Halfword Unsigned
    LWR       = enum.auto() # Load Word Right
    LWU       = enum.auto() # Load Word Unsigned

    SB        = enum.auto() # Store Byte
    SH        = enum.auto() # Store Halfword
    SWL       = enum.auto() # Store Word Left
    SW        = enum.auto() # Store Word
    SDL       = enum.auto() # Store Doubleword Left
    SDR       = enum.auto() # Store Doubleword Right
    SWR       = enum.auto() # Store Word Right
    CACHE     = enum.auto() # Cache

    LL        = enum.auto() # Load Linked word
    LWC1      = enum.auto() # Load Word to Coprocessor z
    LWC2      = enum.auto() # Load Word to Coprocessor z
    PREF      = enum.auto() # Prefetch
    LLD       = enum.auto() # Load Linked Doubleword
    LDC1      = enum.auto() # Load Doubleword to Coprocessor z
    LDC2      = enum.auto() # Load Doubleword to Coprocessor z
    LD        = enum.auto() # Load Doubleword

    SC        = enum.auto() # Store Conditional word
    SWC1      = enum.auto() # Store Word from Coprocessor z
    SWC2      = enum.auto() # Store Word from Coprocessor z
    #
    SCD       = enum.auto() # Store Conditional Doubleword
    SDC1      = enum.auto() # Store Doubleword from Coprocessor z
    SDC2      = enum.auto() # Store Doubleword from Coprocessor z
    SD        = enum.auto() # Store Doubleword

    # Pseudo-Instruction Unique IDs
    BEQZ      = enum.auto() # Branch on EQual Zero
    BNEZ      = enum.auto() # Branch on Not Equal Zero
    B         = enum.auto() # Branch (unconditional)
    NOP       = enum.auto() # No OPeration
    MOVE      = enum.auto() # Move
    NEGU      = enum.auto() 
    NOT       = enum.auto() # Not


@enum.unique
class InstructionVectorId(enum.Enum):
    INVALID   = -1

    VMULF     = enum.auto()
    VMULU     = enum.auto()
    VRNDP     = enum.auto()
    VMULQ     = enum.auto()
    VMUDL     = enum.auto()
    VMUDM     = enum.auto()
    VMUDN     = enum.auto()
    VMUDH     = enum.auto()
    VMACF     = enum.auto()
    VMACU     = enum.auto()
    VRNDN     = enum.auto()
    VMACQ     = enum.auto()
    VMADL     = enum.auto()
    VMADM     = enum.auto()
    VMADN     = enum.auto()
    VMADH     = enum.auto()
    VADD      = enum.auto()
    VSUB      = enum.auto()
    VABS      = enum.auto()
    VADDC     = enum.auto()
    VSUBC     = enum.auto()
    VSAR      = enum.auto()
    VAND      = enum.auto()
    VNAND     = enum.auto()
    VOR       = enum.auto()
    VNOR      = enum.auto()
    VXOR      = enum.auto()
    VNXOR     = enum.auto()

    VLT       = enum.auto()
    VEQ       = enum.auto()
    VNE       = enum.auto()
    VGE       = enum.auto()
    VCL       = enum.auto()
    VCH       = enum.auto()
    VCR       = enum.auto()
    VMRG      = enum.auto()

    VRCP      = enum.auto()
    VRCPL     = enum.auto()
    VRCPH     = enum.auto()
    VMOV      = enum.auto()
    VRSQ      = enum.auto()
    VRSQL     = enum.auto()
    VRSQH     = enum.auto()
    VNOP      = enum.auto()

    MFC2      = enum.auto()
    MTC2      = enum.auto()
    CFC2      = enum.auto()
    CTC2      = enum.auto()

    SBV       = enum.auto()
    SSV       = enum.auto()
    SLV       = enum.auto()
    SDV       = enum.auto()

    SQV       = enum.auto()
    SRV       = enum.auto()

    SPV       = enum.auto()

    SUV       = enum.auto()
    SWV       = enum.auto()

    SHV       = enum.auto()

    SFV       = enum.auto()
    STV       = enum.auto()

    LBV       = enum.auto()
    LSV       = enum.auto()
    LLV       = enum.auto()
    LDV       = enum.auto()

    LQV       = enum.auto()
    LRV       = enum.auto()

    LPV       = enum.auto()

    LUV       = enum.auto()

    LHV       = enum.auto()

    LFV       = enum.auto()
    LTV       = enum.auto()

@enum.unique
class InstrType(enum.Enum):
    typeUnknown = -1

    typeJ       = enum.auto()
    typeI       = enum.auto()
    typeR       = enum.auto()

    typeRegimm  = enum.auto()

@dataclasses.dataclass
class InstrDescriptor:
    operands: list[str]

    instrType: InstrType

    isBranch: bool = False
    isBranchLikely: bool = False
    isJump: bool = False
    isTrap: bool = False

    isFloat: bool = False
    isDouble: bool = False

    isUnsigned: bool = False

    modifiesRt: bool = False
    modifiesRd: bool = False

    mipsVersion: int|None = None
    "Version in which this instruction was introduced. `None` means unknown"
    isRsp: bool = False


instructionDescriptorDict: dict[InstructionId|InstructionVectorId, InstrDescriptor] = {
    InstructionId.INVALID   : InstrDescriptor(["rs", "rt", "IMM"], InstrType.typeUnknown),

    # OP rs
    InstructionId.JR        : InstrDescriptor(["rs"], InstrType.typeR, isJump=True),
    InstructionId.MTHI      : InstrDescriptor(["rs"], InstrType.typeR),
    InstructionId.MTLO      : InstrDescriptor(["rs"], InstrType.typeR),
    InstructionId.JALR      : InstrDescriptor(["rs"], InstrType.typeR, isJump=True, modifiesRd=True),

    # OP rd, rs
    InstructionId.JALR_RD   : InstrDescriptor(["rd", "rs"], InstrType.typeR, isJump=True, modifiesRd=True),

    # OP rd
    InstructionId.MFHI      : InstrDescriptor(["rd"], InstrType.typeR, modifiesRd=True),
    InstructionId.MFLO      : InstrDescriptor(["rd"], InstrType.typeR, modifiesRd=True),

    # OP rs, rt
    InstructionId.MULT      : InstrDescriptor(["rs", "rt"], InstrType.typeR),
    InstructionId.MULTU     : InstrDescriptor(["rs", "rt"], InstrType.typeR),
    InstructionId.DMULT     : InstrDescriptor(["rs", "rt"], InstrType.typeR),
    InstructionId.DMULTU    : InstrDescriptor(["rs", "rt"], InstrType.typeR),
    InstructionId.TGE       : InstrDescriptor(["rs", "rt"], InstrType.typeR, isTrap=True),
    InstructionId.TGEU      : InstrDescriptor(["rs", "rt"], InstrType.typeR, isTrap=True),
    InstructionId.TLT       : InstrDescriptor(["rs", "rt"], InstrType.typeR, isTrap=True),
    InstructionId.TLTU      : InstrDescriptor(["rs", "rt"], InstrType.typeR, isTrap=True),
    InstructionId.TEQ       : InstrDescriptor(["rs", "rt"], InstrType.typeR, isTrap=True),
    InstructionId.TNE       : InstrDescriptor(["rs", "rt"], InstrType.typeR, isTrap=True),

    # OP rd, rs, rt
    InstructionId.MOVZ      : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.MOVN      : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.DIV       : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR),
    InstructionId.DIVU      : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR),
    # InstructionId.DIV       : InstrDescriptor(["rs", "rt"], InstrType.typeR),
    # InstructionId.DIVU      : InstrDescriptor(["rs", "rt"], InstrType.typeR),
    InstructionId.DDIV      : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR),
    InstructionId.DDIVU     : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR),
    # InstructionId.DDIV      : InstrDescriptor(["rs", "rt"], InstrType.typeR),
    # InstructionId.DDIVU     : InstrDescriptor(["rs", "rt"], InstrType.typeR),
    InstructionId.ADD       : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.ADDU      : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.SUB       : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.SUBU      : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.AND       : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.OR        : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.XOR       : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.NOR       : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.SLT       : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.SLTU      : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.DADD      : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.DADDU     : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.DSUB      : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),
    InstructionId.DSUBU     : InstrDescriptor(["rd", "rs", "rt"], InstrType.typeR, modifiesRd=True),

    # OP code
    InstructionId.SYSCALL   : InstrDescriptor(["code"], InstrType.typeR),
    InstructionId.BREAK     : InstrDescriptor(["code"], InstrType.typeR),
    InstructionId.SYNC      : InstrDescriptor(["code"], InstrType.typeR),

    # OP rd, rt, rs
    InstructionId.DSLLV     : InstrDescriptor(["rd", "rt", "rs"], InstrType.typeR, modifiesRd=True),
    InstructionId.DSRLV     : InstrDescriptor(["rd", "rt", "rs"], InstrType.typeR, modifiesRd=True),
    InstructionId.DSRAV     : InstrDescriptor(["rd", "rt", "rs"], InstrType.typeR, modifiesRd=True),
    InstructionId.SLLV      : InstrDescriptor(["rd", "rt", "rs"], InstrType.typeR, modifiesRd=True),
    InstructionId.SRLV      : InstrDescriptor(["rd", "rt", "rs"], InstrType.typeR, modifiesRd=True),
    InstructionId.SRAV      : InstrDescriptor(["rd", "rt", "rs"], InstrType.typeR, modifiesRd=True),

    # OP rd, rt, sa
    InstructionId.SLL       : InstrDescriptor(["rd", "rt", "sa"], InstrType.typeR, modifiesRd=True),
    InstructionId.SRL       : InstrDescriptor(["rd", "rt", "sa"], InstrType.typeR, modifiesRd=True),
    InstructionId.SRA       : InstrDescriptor(["rd", "rt", "sa"], InstrType.typeR, modifiesRd=True),
    InstructionId.DSLL      : InstrDescriptor(["rd", "rt", "sa"], InstrType.typeR, modifiesRd=True),
    InstructionId.DSRL      : InstrDescriptor(["rd", "rt", "sa"], InstrType.typeR, modifiesRd=True),
    InstructionId.DSRA      : InstrDescriptor(["rd", "rt", "sa"], InstrType.typeR, modifiesRd=True),
    InstructionId.DSLL32    : InstrDescriptor(["rd", "rt", "sa"], InstrType.typeR, modifiesRd=True),
    InstructionId.DSRL32    : InstrDescriptor(["rd", "rt", "sa"], InstrType.typeR, modifiesRd=True),
    InstructionId.DSRA32    : InstrDescriptor(["rd", "rt", "sa"], InstrType.typeR, modifiesRd=True),

    # OP rs, IMM
    InstructionId.BLTZ      : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True),
    InstructionId.BGEZ      : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True),
    InstructionId.BLTZL     : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True, isBranchLikely=True),
    InstructionId.BGEZL     : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True, isBranchLikely=True),
    InstructionId.TGEI      : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isTrap=True),
    InstructionId.TGEIU     : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isTrap=True),
    InstructionId.TLTI      : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isTrap=True),
    InstructionId.TLTIU     : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isTrap=True),
    InstructionId.BLTZAL    : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True),
    InstructionId.BGEZAL    : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True),
    InstructionId.BLTZALL   : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True, isBranchLikely=True),
    InstructionId.BGEZALL   : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True, isBranchLikely=True),
    InstructionId.TEQI      : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isTrap=True),
    InstructionId.TNEI      : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isTrap=True),

    # OP LABEL
    InstructionId.J         : InstrDescriptor(["LABEL"], InstrType.typeJ, isJump=True),
    InstructionId.JAL       : InstrDescriptor(["LABEL"], InstrType.typeJ, isJump=True),

    # OP rs, rt, IMM
    InstructionId.BEQ       : InstrDescriptor(["rs", "rt", "IMM"], InstrType.typeRegimm, isBranch=True),
    InstructionId.BNE       : InstrDescriptor(["rs", "rt", "IMM"], InstrType.typeRegimm, isBranch=True),
    InstructionId.BEQL      : InstrDescriptor(["rs", "rt", "IMM"], InstrType.typeRegimm, isBranch=True, isBranchLikely=True),
    InstructionId.BNEL      : InstrDescriptor(["rs", "rt", "IMM"], InstrType.typeRegimm, isBranch=True, isBranchLikely=True),

    # OP rs, IMM
    InstructionId.BLEZ      : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True),
    InstructionId.BGTZ      : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True),
    InstructionId.BLEZL     : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True, isBranchLikely=True),
    InstructionId.BGTZL     : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True, isBranchLikely=True),

    # OP rt, IMM
    InstructionId.LUI       : InstrDescriptor(["rt", "IMM"], InstrType.typeI, isUnsigned=True, modifiesRt=True),

    # OP rt, rs, IMM
    InstructionId.ANDI      : InstrDescriptor(["rt", "rs", "IMM"], InstrType.typeI, isUnsigned=True, modifiesRt=True),
    InstructionId.ORI       : InstrDescriptor(["rt", "rs", "IMM"], InstrType.typeI, isUnsigned=True, modifiesRt=True),
    InstructionId.XORI      : InstrDescriptor(["rt", "rs", "IMM"], InstrType.typeI, isUnsigned=True, modifiesRt=True),
    InstructionId.ADDI      : InstrDescriptor(["rt", "rs", "IMM"], InstrType.typeI, modifiesRt=True),
    InstructionId.ADDIU     : InstrDescriptor(["rt", "rs", "IMM"], InstrType.typeI, modifiesRt=True),
    InstructionId.DADDI     : InstrDescriptor(["rt", "rs", "IMM"], InstrType.typeI, modifiesRt=True),
    InstructionId.DADDIU    : InstrDescriptor(["rt", "rs", "IMM"], InstrType.typeI, modifiesRt=True),
    InstructionId.SLTI      : InstrDescriptor(["rt", "rs", "IMM"], InstrType.typeI, modifiesRt=True),
    InstructionId.SLTIU     : InstrDescriptor(["rt", "rs", "IMM"], InstrType.typeI, modifiesRt=True),

    # OP rt, IMM(base)
    InstructionId.LDL       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.LDR       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.LB        : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.LH        : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.LWL       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.LW        : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.LBU       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.LHU       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.LWR       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.LWU       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.SB        : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI),
    InstructionId.SH        : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI),
    InstructionId.SWL       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI),
    InstructionId.SW        : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI),
    InstructionId.SDL       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI),
    InstructionId.SDR       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI),
    InstructionId.SWR       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI),
    InstructionId.LL        : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.PREF      : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.LLD       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.LD        : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.SC        : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.SCD       : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),
    InstructionId.SD        : InstrDescriptor(["rt", "IMM(base)"], InstrType.typeI, modifiesRt=True),

    InstructionId.CACHE     : InstrDescriptor(["op", "IMM(base)"], InstrType.typeI),

    # OP ft, IMM(base)
    InstructionId.LWC1      : InstrDescriptor(["ft", "IMM(base)"], InstrType.typeI, isFloat=True),
    InstructionId.LDC1      : InstrDescriptor(["ft", "IMM(base)"], InstrType.typeI, isFloat=True, isDouble=True),
    InstructionId.SWC1      : InstrDescriptor(["ft", "IMM(base)"], InstrType.typeI, isFloat=True),
    InstructionId.SDC1      : InstrDescriptor(["ft", "IMM(base)"], InstrType.typeI, isFloat=True, isDouble=True),

    # OP cop2t, IMM(base)
    InstructionId.LWC2      : InstrDescriptor(["cop2t", "IMM(base)"], InstrType.typeI),
    InstructionId.LDC2      : InstrDescriptor(["cop2t", "IMM(base)"], InstrType.typeI),
    InstructionId.SWC2      : InstrDescriptor(["cop2t", "IMM(base)"], InstrType.typeI),
    InstructionId.SDC2      : InstrDescriptor(["cop2t", "IMM(base)"], InstrType.typeI),

    # OP rt, cop0d
    InstructionId.MFC0      : InstrDescriptor(["rt", "cop0d"], InstrType.typeUnknown, modifiesRt=True),
    InstructionId.DMFC0     : InstrDescriptor(["rt", "cop0d"], InstrType.typeUnknown, modifiesRt=True),
    InstructionId.CFC0      : InstrDescriptor(["rt", "cop0d"], InstrType.typeUnknown, modifiesRt=True),
    InstructionId.MTC0      : InstrDescriptor(["rt", "cop0d"], InstrType.typeUnknown),
    InstructionId.DMTC0     : InstrDescriptor(["rt", "cop0d"], InstrType.typeUnknown),
    InstructionId.CTC0      : InstrDescriptor(["rt", "cop0d"], InstrType.typeUnknown),

    # OP
    InstructionId.TLBR      : InstrDescriptor([], InstrType.typeUnknown),
    InstructionId.TLBWI     : InstrDescriptor([], InstrType.typeUnknown),
    InstructionId.TLBWR     : InstrDescriptor([], InstrType.typeUnknown),
    InstructionId.TLBP      : InstrDescriptor([], InstrType.typeUnknown),
    InstructionId.ERET      : InstrDescriptor([], InstrType.typeUnknown),

    # OP IMM
    InstructionId.BC0T      : InstrDescriptor(["IMM"], InstrType.typeUnknown, isBranch=True, isFloat=True),
    InstructionId.BC0F      : InstrDescriptor(["IMM"], InstrType.typeUnknown, isBranch=True, isFloat=True),
    InstructionId.BC0TL     : InstrDescriptor(["IMM"], InstrType.typeUnknown, isBranch=True, isBranchLikely=True, isFloat=True),
    InstructionId.BC0FL     : InstrDescriptor(["IMM"], InstrType.typeUnknown, isBranch=True, isBranchLikely=True, isFloat=True),

    # OP rt, fs
    InstructionId.MFC1      : InstrDescriptor(["rt", "fs"], InstrType.typeUnknown, isFloat=True, modifiesRt=True),
    InstructionId.DMFC1     : InstrDescriptor(["rt", "fs"], InstrType.typeUnknown, isFloat=True, modifiesRt=True),
    InstructionId.CFC1      : InstrDescriptor(["rt", "fs"], InstrType.typeUnknown, isFloat=True, modifiesRt=True),
    InstructionId.MTC1      : InstrDescriptor(["rt", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.DMTC1     : InstrDescriptor(["rt", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.CTC1      : InstrDescriptor(["rt", "fs"], InstrType.typeUnknown, isFloat=True),

    # OP IMM
    InstructionId.BC1F      : InstrDescriptor(["IMM"], InstrType.typeUnknown, isBranch=True, isFloat=True),
    InstructionId.BC1T      : InstrDescriptor(["IMM"], InstrType.typeUnknown, isBranch=True, isFloat=True),
    InstructionId.BC1FL     : InstrDescriptor(["IMM"], InstrType.typeUnknown, isBranch=True, isBranchLikely=True, isFloat=True),
    InstructionId.BC1TL     : InstrDescriptor(["IMM"], InstrType.typeUnknown, isBranch=True, isBranchLikely=True, isFloat=True),

    # OP fd, fs, ft
    InstructionId.ADD_S     : InstrDescriptor(["fd", "fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.SUB_S     : InstrDescriptor(["fd", "fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.MUL_S     : InstrDescriptor(["fd", "fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.DIV_S     : InstrDescriptor(["fd", "fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.ADD_D     : InstrDescriptor(["fd", "fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.SUB_D     : InstrDescriptor(["fd", "fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.MUL_D     : InstrDescriptor(["fd", "fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.DIV_D     : InstrDescriptor(["fd", "fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),

    # OP fd, fs
    InstructionId.SQRT_S    : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.ABS_S     : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.MOV_S     : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.NEG_S     : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.SQRT_D    : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.ABS_D     : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.MOV_D     : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.NEG_D     : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.ROUND_L_S : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.TRUNC_L_S : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.CEIL_L_S  : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.FLOOR_L_S : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.ROUND_L_D : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.TRUNC_L_D : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.CEIL_L_D  : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.FLOOR_L_D : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.ROUND_W_S : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.TRUNC_W_S : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.CEIL_W_S  : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.FLOOR_W_S : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.ROUND_W_D : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.TRUNC_W_D : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.CEIL_W_D  : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.FLOOR_W_D : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),

    # OP fs, ft
    InstructionId.C_F_S     : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_UN_S    : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_EQ_S    : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_UEQ_S   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_OLT_S   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_ULT_S   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_OLE_S   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_ULE_S   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_F_D     : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_UN_D    : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_EQ_D    : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_UEQ_D   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_OLT_D   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_ULT_D   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_OLE_D   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_ULE_D   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_SF_S    : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_NGLE_S  : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_SEQ_S   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_NGL_S   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_LT_S    : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_NGE_S   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_LE_S    : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_NGT_S   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True),
    InstructionId.C_SF_D    : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_NGLE_D  : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_SEQ_D   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_NGL_D   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_LT_D    : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_NGE_D   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_LE_D    : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.C_NGT_D   : InstrDescriptor(["fs", "ft"], InstrType.typeUnknown, isFloat=True, isDouble=True),

    # OP fd, fs
    InstructionId.CVT_S_D   : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.CVT_S_W   : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.CVT_S_L   : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.CVT_D_S   : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.CVT_D_W   : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.CVT_D_L   : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.CVT_W_S   : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.CVT_W_D   : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),
    InstructionId.CVT_L_S   : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True),
    InstructionId.CVT_L_D   : InstrDescriptor(["fd", "fs"], InstrType.typeUnknown, isFloat=True, isDouble=True),

    # Pseudo-Instruction Unique IDs
    # OP rs, IMM
    InstructionId.BEQZ      : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True),
    InstructionId.BNEZ      : InstrDescriptor(["rs", "IMM"], InstrType.typeRegimm, isBranch=True),

    # OP IMM
    InstructionId.B         : InstrDescriptor(["IMM"], InstrType.typeRegimm, isBranch=True),

    # OP
    InstructionId.NOP       : InstrDescriptor([], InstrType.typeR),

    # OP rd, rs
    InstructionId.MOVE      : InstrDescriptor(["rd", "rs"], InstrType.typeR, modifiesRd=True),
    InstructionId.NOT       : InstrDescriptor(["rd", "rs"], InstrType.typeR, modifiesRd=True),

    # OP rd, rt
    InstructionId.NEGU      : InstrDescriptor(["rd", "rt"], InstrType.typeR, modifiesRd=True),
}


InstructionsNotEmitedByIDO = {
    InstructionId.ADD,
    InstructionId.ADDI,
    InstructionId.MTC0,
    InstructionId.MFC0,
    InstructionId.ERET,
    InstructionId.TLBP,
    InstructionId.TLBR,
    InstructionId.TLBWI,
    InstructionId.CACHE,
}
