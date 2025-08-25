from dataclasses import dataclass
from typing import Optional, Dict


@dataclass
class Compiler:
    name: str
    asm_function_macro: str = "glabel"
    asm_function_alt_macro: str = "alabel"
    asm_jtbl_label_macro: str = "jlabel"
    asm_data_macro: str = "dlabel"
    asm_end_label: str = "endlabel"
    asm_data_end_label: str = "enddlabel"
    asm_ehtable_label_macro: str = "ehlabel"
    asm_nonmatching_label_macro: str = "nonmatching"
    c_newline: str = "\n"
    asm_inc_header: str = ""
    asm_emit_size_directive: Optional[bool] = None
    j_as_branch: bool = False
    uses_include_asm: bool = True


GCC = Compiler(
    "GCC",
    asm_inc_header=".set noat      /* allow manual use of $at */\n.set noreorder /* don't insert nops after branches */\n\n",
    j_as_branch=True,
)

SN64 = Compiler(
    "SN64",
    asm_function_macro=".globl",
    asm_function_alt_macro=".globl",
    asm_jtbl_label_macro=".globl",
    asm_data_macro=".globl",
    asm_end_label=".end",
    asm_data_end_label="",
    asm_nonmatching_label_macro="",
    c_newline="\r\n",
    asm_emit_size_directive=False,
    j_as_branch=True,
)

IDO = Compiler("IDO", asm_emit_size_directive=False, uses_include_asm=False)

KMC = Compiler(
    "KMC",
    j_as_branch=True,
)

# iQue
EGCS = Compiler(
    "EGCS",
    j_as_branch=True,
)

# PS1
PSYQ = Compiler(
    "PSYQ",
    j_as_branch=True,
)

# PS2
MWCCPS2 = Compiler("MWCCPS2", uses_include_asm=False)
EEGCC = Compiler("EEGCC")

compiler_for_name: Dict[str, Compiler] = {
    x.name: x
    for x in [
        GCC,
        SN64,
        IDO,
        KMC,
        EGCS,
        PSYQ,
        MWCCPS2,
        EEGCC,
    ]
}


def for_name(name: str) -> Compiler:
    name = name.upper()
    return compiler_for_name.get(name, Compiler(name))
