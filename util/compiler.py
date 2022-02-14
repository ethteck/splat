from dataclasses import dataclass


@dataclass
class Compiler:
    name: str
    function_label_macro: str = ""
    data_label_macro: str = ""
    asm_end_label: str = ""
    c_newline: str = "\n"
    asm_inc_header: str = ""

GCC = Compiler(
    "GCC",
    asm_inc_header=".set noat      # allow manual use of $at\n.set noreorder # don't insert nops after branches\n\n",
)

SN64 = Compiler(
    "SN64",
    asm_end_label=".end",
    c_newline="\r\n",
)

compiler_for_name = {
    "GCC": GCC,
    "SN64": SN64
}

def for_name(name: str) -> Compiler:
    name = name.upper()
    if name in compiler_for_name:
        return compiler_for_name[name]
    return Compiler(name)