from wasm_tob import (
    Section,
    SEC_TYPE,
    TypeSection,
    FuncType,
    ValueTypeField,
    format_lang_type,
    ImportSection,
    ImportEntry
)


def func_type_to_wat(index: int, func: FuncType) -> str:
    params = (
        f" (param {' '.join(map(format_lang_type, func.param_types))})"
        if func.param_count
        else ""
    )
    returns = (
        f" (result {format_lang_type(func.return_type)})" if func.return_count else ""
    )

    return f"(type (;{index};) (func{params}{returns}))"


def type_section_to_wat(section: TypeSection) -> str:
    return "\n".join(
        func_type_to_wat(index, entry) for index, entry in enumerate(section.entries)
    )

#   (import "a" "a" (func (;0;) (type 8)))
#   (import "a" "b" (func (;1;) (type 0)))
#   (import "a" "c" (func (;2;) (type 2)))
#   (import "a" "d" (func (;3;) (type 0)))
#   (import "a" "e" (func (;4;) (type 1)))
#   (import "a" "f" (func (;5;) (type 13)))
#   (import "a" "g" (func (;6;) (type 0)))
#   (import "a" "h" (func (;7;) (type 4)))
#   (import "a" "i" (func (;8;) (type 6)))
#   (import "a" "j" (func (;9;) (type 3)))
def import_entry_to_wat(index: int, entry: ImportEntry) -> str:
    from enum import IntEnum

    class ImportKind(IntEnum):
        FUNC = 0x00
        TABLE = 0x01
        MEM = 0x02
        GLOBAL = 0x03

    module = entry.module_str.decode()
    field = entry.field_str.decode()

    wat = ""
    match entry.kind:
        case ImportKind.FUNC:
            wat = f'(func (;{index};) (type {entry.type.type}))'
            pass

        case _:
            # TODO: Support table, mem, global
            wat = "() ;; TODO "

    return f'(import "{module}" "{field}" {wat})'

def import_section_to_wat(section: ImportSection) -> str:
    return "\n".join(
        import_entry_to_wat(index, entry) for index, entry in enumerate(section.entries)
    )