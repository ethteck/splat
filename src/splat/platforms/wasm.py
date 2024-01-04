from wasm_tob import (
    Section,
    SEC_TYPE,
    TypeSection,
    FuncType,
    ValueTypeField,
    format_lang_type,
    ImportSection,
    ImportEntry,
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
            wat = f"(func (;{index};) (type {entry.type.type}))"
            pass

        case _:
            # TODO: Support table, mem, global
            wat = "() ;; TODO "

    return f'(import "{module}" "{field}" {wat})'


def import_section_to_wat(section: ImportSection) -> str:
    return "\n".join(
        import_entry_to_wat(index, entry) for index, entry in enumerate(section.entries)
    )


def init(target_bytes: bytes):
    pass
