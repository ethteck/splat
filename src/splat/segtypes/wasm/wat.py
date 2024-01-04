from wasm_tob import (
    Section,
    SEC_TYPE,
    TypeSection,
    FuncType,
    ValueTypeField,
    format_lang_type,
)


def func_type_to_wat(index: int, func: FuncType) -> str:
    params = ""
    if func.param_count > 0:
        vals = " ".join(map(format_lang_type, func.param_types))
        params += f" (param {vals})"

    returns = ""
    if func.return_count:
        returns += f" (result {format_lang_type(func.return_type)})"

    return f"(type (;{index};) (func{params}{returns}))"


def type_section_to_wat(section: TypeSection) -> str:
    return "\n".join(
        func_type_to_wat(index, entry) for index, entry in enumerate(section.entries)
    )
