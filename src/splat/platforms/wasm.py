from wasm_tob import (
    format_instruction,
    Section,
    SEC_TYPE,
    TypeSection,
    FuncType,
    ValueTypeField,
    format_lang_type,
    ImportSection,
    ImportEntry,
    FunctionSection,
    ExportSection,
    ExportEntry,
    DataSection,
    DataSegment,
    CodeSection,
    FunctionBody,
    INSN_LEAVE_BLOCK,
    INSN_ENTER_BLOCK,
    decode_bytecode,
)

from enum import IntEnum
from typing import Optional


class ExternalKind(IntEnum):
    FUNC = 0x00
    TABLE = 0x01
    MEM = 0x02
    GLOBAL = 0x03


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
    module = entry.module_str.decode()
    field = entry.field_str.decode()

    KIND_TO_FMT = {ExternalKind.FUNC: "(func (;{index};) (type {entry.type.type}))"}

    wat = KIND_TO_FMT[entry.kind].format(index=index, entry=entry)

    return f'(import "{module}" "{field}" {wat})'


def import_section_to_wat(section: ImportSection) -> str:
    return "\n".join(
        import_entry_to_wat(index, entry) for index, entry in enumerate(section.entries)
    )


def function_section_to_wat(section: FunctionSection) -> str:
    return "TODO"


# https://webassembly.github.io/spec/core/text/modules.html#exports
def export_entry_to_wat(entry: ExportEntry) -> str:
    KIND_TO_STR = {
        ExternalKind.FUNC: "func",
        ExternalKind.TABLE: "table",
        ExternalKind.MEM: "memory",
        ExternalKind.GLOBAL: "global",
    }

    fmt = '(export "{field}" ({kind} {index}))'

    return fmt.format(
        field=entry.field_str.decode(), kind=KIND_TO_STR[entry.kind], index=entry.index
    )


def export_section_to_wat(section: ExportSection) -> str:
    return "\n".join(export_entry_to_wat(entry) for entry in section.entries)


def data_segment_to_wat(index: int, segment: DataSegment) -> str:
    fmt = "(data (;{index};) ({instruction}) {datastring})"

    return fmt.format(
        index=index,
        # Currently the spec only supports a single instruction.
        instruction=format_instruction(segment.offset[0]),
        datastring=f'"{repr(segment.data)[2:-1]}"'.replace("\\x", "\\"),
    )


def data_section_to_wat(section: DataSection) -> str:
    return "\n".join(
        data_segment_to_wat(index, entry) for index, entry in enumerate(section.entries)
    )


def format_function(
    fname: str,
    type_index: int,
    func_body: FunctionBody,
    func_type: FuncType,
    indent=2,
    format_locals=True,
):
    import itertools

    func_fmt = '(func "{name}" (type {type_index}){param_section}{result_section}'

    param_section = (
        " (param {})".format(" ".join(map(format_lang_type, func_type.param_types)))
        if func_type.param_types
        else ""
    )
    result_section = (
        " (result {})".format(format_lang_type(func_type.return_type))
        if func_type.return_type
        else ""
    )

    yield func_fmt.format(
        name=fname,
        type_index=type_index,
        param_section=param_section,
        result_section=result_section,
    )

    if format_locals and func_body.locals:
        yield " " * indent + "(local {})".format(
            " ".join(
                itertools.chain.from_iterable(
                    itertools.repeat(format_lang_type(x.type), x.count)
                    for x in func_body.locals
                )
            )
        )

    level = 1
    for cur_insn in decode_bytecode(func_body.code):
        if cur_insn.op.flags & INSN_LEAVE_BLOCK:
            level -= 1
        yield " " * (level * indent) + format_instruction(cur_insn)
        if cur_insn.op.flags & INSN_ENTER_BLOCK:
            level += 1


def code_section_to_wat(
    code: CodeSection, funcs: FunctionSection, types: TypeSection
) -> str:
    src = ""
    for index, body in enumerate(code.bodies):
        type_index = funcs.types[index]

        try:
            src += "\n".join(
                format_function(
                    f"func_{index:04d}", type_index, body, types.entries[type_index]
                )
            )
        except Exception as e:
            src += f";; Exception: {str(e)}"
            pass

        src += "\n"

    # zip(code.bodies, types.entries[idx] for idx in func

    return src
    # return "\n\n".join(map(function_body_to_wat, zip(code.bodies, types.))


def init(target_bytes: bytes):
    pass
