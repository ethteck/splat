from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypedDict

from . import log

if TYPE_CHECKING:
    from typing_extensions import NotRequired


@dataclass(frozen=True)
class VramClass:
    name: str
    vram: int
    given_vram_symbol: str | None = None
    follows_classes: list[str] = field(default_factory=list, compare=False)

    @property
    def vram_symbol(self) -> str | None:
        if self.given_vram_symbol is not None:
            return self.given_vram_symbol
        if self.follows_classes:
            return self.name + "_CLASS_VRAM"
        return None


_vram_classes: dict[str, VramClass] = {}


class SerializedSegmentData(TypedDict):
    name: NotRequired[str]
    vram: int
    vram_symbol: str | None
    follows_classes: list[str]
    vram_class: NotRequired[str]
    follows_vram: NotRequired[str | None]
    align: NotRequired[str]
    subalign: NotRequired[str]
    section_order: NotRequired[list[str]]
    start: NotRequired[str]
    type: NotRequired[str]
    dir: NotRequired[str]
    symbol_name_format: NotRequired[str]
    symbol_name_format_no_rom: NotRequired[str]
    path: NotRequired[str]
    bss_contains_common: NotRequired[bool]
    linker_section_order: NotRequired[str]
    linker_section: NotRequired[str]
    ld_fill_value: NotRequired[int]
    ld_align_segment_start: NotRequired[int]
    pair_segment: NotRequired[str]
    exclusive_ram_id: NotRequired[str]
    find_file_boundaries: NotRequired[bool]
    size: NotRequired[int]
    global_id: NotRequired[str]
    length: NotRequired[int]
    in_segment: NotRequired[bool]
    data_only: NotRequired[bool]
    bss_size: NotRequired[int]
    str_encoding: NotRequired[str]
    detect_redundant_function_end: NotRequired[bool]
    width: NotRequired[int]
    height: NotRequired[int]


def initialize(yaml: list[SerializedSegmentData | list[str]] | None) -> None:
    global _vram_classes

    _vram_classes = {}

    if yaml is None:
        return

    if not isinstance(yaml, list):
        log.error("vram_classes must be a list")

    class_names = set()
    for vram_class in yaml:
        if isinstance(vram_class, dict):
            if "name" not in vram_class:
                log.error(f"vram_class ({vram_class}) must have a name")
            class_names.add(vram_class["name"])
        elif isinstance(vram_class, list):
            class_names.add(vram_class[0])

    for vram_class in yaml:
        name: str
        vram: int
        vram_symbol: str | None = None
        follows_classes: list[str] = []

        if isinstance(vram_class, dict):
            if "name" not in vram_class:
                log.error(f"vram_class ({vram_class}) must have a name")
            name = vram_class["name"]

            if "vram" not in vram_class:
                log.error(f"vram_class ({vram_class}) must have a vram")
            vram = vram_class["vram"]

            if "vram_symbol" in vram_class:
                vram_symbol = vram_class["vram_symbol"]
                if not isinstance(vram_symbol, str):
                    log.error(
                    )

            if "follows_classes" in vram_class:
                follows_classes = vram_class["follows_classes"]
                if not isinstance(follows_classes, list):
                    log.error(
                    )
                for follows_class in follows_classes:
                    if follows_class not in class_names:
                        log.error(
                        )
        elif isinstance(vram_class, list):
            if len(vram_class) != 2:
                log.error(
                )
            name = vram_class[0]
            vram = int(vram_class[1])
        else:
            log.error(f"vram_class must be a dict or list, got {type(vram_class)}")

        if not isinstance(name, str):
            log.error(f"vram_class name ({name}) must be a string, got {type(name)}")
        if not isinstance(vram, int):
            log.error(f"vram_class vram ({vram}) must be an int, got {type(vram)}")
        if name in _vram_classes:
            log.error(f"Duplicate vram class name '{name}'")
        _vram_classes[name] = VramClass(name, vram, vram_symbol, follows_classes)


def resolve(name: str) -> VramClass:
    if name not in _vram_classes:
        log.error(f"Unknown vram class '{name}'")
    return _vram_classes[name]
