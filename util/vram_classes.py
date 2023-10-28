from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class VramClass:
    name: str
    vram: int


_vram_classes: Dict[str, VramClass] = {}


def initialize(yaml: Any):
    global _vram_classes

    _vram_classes = {}

    if yaml is None:
        return

    if not isinstance(yaml, list):
        raise TypeError("vram_classes must be a list")

    for vram_class in yaml:
        name: str
        vram: int

        if isinstance(vram_class, dict):
            if "name" not in vram_class:
                raise KeyError(f"vram_class ({vram_class}) must have a name")
            name = vram_class["name"]

            if "vram" not in vram_class:
                raise KeyError(f"vram_class ({vram_class}) must have a vram")
            vram = int(vram_class["vram"], 0)
        elif isinstance(vram_class, list):
            if len(vram_class) != 2:
                raise ValueError(
                    f"vram_class ({vram_class}) must have 2 elements, got {len(vram_class)}"
                )
            name = vram_class[0]
            vram = int(vram_class[1], 0)
        else:
            raise TypeError(
                f"vram_class must be a dict or list, got {type(vram_class)}"
            )

        if not isinstance(name, str):
            raise TypeError(
                f"vram_class name ({name}) must be a string, got {type(name)}"
            )
        if not isinstance(vram, int):
            raise TypeError(
                f"vram_class vram ({vram}) must be an int, got {type(vram)}"
            )
        if name in _vram_classes:
            raise ValueError(f"Duplicate vram class name '{name}'")
        _vram_classes[name] = VramClass(name, vram)


def resolve(name: str) -> int:
    if name not in _vram_classes:
        raise ValueError(f"Unknown vram class '{name}'")
    return _vram_classes[name].vram
