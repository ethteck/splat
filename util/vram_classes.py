from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class VramClass:
    name: str
    vram: int
    vram_symbol: Optional[str] = None
    follows_classes: Optional[List[str]] = None


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
        vram_symbol: Optional[str] = None
        follows_classes: Optional[List[str]] = None

        if isinstance(vram_class, dict):
            if "name" not in vram_class:
                raise KeyError(f"vram_class ({vram_class}) must have a name")
            name = vram_class["name"]

            if "vram" not in vram_class:
                raise KeyError(f"vram_class ({vram_class}) must have a vram")
            vram = vram_class["vram"]

            if "vram_symbol" in vram_class:
                vram_symbol = vram_class["vram_symbol"]

            if "follows_classes" in vram_class:
                follows_classes = vram_class["follows_classes"]
        elif isinstance(vram_class, list):
            if len(vram_class) != 2:
                raise ValueError(
                    f"vram_class ({vram_class}) must have 2 elements, got {len(vram_class)}"
                )
            name = vram_class[0]
            vram = vram_class[1]
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
        _vram_classes[name] = VramClass(name, vram, vram_symbol, follows_classes)


def resolve(name: str) -> VramClass:
    if name not in _vram_classes:
        raise ValueError(f"Unknown vram class '{name}'")
    return _vram_classes[name]
