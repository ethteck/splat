from dataclasses import dataclass

def dotless_type_equals(sect1: str, sect2: str) -> bool:
    return sect1 == sect2 or sect1[1:] == sect2 or sect1 == sect2[1:]

@dataclass
class LinkerSection:
    name: str
    started: bool
    ended: bool
