import dataclasses
from typing import Optional


@dataclasses.dataclass
class ParentSegmentInfo:
    """
    Information from the parent segment, used to locate the segment's metadata
    or to locate segments that can be referenced by this parent segment.
    """

    name: str
    segment_rom: int
    segment_vram: int
    exclusive_ram_id: Optional[str]

    def __repr__(self) -> str:
        if self.exclusive_ram_id is None:
            exclusive_ram_id = "None"
        else:
            exclusive_ram_id = f"{self.exclusive_ram_id!r}"
        return f"ParentSegmentInfo(name={self.name}, segment_rom=0x{self.segment_rom:08X}, segment_vram=0x{self.segment_vram:08X}, exclusive_ram_id={exclusive_ram_id})"

    def __str__(self) -> str:
        return self.__repr__()
