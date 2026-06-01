import dataclasses

@dataclasses.dataclass
class ParentSegmentInfo:
    segment_rom: int
    segment_vram: int
    exclusive_ram_id: str | None

    def __repr__(self) -> str:
        exclusive_ram_id = f"{self.exclusive_ram_id:r}" if self.exclusive_ram_id is not None else "None"
        return f"ParentSegmentInfo(segment_rom=0x{self.segment_rom:08X}, segment_vram=0x{self.segment_vram:08X}, exclusive_ram_id={exclusive_ram_id})"

    def __str__(self) -> str:
        return self.__repr__()
