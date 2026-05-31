import dataclasses
import enum

from spimdisasm.common import SortedDict

from ..symbols import Symbol
from .. import log

class SegmentKind(enum.Enum):
    Global = 0
    Overlay = 1
    Unknown = 2

@dataclasses.dataclass
class SegmentMetadata:
    kind: SegmentKind
    name: str

    rom_start: int
    rom_end: int
    vram_start: int
    vram_end: int

    exclusive_ram_id: str | None

    symbols: SortedDict[Symbol]


    def in_rom_range(self, rom: int) -> bool:
        if rom < self.rom_start:
            return False
        if rom >= self.rom_end:
            return False
        return True

    def in_vram_range(self, vram: int) -> bool:
        if vram < self.vram_start:
            return False
        if vram >= self.vram_end:
            return False
        return True

    def add_symbol(self, vram: int, allow_addend) -> Symbol:
        if not self.in_vram_range(vram):
            log.write(f"\nWARNING: Bug! Adding symbol 0x{vram:08X} to segment '{self.name}' ({self.kind}), but the address of the symbol is outside the segment vram range (0x{self.vram_start:08X} ~ 0x{self.vram_end:08X})\n", status="warn")

        symbol = self.find_symbol(vram, allow_addend)
        if symbol is None:
            symbol = Symbol(vram)
            self.symbols[vram] = symbol

        return symbol

    def find_symbol(self, vram: int, allow_addend) -> Symbol | None:
        if allow_addend:
            pair = self.symbols.getKeyRight(vram, True)
            if pair is None:
                return None

            symbol_vram, sym = pair
            if vram >= symbol_vram + sym.size:
                return None
            return sym

        return self.symbols.get(vram)
