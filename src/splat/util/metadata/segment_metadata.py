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

    def rom_from_vram(self, vram: int) -> int | None:
        if not self.in_vram_range(vram):
            return None
        rom = vram - self.vram_start + self.rom_start
        if not self.in_rom_range(rom):
            return None
        return rom


    def create_symbol(self, vram: int, allow_addend: bool) -> Symbol:
        if not self.in_vram_range(vram):
            log.write(f"\nWARNING: Bug! Adding symbol 0x{vram:08X} to segment '{self.name}' ({self.kind}), but the address of the symbol is outside the segment vram range (0x{self.vram_start:08X} ~ 0x{self.vram_end:08X})\n", status="warn")

        symbol = self.find_symbol(vram, allow_addend)
        if symbol is None:
            symbol = Symbol(vram)
            self.symbols[vram] = symbol

        return symbol

    def add_user_symbol(self, sym: Symbol) -> None:
        if not self.in_vram_range(sym.vram_start):
            log.error(f"\nERROR: Adding symbol 0x{sym.vram_start:08X} to segment '{self.name}' ({self.kind}), but the address of the symbol is outside the segment vram range (0x{self.vram_start:08X} ~ 0x{self.vram_end:08X})\n")

        existing_sym = self.find_symbol(sym.vram_start, True)
        if existing_sym is not None:
            log.error(f"\nERROR: The user defined symbol '{sym.name}' (Vram 0x{sym.vram_start:08X}, size 0x{sym.size:X}) overlaps with the previously defined '{existing_sym.name}' (Vram 0x{existing_sym.vram_start:08X}, size 0x{existing_sym.size:X})")

        sym._added_to_meta = True
        self.symbols[sym.vram_start] = sym


    def find_symbol(self, vram: int, allow_addend: bool) -> Symbol | None:
        if allow_addend:
            pair = self.symbols.getKeyRight(vram, True)
            if pair is None:
                return None

            symbol_vram, sym = pair
            if vram >= symbol_vram + sym.size:
                return None
            return sym

        return self.symbols.get(vram)
