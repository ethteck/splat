from pathlib import Path
from typing import List, TYPE_CHECKING

from ...util import log, options

from .img import N64SegImg

if TYPE_CHECKING:
    from .palette import N64SegPalette


# Base class for CI4/CI8
class N64SegCi(N64SegImg):
    def parse_palette_names(self, yaml, args) -> List[str]:
        ret = [self.name]
        if isinstance(yaml, dict):
            if "palettes" in yaml:
                ret = yaml["palettes"]
        elif len(args) > 2:
            ret = args[2]

        if isinstance(ret, str):
            ret = [ret]
        return ret

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.palettes: "List[N64SegPalette]" = []
        self.palette_names = self.parse_palette_names(self.yaml, self.args)

    def scan(self, rom_bytes: bytes) -> None:
        self.n64img.data = rom_bytes[self.rom_start : self.rom_end]

    def out_path_pal(self, pal_name) -> Path:
        type_extension = f".{self.type}" if options.opts.image_type_in_extension else ""

        if len(self.palettes) == 1:
            # If there's only one palette, use the ci name
            out_name = self.name
        elif pal_name.startswith(self.name):
            # Otherwise, if the palette name starts with / equals the ci name, use that
            out_name = pal_name
        else:
            # Otherwise, just append the palette name to the ci name
            out_name = f"{self.name}_{pal_name}"

        return options.opts.asset_path / self.dir / f"{out_name}{type_extension}.png"

    def split(self, rom_bytes):
        assert self.palettes is not None
        if len(self.palettes) == 0:
            # TODO: output with blank palette
            log.error(
                f"no palettes have been mapped to ci segment `{self.name}`\n(hint: add a palette segment with the same name or use the `palettes:` field of this segment to specify palettes by name')"
            )

        assert isinstance(self.rom_start, int)
        assert isinstance(self.rom_end, int)
        self.n64img.data = rom_bytes[self.rom_start : self.rom_end]

        for palette in self.palettes:
            path = self.out_path_pal(palette.name)
            path.parent.mkdir(parents=True, exist_ok=True)

            self.n64img.palette = palette.parse_palette(rom_bytes)
            self.n64img.write(path)

            self.log(f"Wrote {path.name} to {path}")
