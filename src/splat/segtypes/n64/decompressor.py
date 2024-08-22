from ...util import log, options

from ..segment import Segment


class CommonSegDecompressor(Segment):
    def split(self, rom_bytes):
        out_dir = options.opts.asset_path / self.dir
        out_dir.mkdir(parents=True, exist_ok=True)

        if self.rom_end is None:
            log.error(
                f"segment {self.name} needs to know where it ends; add a position marker [0xDEADBEEF] after it"
            )

        out_path = out_dir / f"{self.name}.bin"
        with open(out_path, "wb") as f:
            assert isinstance(self.rom_start, int)
            assert isinstance(self.rom_end, int)

            self.log(f"Decompressing {self.name}")
            compressed_bytes = rom_bytes[self.rom_start : self.rom_end]
            decompressed_bytes = self.decompress(compressed_bytes)
            f.write(decompressed_bytes)
        self.log(f"Wrote {self.name} to {out_path}")

    def get_linker_entries(self):
        from ..linker_entry import LinkerEntry

        return [
            LinkerEntry(
                self,
                [options.opts.asset_path / self.dir / f"{self.name}.bin"],
                options.opts.asset_path
                / self.dir
                / f"{self.name}.{self.compression_type}",  # "MIO0" -> filename.MIO0.o
                self.get_linker_section_order(),
                self.get_linker_section_linksection(),
                self.is_noload(),
            )
        ]

    @property
    def compression_type(self) -> str:
        log.error(
            f"Segment {self.__class__.__name__} needs to define a compression type"
        )

    def decompress(self, compressed_bytes: bytes) -> bytes:
        log.error(
            f"Segment {self.__class__.__name__} needs to define a decompression method"
        )
