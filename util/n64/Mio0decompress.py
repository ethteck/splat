import argparse
import struct

try:
    from util import log
except ModuleNotFoundError:
    # allow script to run standalone
    import sys
    from pathlib import Path

    sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
    from util import log


class GenericMio0Decompressor:
    def __init__(
        self, unpacked_offset, compressed_offset, uncompressed_offset, header_length
    ):
        self.unpacked_offset = unpacked_offset
        self.compressed_offset = compressed_offset
        self.uncompressed_offset = uncompressed_offset
        self.header_length = header_length

    @staticmethod
    def read_word(data, offset):
        (res,) = struct.unpack(">I", data[offset : offset + 4])
        return res

    @staticmethod
    def read_short(data, offset):
        (res,) = struct.unpack(">H", data[offset : offset + 2])
        return res

    def decompress(self, in_bytes):
        magic = in_bytes[0:4]
        if magic != b"MIO0":
            log.error(f"MIO0 magic is incorrect: {magic}")

        unpacked_size = self.read_word(in_bytes, self.unpacked_offset)
        comp_offset = self.read_word(in_bytes, self.compressed_offset)
        uncomp_offset = self.read_word(in_bytes, self.uncompressed_offset)

        layout_data = struct.iter_unpack(">I", in_bytes[self.header_length :])
        uncompressed_data = struct.iter_unpack(">B", in_bytes[uncomp_offset:])
        compressed_data = struct.iter_unpack(">H", in_bytes[comp_offset:])

        idx = 0
        ret = bytearray(unpacked_size)

        mask_bit_counter = 0
        while idx < unpacked_size:
            if mask_bit_counter == 0:
                (current_mask,) = next(layout_data)
                mask_bit_counter = 32

            if current_mask & 0x80000000:
                (ud,) = next(uncompressed_data)
                ret[idx] = ud
                idx += 1
            else:
                (length_offset,) = next(compressed_data)

                length = (length_offset >> 12) + 3
                index = (length_offset & 0xFFF) + 1

                if not (3 <= length <= 18):
                    log.error(f"Invalid length: {length}, corrupt data?")

                if not (1 <= index <= 4096):
                    log.error(f"Invalid index: {index}, corrupt data?")

                for i in range(length):
                    ret[idx] = ret[idx - index]
                    idx += 1

            current_mask <<= 1
            mask_bit_counter -= 1

        return ret


class Mio0Decompressor(GenericMio0Decompressor):
    def __init__(self):
        super().__init__(
            4,  # unpacked size ofset
            8,  # compresed data offset
            12,  # uncompressed data offset
            16,  # header length
        )


def main(args):
    with open(args.infile, "rb") as f:
        raw_bytes = f.read()

    miodecompress = Mio0Decompressor()
    decompressed = miodecompress.decompress(raw_bytes)

    with open(args.outfile, "wb") as f:
        f.write(decompressed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("infile")
    parser.add_argument("outfile")

    args = parser.parse_args()
    main(args)
