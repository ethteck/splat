import argparse
import sys

def decompress_yay0(in_bytes, byte_order="big"):
    if in_bytes[:4] != b"Yay0":
        sys.exit("Input file is not yay0")

    decompressed_size = int.from_bytes(in_bytes[4:8], byteorder=byte_order)
    link_table_offset = int.from_bytes(in_bytes[8:12], byteorder=byte_order)
    chunk_offset = int.from_bytes(in_bytes[12:16], byteorder=byte_order)

    link_table_idx = link_table_offset
    chunk_idx = chunk_offset
    other_idx = 16

    mask_bit_counter = 0
    current_mask = 0

    # preallocate result and index into it
    idx = 0
    ret = bytearray(decompressed_size);

    while idx < decompressed_size:
        # If we're out of bits, get the next mask
        if mask_bit_counter == 0:
            current_mask = int.from_bytes(in_bytes[other_idx : other_idx + 4], byteorder=byte_order)
            other_idx += 4
            mask_bit_counter = 32

        if (current_mask & 0x80000000):
            ret[idx] = in_bytes[chunk_idx]
            idx += 1
            chunk_idx += 1
        else:
            link = int.from_bytes(in_bytes[link_table_idx : link_table_idx + 2], byteorder=byte_order)
            link_table_idx += 2

            offset = idx - (link & 0xfff)

            count = link >> 12

            if count == 0:
                count_modifier = in_bytes[chunk_idx]
                chunk_idx += 1
                count = count_modifier + 18
            else:
                count += 2

            # Copy the block
            for i in range(count):
                ret[idx] = ret[offset + i - 1]
                idx += 1

        current_mask <<= 1
        mask_bit_counter -= 1

    return ret


def main(args):
    with open(args.infile, "rb") as f:
        raw_bytes = f.read()
    decompressed = decompress_yay0(raw_bytes, args.byte_order)
    with open(args.outfile, "wb") as f:
        f.write(decompressed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("infile")
    parser.add_argument("outfile")
    parser.add_argument("--byte-order", default="big")

    args = parser.parse_args()
    main(args)
