from typing import List, Tuple

def varint_le(bs, i):
    x = 0
    shift = 0
    while True:
        b = bs[i]; i += 1
        x |= (b & 0x7F) << shift
        if b < 0x80:
            return x, i
        shift += 7

def reassemble_mask(n_items: int, groups: List[Tuple[int, List[int]]]) -> bytes:
    out = bytearray(n_items)
    for val, pos_list in groups:
        for p in pos_list:
            if not (0 <= p < n_items):
                raise ValueError("position out of range")
            out[p] = val & 0xFF
    return bytes(out)

def bits_to_bool_rows(mask_bytes: bytes, w2: int, h2: int):
    row_bytes = (w2 + 7) // 8
    assert len(mask_bytes) == row_bytes * h2
    img = []
    k = 0
    for _ in range(h2):
        row = []
        for j in range(row_bytes):
            b = mask_bytes[k]; k += 1
            for bit in range(8):
                if len(row) == w2: break
                row.append((b >> (7 - bit)) & 1)
        img.append(row)
    return img

if __name__ == "__main__":
    n = 4
    groups = [
        (0xC0, [0, 1]),
        (0x30, [2, 3]),
    ]
    mask = reassemble_mask(n, groups)
    print(mask)
    img = bits_to_bool_rows(mask, w2=4, h2=4)

    print(img)