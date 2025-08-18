from sage.all import *

TABLE = [
    171, 68, 62, 158, 14, 181, 123, 43, 209,
    174, 136, 39, 10, 48, 185, 228, 142, 125,
    99, 37, 226, 50, 246, 146, 63, 195, 64,
    67, 175, 45, 93, 130, 165, 214, 63, 25,
    77, 1, 173, 85, 204, 72, 38, 135, 215,
    217, 240, 55, 116
]

REAL = [
    12974, 25518, 44848, 58082, 45028, 58014, 10048, 53552,
    37426, 43985, 11715, 40493, 34826, 33438, 34826, 17202,
    11662, 15997, 44643, 37550, 37443, 34941, 46400, 12387,
    24034, 12864, 2570, 3652, 40676, 36389, 16081, 63171,
    17326, 10130, 16630, 44867, 12971, 63157, 3683, 12862
]


def rev_bits(val: int, width: int) -> int:
    return int(f"{val:0{width}b}"[::-1], 2)


def decode(encoded: list[int]) -> str:
    bitstream = rev_bits(TABLE.index(encoded[-1] & 0xFF), 2)
    for w in encoded[-2::-1]:
        bitstream = (bitstream << 5) | rev_bits(TABLE.index(w & 0xFF), 5)
        bitstream = (bitstream << 5) | rev_bits(TABLE.index((w >> 8) & 0xFF), 5)

    data_bytes = list(bitstream.to_bytes(49, "little"))

    R = IntegerModRing(251)
    mat_tbl = Matrix(R, 7, 7, TABLE).transpose()
    mat_data = Matrix(R, 7, 7, data_bytes).transpose()

    decoded_matrix = mat_tbl.inverse() * mat_data
    return "".join(chr(int(decoded_matrix[i, j])) for j in range(7) for i in range(7))


if __name__ == "__main__":
    print(decode(REAL))

