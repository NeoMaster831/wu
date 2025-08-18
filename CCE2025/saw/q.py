def _get_bit(buf: bytes, rowbytes: int, x: int, y: int) -> int:
    """PBM(P4) MSB-first에서 (x,y) 픽셀을 0/1로 반환."""
    b = buf[y * rowbytes + (x >> 3)]
    return (b >> (7 - (x & 7))) & 1

def _set_bit(buf: bytearray, rowbytes: int, x: int, y: int, v: int) -> None:
    """PBM(P4) MSB-first에서 (x,y) 픽셀을 v(0/1)로 설정."""
    i = y * rowbytes + (x >> 3)
    m = 1 << (7 - (x & 7))
    if v:
        buf[i] |= m
    else:
        buf[i] &= ~m & 0xFF

def downscale_2x_majority(src_bits: bytes, w: int, h: int) -> tuple[bytes, int, int]:
    if w <= 0 or h <= 0:
        return b"", 0, 0

    src_rowbytes = (w + 7) // 8
    w2, h2 = (w + 1) // 2, (h + 1) // 2
    dst_rowbytes = (w2 + 7) // 8
    dst = bytearray(dst_rowbytes * h2)

    for y2 in range(h2):
        y0 = 2 * y2
        y1 = y0 + 1
        for x2 in range(w2):
            x0 = 2 * x2
            x1 = x0 + 1

            v51 = 0  # 1의 개수
            v52 = 0  # 유효 표본 개수

            # top-left
            if x0 < w and y0 < h:
                v51 += _get_bit(src_bits, src_rowbytes, x0, y0)
                v52 += 1
            # top-right
            if x1 < w and y0 < h:
                v51 += _get_bit(src_bits, src_rowbytes, x1, y0)
                v52 += 1
            # bottom-left
            if x0 < w and y1 < h:
                v51 += _get_bit(src_bits, src_rowbytes, x0, y1)
                v52 += 1
            # bottom-right
            if x1 < w and y1 < h:
                v51 += _get_bit(src_bits, src_rowbytes, x1, y1)
                v52 += 1

            out_bit = 1 if (2 * v51) > (v52 - 1) else 0  # 어셈블리 조건 그대로
            _set_bit(dst, dst_rowbytes, x2, y2, out_bit)

    return bytes(dst), w2, h2

with open("randomic.pbm", 'rb') as f:
    pbm_data = f.read()

pbm_data = pbm_data.splitlines()
w, h = map(int, pbm_data[1].split())
pbm_data = b"\n".join(pbm_data[2:])

print(downscale_2x_majority(pbm_data, w, h))