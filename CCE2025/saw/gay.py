from pathlib import Path

def write_pbm_p4(path, w, h, bits):
    assert len(bits) == w*h
    hdr = f"P4\n{w} {h}\n".encode()
    rows = bytearray()
    for y in range(h):
        b = 0; k = 0
        for x in range(w):
            b = (b << 1) | (1 if bits[y*w+x] else 0)
            k += 1
            if k == 8:
                rows.append(b); b=0; k=0
        if k:  # 행 패딩
            rows.append(b << (8-k))
    Path(path).write_bytes(hdr + rows)
w=h=32
import random
randomic = [  random.randint(0, 1) for _ in range(w * h) ]
write_pbm_p4("randomic.pbm", w, h, randomic)