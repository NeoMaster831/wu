import numpy as np

POLY4=0x13
MASKS=[0x9A,0x65,0x4B,0xB4]
PERM=[0x1B,0x6C,0xB1,0xD2]
K=257.0

def gf16_mul(a,b,poly=POLY4):
    r=0
    for _ in range(4):
        if b&1:r^=a
        b>>=1
        hi=a&8
        a=(a<<1)&0xF
        if hi:a^=poly
    return r

def gf16_inv(a):
    if a==0:return 0
    t=a
    for _ in range(3):
        t=gf16_mul(t,t)
        a=gf16_mul(a,t)
    return a

def stage1(flag):
    off=[0x38,0x30,0x28,0x20,0x18,0x10,0x8,0]
    buf=[]
    for i in range(8):
        vals=[np.float32(np.int8(flag[i+o])) for o in off]
        buf.append(np.array(vals,dtype=np.float32))
    return np.stack(buf)

def rot4(v,n):
    n&=3
    return((v<<n)|(v>>(4-n)))&0xF

def affine4(b,c):
    return b^rot4(b,1)^rot4(b,2)^rot4(b,3)^c

W = [23.0, 76.0, 94.0, 37.0, 89.0, 58.0, 127.0, 43.0, 35.0, 119.0, 46.0, 73.0, 14.0, 82.0, 105.0, 61.0, 113.0, 59.0, 87.0, 41.0, 66.0, 154.0, 27.0, 98.0, 84.0, 22.0, 151.0, 68.0, 96.0, 33.0, 142.0, 79.0, 55.0, 72.0, 134.0, 29.0, 165.0, 91.0, 38.0, 117.0, 47.0, 124.0, 17.0, 85.0, 108.0, 63.0, 149.0, 26.0, 106.0, 83.0, 45.0, 156.0, 31.0, 92.0, 74.0, 139.0, 115.0, 36.0, 162.0, 71.0, 97.0, 19.0, 128.0, 54.0]

def stage2(mat, weights=W):
    wmat = np.reshape(np.array(weights, dtype=np.float32), (8, 8))

    out = np.empty_like(mat)
    for r in range(8):
        v   = mat[r] / K
        p   = PERM[r & 3]          # 0x1B / 0x6C / 0xB1 / 0xD2
        idx = [(p >> (2*k)) & 3 for k in range(4)]
        idx = idx + [i+4 for i in idx]
        w   = wmat[r][idx]
        out[r] = v * w
    return out

def stage3(mat, masks=MASKS):
    out = np.empty((16, 8), dtype=np.float32)
    k = 0
    for r in range(0, 8, 2):
        a, b = mat[r], mat[r+1]
        for m in masks:
            sel = ((m >> np.arange(8)) & 1).astype(bool)
            out[k] = np.where(sel, a, b)
            k += 1
    return out


SEEDS = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0xC5, 0x01, 0x67]

def build_sbox(seed: int) -> np.ndarray:
    tbl = np.empty(256, dtype=np.uint8)

    c_lo =  seed        & 0xF
    c_hi = (seed >> 4)  & 0xF

    for x in range(256):
        hi, lo = x >> 4, x & 0xF
        hi_s = affine4(gf16_inv(hi), c_hi)
        lo_s = affine4(gf16_inv(lo), c_lo)

        tbl[x] = (hi_s << 4) | lo_s
    return tbl

def stage4(mat16x8: np.ndarray) -> np.ndarray:
    if mat16x8.shape != (16, 8) or mat16x8.dtype != np.float32:
        raise ValueError("expect (16,8) float32 matrix")

    buf  = mat16x8.view(np.uint8).reshape(16, 32)
    out  = np.empty_like(buf)

    for r in range(16):
        sbox = build_sbox(SEEDS[r & 7])
        out[r] = sbox[buf[r]]

    return out.view(np.float32).reshape(16, 8)

cipher = stage1(b"0123456789abcdef" * 4)
cipher = stage2(cipher)
cipher = stage3(cipher)
cipher = stage4(cipher)