import struct

raw_words = bytes.fromhex(
'''
00 00 B8 41 00 00 98 42  00 00 BC 42 00 00 14 42
00 00 B2 42 00 00 68 42  00 00 FE 42 00 00 2C 42
00 00 0C 42 00 00 EE 42  00 00 38 42 00 00 92 42
00 00 60 41 00 00 A4 42  00 00 D2 42 00 00 74 42
00 00 E2 42 00 00 6C 42  00 00 AE 42 00 00 24 42
00 00 84 42 00 00 1A 43  00 00 D8 41 00 00 C4 42
00 00 A8 42 00 00 B0 41  00 00 17 43 00 00 88 42
00 00 C0 42 00 00 04 42  00 00 0E 43 00 00 9E 42
00 00 5C 42 00 00 90 42  00 00 06 43 00 00 E8 41
00 00 25 43 00 00 B6 42  00 00 18 42 00 00 EA 42
00 00 3C 42 00 00 F8 42  00 00 88 41 00 00 AA 42
00 00 D8 42 00 00 7C 42  00 00 15 43 00 00 D0 41
00 00 D4 42 00 00 A6 42  00 00 34 42 00 00 1C 43
00 00 F8 41 00 00 B8 42  00 00 94 42 00 00 0B 43
00 00 E6 42 00 00 10 42  00 00 22 43 00 00 8E 42
00 00 C2 42 00 00 98 41  00 00 00 43 00 00 58 42
'''
)

words = []
for i in range(0, len(raw_words), 4):
    word = struct.unpack('<f', raw_words[i:i+4])[0]
    words.append(word)

print(words)

rk = [[c[0], c[1], c[2], c[3]] for c in zip(*[iter(words)]*4)]
print(rk)

def plane_to_bytes(plane: bytes) -> bytes:
    """512 B bitslice → 64 B 바이트 배열 (암호문 → 평문 전환용)"""
    from struct import unpack_from
    if len(plane)!=512: raise ValueError
    w = [unpack_from("<I",plane,4*i)[0] for i in range(128)]
    out = bytearray(64)
    for bit in range(128):           # 16바이트 × 8비트
        for blk in range(4):         # 32-bit 워드의 8번째 비트마다 정보
            if w[bit] & (1<<(blk*8)):
                out[(bit>>3) ^ (blk*16)] |= 1<<(bit&7)
    return bytes(out)

raw_cipher = bytes.fromhex(
'''
E4 D1 E4 09 D6 A1 F9 B6  C1 93 C1 09 41 C5 E8 83
B5 D8 13 83 47 04 AE 6F  B2 25 7A 83 0D D8 9E 6F
AB BA 66 65 69 17 04 B6  61 CC 6C 83 11 9C FB 83
2E EB FB 83 8F 3A F7 6F  97 13 DB B6 F7 0A 8C B6
73 89 55 37 EA 1E D4 37  C3 0B 25 60 B6 0F 41 7F
86 03 8F 60 5C 56 5C 60  9A F3 BD 86 40 96 40 86
8D 87 8D 60 FE 5C 68 37  E7 2F D2 60 42 EF 8B 37
91 4C AA 94 1D 73 3F 3F  71 F4 56 60 C5 E8 35 37
9A 48 FA 57 1C D1 95 48  8D 6B 6A FA 1F F9 1F E5
F9 1F 65 FA A0 46 10 FA  D3 01 91 48 92 40 83 48
E5 75 B3 FA 9D 7B 9D FA  C4 22 57 FA 02 CF 2C 48
6D A0 72 48 06 E0 2A E5  AC 7E 69 48 A3 71 E1 48
D5 8E 4D E2 69 C5 66 D7  35 B6 79 B5 8C 6C E5 D6
7B 9B BE D6 29 85 3A 59  74 9C DB D7 2C CC 35 B5
2B 12 75 59 D2 19 62 59  8C B5 E0 D7 27 D8 22 D6
51 23 1D D6 8A 6A 90 D6  74 8B AE D6 F3 86 88 59
66 71 7B 83 65 A6 9B B6  AE 83 1D 09 41 C5 E8 83
6B 0F 5F 83 F3 C6 29 B6  B2 25 7A 83 0D D8 9E 6F
6E AF C4 65 69 17 04 B6  84 C8 24 83 11 9C FB 83
2E EB FB 83 D4 A4 D4 65  97 13 DB B6 F7 0A 8C B6
5C 56 5C 60 B5 12 35 3F  40 96 40 86 5D 39 DE 7F
EA 1E D4 37 73 89 55 37  4B D1 5B 7F C3 0B 25 60
1D 73 3F 3F F7 21 FE 60  B8 D9 9D 7F 2F 88 9D 60
FE 5C 68 37 8D 87 8D 60  56 CB E6 37 EE 74 E2 3F
CC 1E 18 48 99 4B 99 57  EF 16 02 99 8D 6B 6A FA
A5 5C 51 99 F9 1F 65 FA  92 40 83 48 EB 39 EB 57
9D 7B 9D FA B0 56 2C FA  77 A5 17 48 C4 22 57 FA
CE 28 C2 E5 6D A0 72 48  A3 71 E1 48 AC 7E 69 48
69 C5 66 D7 D5 8E 4D E2  8C 6C E5 D6 30 D0 5B B5
29 85 3A 59 1A 99 D7 D6  2C CC 35 B5 7D 2B 07 59
D2 19 62 59 48 BF BE 59  F7 17 32 B5 53 A4 C4 59
E2 02 93 C9 51 23 1D D6  E7 D6 0D E2 74 8B AE D6
'''
)

print(plane_to_bytes(raw_cipher))

print(words)

def xtime(b): return ((b<<1)&0xFF) ^ (0x1B if b&0x80 else 0)
def gf_inv(b):
    if b==0: return 0
    x=1
    for _ in range(253): x=xtime(x)^b
    return x
S  = [0]*256
Si = [0]*256
for x in range(256):
    y = gf_inv(x)
    z = y ^ ((y<<1)|(y>>7)&1) ^ ((y<<2)|(y>>6)&3) ^ ((y<<3)|(y>>5)&7) \
        ^ ((y<<4)|(y>>4)&0xF) ^ 0x63
    S[x] ,Si[z&0xFF] = z&0xFF ,x

def mul(a,b):
    r=0
    while b:
        if b&1: r^=a
        a = xtime(a)
        b >>=1
    return r & 0xFF
mIx = [mul(x,c) for c in (0x0E,0x0B,0x0D,0x09) for x in range(256)]

def inv_mix(c):
    out = bytearray(16)
    for col in range(4):
        s = c[col*4:(col+1)*4]
        out[col*4+0] = mIx[ 0*256+s[0]]^mIx[ 1*256+s[1]]^mIx[ 2*256+s[2]]^mIx[ 3*256+s[3]]
        out[col*4+1] = mIx[ 3*256+s[0]]^mIx[ 0*256+s[1]]^mIx[ 1*256+s[2]]^mIx[ 2*256+s[3]]
        out[col*4+2] = mIx[ 2*256+s[0]]^mIx[ 3*256+s[1]]^mIx[ 0*256+s[2]]^mIx[ 1*256+s[3]]
        out[col*4+3] = mIx[ 1*256+s[0]]^mIx[ 2*256+s[1]]^mIx[ 3*256+s[2]]^mIx[ 0*256+s[3]]
    return out

def inv_shift(b):
    t = bytearray(b)
    t[ 1],t[ 5],t[ 9],t[13] = b[13],b[ 1],b[ 5],b[ 9]
    t[ 2],t[ 6],t[10],t[14] = b[10],b[14],b[ 2],b[ 6]
    t[ 3],t[ 7],t[11],t[15] = b[ 7],b[11],b[15],b[ 3]
    return t

state = bytearray(plane_to_bytes(raw_cipher))

state = bytes(a^b for a,b in zip(state, rk[15]))
state = inv_shift(state)
state = bytearray(Si[x] for x in state)

for r in range(14, -1, -1):
    state = bytes(a^b for a,b in zip(state, rk[r]))
    state = inv_mix(state)
    state = inv_shift(state)
    state = bytearray(Si[x] for x in state)

state = bytes(a^b for a,b in zip(state, rk[0]))