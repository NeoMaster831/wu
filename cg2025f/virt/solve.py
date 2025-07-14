target = bytes.fromhex(
'''
E0 F9 D7 A2 2A F7 E7 FA  0D A4 D4 69 78 EA 36 71
1A DC A2 48 A3 D2 52 3E  66 71 C3 D4 92 03 4B F3
68 9E 37 01 C1 38 90 AD  F9 A4 DA D8 19 30 C6 E8
41 DF C6 5C 22 7D 99 B1  B4 70 D6 D6 70 B4 A2 99
'''
)

def rotl8(x: int, k: int) -> int:
    return ((x << k) | (x >> (8 - k))) & 0xFF

def decrypt_block(ct: bytes) -> bytes:
    pt = bytearray(len(ct))

    for i, c in enumerate(ct):
        t = (c - 0x2A) & 0xFF
        t ^= ((0x0D * i + 7) & 0xFF)
        rot = (i % 7) + 1
        pt[i] = rotl8(t, rot)

    while pt and pt[-1] == 0xAA:
        pt.pop()

    return bytes(pt)

print(decrypt_block(target))