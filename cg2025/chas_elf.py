def ROL(v, k: int):
    BITS = 32
    k = k % BITS
    return ((v << k) & (2 ** BITS - 1)) | (v >> (BITS - k))

def ROR(v, k: int):
    BITS = 32
    k = k % BITS
    return (v >> k) | ((v << (BITS - k)) & (2 ** BITS - 1))

def _four(Arr, i1, i2, i3, i4):
    r8d = Arr[i1]
    r9d = Arr[i2]
    r10d = Arr[i3]
    r11d = Arr[i4]

    r8d += r9d
    r8d &= 0xffffffff
    r11d ^= r8d
    r11d = ROL(r11d, 0x10)
    r10d += r11d
    r10d &= 0xffffffff
    r9d ^= r10d
    r9d = ROL(r9d, 0xc)
    r8d += r9d
    r8d &= 0xffffffff
    r11d ^= r8d
    r11d = ROL(r11d, 0x8)
    r10d += r11d
    r10d &= 0xffffffff
    r9d ^= r10d
    r9d = ROL(r9d, 0x7)

    Arr[i1] = r8d
    Arr[i2] = r9d
    Arr[i3] = r10d
    Arr[i4] = r11d


def _two(Arr1, Arr2):
    for i in range(64):
        Arr2[i] = Arr1[i]

def _three(Arr1, Arr2):
    for i in range(64):
        Arr2[i] = Arr1[i]

sbox = bytes.fromhex("""
63 7C 77 7B F2 6B 6F C5  30 01 67 2B FE D7 AB 76
CA 82 C9 7D FA 59 47 F0  AD D4 A2 AF 9C A4 72 C0
B7 FD 93 26 36 3F F7 CC  34 A5 E5 F1 71 D8 31 15
04 C7 23 C3 18 96 05 9A  07 12 80 E2 EB 27 B2 75
09 83 2C 1A 1B 6E 5A A0  52 3B D6 B3 29 E3 2F 84
53 D1 00 ED 20 FC B1 5B  6A CB BE 39 4A 4C 58 CF
D0 EF AA FB 43 4D 33 85  45 F9 02 7F 50 3C 9F A8
51 A3 40 8F 92 9D 38 F5  BC B6 DA 21 10 FF F3 D2
CD 0C 13 EC 5F 97 44 17  C4 A7 7E 3D 64 5D 19 73
60 81 4F DC 22 2A 90 88  46 EE B8 14 DE 5E 0B DB
E0 32 3A 0A 49 06 24 5C  C2 D3 AC 62 91 95 E4 79
E7 C8 37 6D 8D D5 4E A9  6C 56 F4 EA 65 7A AE 08
BA 78 25 2E 1C A6 B4 C6  E8 DD 74 1F 4B BD 8B 8A
70 3E B5 66 48 03 F6 0E  61 35 57 B9 86 C1 1D 9E
E1 F8 98 11 69 D9 8E 94  9B 1E 87 E9 CE 55 28 DF
8C A1 89 0D BF E6 42 68  41 99 2D 0F B0 54 BB 16
""")

def GenKey1(b):

    kv = []

    for _ in range(32):
        kv.append(sbox[b])
        if b % 8 != 7:
            b += 9
        else:
            b += 1
        b %= 256
    
    return bytes(kv)

def GenKey2(b):

    kv = []
    for _ in range(12):
        kv.append(sbox[b])
        if b % 21 != 20:
            b += 22
        else:
            b += 1
        b %= 252
    
    return bytes(kv)


from pwn import u32, p32

target = bytes.fromhex("147274ff36e71d07cfad08e75f0352799d0081c6862fd96aebb08566f49ca86f15528c5121940ddc3ee92b816b1147be934d03389ee0cfad5b539ebf35feb969")
print(len(target))

for b in range(0x21, 0x22):

    for idx in range(0, len(target), 64):
        key1 = GenKey1(b)
        key2 = GenKey2(b)
        initial_key = b"Codegate2025 Pre" + key1 + b"\x00\x00\x00\x00" + key2

        initial_key = [ u32(initial_key[i:i+4]) for i in range(0, len(initial_key), 4) ]

        vArr2 = [] + initial_key

        for _ in range(10):
            _four(vArr2, 0, 4, 8, 12)
            _four(vArr2, 1, 5, 9, 13)
            _four(vArr2, 2, 6, 10, 14)
            _four(vArr2, 3, 7, 11, 15)
            _four(vArr2, 0, 5, 10, 15)
            _four(vArr2, 1, 6, 11, 12)
            _four(vArr2, 2, 7, 8, 13)
            _four(vArr2, 3, 4, 9, 14)
        
        for i in range(16):
            vArr2[i] += initial_key[i]
            vArr2[i] &= 0xffffffff


        vArr2 = [ p32(v) for v in vArr2 ]
        vArr2 = b"".join(vArr2)
        assert(len(vArr2) == 64)

        flag = b""
        for i in range(idx, idx+64):
            flag += bytes([ target[i] ^ vArr2[i] ])
        print(flag)
