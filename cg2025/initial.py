target = bytes.fromhex("""
36 E2 2E 86 6D 24 CD 94  1A 1A 46 9B 49 83 61 15
20 B2 47 EA 0D 42 E9 3D  E4 74 1B 16 8B 54 2E AA
""")

target = list(target)

def ROL(k, n):
    return ((k << n) | (k >> (8 - n))) & 0xFF

for i in range(32):
    target[i] = ROL(target[i], i & 6)

sbox = bytes.fromhex("""
45 B8 1A 80 47 CB D6 19  1D 58 56 E2 36 E4 27 65
B1 73 E9 5C 7E 42 7C DE  71 61 F6 48 F5 22 57 1B
AF DB 8D 8B C0 2B D4 A1  CC F2 EB BE 37 38 D9 1E
63 E3 4D 94 13 BA 9C 86  10 35 FC 4F D7 D3 7B 3A
C9 8F D0 24 F1 05 2C 53  5E 8C 96 3D A6 A4 6E CF
5B 6D 04 ED 12 7A 17 25  34 DC AD E1 20 91 75 06
C4 74 6F 78 00 6C C2 AB  A9 9F B0 16 33 90 CD B2
3C AA 9B 51 4E 3F 1C 50  FA 18 E8 B4 54 B9 3B 49
F9 B6 99 9D 7D 0E 66 EF  FF 15 97 55 0F F8 21 2E
83 F3 95 0A A8 BC 5D B5  32 FD F7 D8 26 89 64 2F
A7 CA 0D EC C3 FB AC B7  09 EE 84 92 79 01 07 A2
77 4A 02 60 39 A0 93 BD  88 C6 E5 E7 CE 23 BB DF
85 C1 59 EA D2 9A E6 31  14 FE C5 44 11 87 67 D1
4B DA 6A 52 BF 0B F4 5A  8A 08 28 A3 7F 30 70 9E
2D 0C 82 AE 40 68 43 76  E0 3E 8E 2A 4C A5 D5 69
72 C8 81 6B 46 C7 B3 1F  5F 98 29 F0 62 03 DD 41
""")

for i in range(32):
    target[i] = sbox.index(target[i])

print(bytes(target))

target[31] ^= target[0]
for i in range(30, -1, -1):
    target[i] ^= target[i + 1]


print(bytes(target))
