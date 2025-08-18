cl = bytes.fromhex("""
F3 BD 27 86 31 80 25 B9  61 6B A2 A9 B4 83 3E CA
49 23 96 70 ED 22 3C 17  10 70 5A BA 0C 6A 7C A5
8D 5B 99 D7 6B C2 02 7C  7F 0F 05 A5 64 4D 2A A4
62 0E 2A FF 56 83 28 97  5B 72 5B D7 EB 05 ED 6F
""")

log_list = bytes.fromhex("""
00 00 01 19 02 32 1A C6  03 DF 33 EE 1B 68 C7 4B
04 64 E0 0E 34 8D EF 81  1C C1 69 F8 C8 08 4C 71
05 8A 65 2F E1 24 0F 21  35 93 8E DA F0 12 82 45
1D B5 C2 7D 6A 27 F9 B9  C9 9A 09 78 4D E4 72 A6
06 BF 8B 62 66 DD 30 FD  E2 98 25 B3 10 91 22 88
36 D0 94 CE 8F 96 DB BD  F1 D2 13 5C 83 38 46 40
1E 42 B6 A3 C3 48 7E 6E  6B 3A 28 54 FA 85 BA 3D
CA 5E 9B 9F 0A 15 79 2B  4E D4 E5 AC 73 F3 A7 57
07 70 C0 F7 8C 80 63 0D  67 4A DE ED 31 C5 FE 18
E3 A5 99 77 26 B8 B4 7C  11 44 92 D9 23 20 89 2E
37 3F D1 5B 95 BC CF CD  90 87 97 B2 DC FC BE 61
F2 56 D3 AB 14 2A 5D 9E  84 3C 39 53 47 6D 41 A2
1F 2D 43 D8 B7 7B A4 76  C4 17 49 EC 7F 0C 6F F6
6C A1 3B 52 29 9D 55 AA  FB 60 86 B1 BB CC 3E 5A
CB 59 5F B0 9C A9 A0 51  0B F5 16 EB 7A 75 2C D7
4F AE D5 E9 E6 E7 AD E8  74 D6 F4 EA A8 50 58 AF
""")

exp_list = bytes.fromhex("""
01 02 04 08 10 20 40 80  1D 3A 74 E8 CD 87 13 26
4C 98 2D 5A B4 75 EA C9  8F 03 06 0C 18 30 60 C0
9D 27 4E 9C 25 4A 94 35  6A D4 B5 77 EE C1 9F 23
46 8C 05 0A 14 28 50 A0  5D BA 69 D2 B9 6F DE A1
5F BE 61 C2 99 2F 5E BC  65 CA 89 0F 1E 3C 78 F0
FD E7 D3 BB 6B D6 B1 7F  FE E1 DF A3 5B B6 71 E2
D9 AF 43 86 11 22 44 88  0D 1A 34 68 D0 BD 67 CE
81 1F 3E 7C F8 ED C7 93  3B 76 EC C5 97 33 66 CC
85 17 2E 5C B8 6D DA A9  4F 9E 21 42 84 15 2A 54
A8 4D 9A 29 52 A4 55 AA  49 92 39 72 E4 D5 B7 73
E6 D1 BF 63 C6 91 3F 7E  FC E5 D7 B3 7B F6 F1 FF
E3 DB AB 4B 96 31 62 C4  95 37 6E DC A5 57 AE 41
82 19 32 64 C8 8D 07 0E  1C 38 70 E0 DD A7 53 A6
51 A2 59 B2 79 F2 F9 EF  C3 9B 2B 56 AC 45 8A 09
12 24 48 90 3D 7A F4 F5  F7 F3 FB EB CB 8B 0B 16
2C 58 B0 7D FA E9 CF 83  1B 36 6C D8 AD 47 8E 01
""")

def gf_add(a: int, b: int):
    return a ^^ b

def gf_mul(a: int, b: int):
    return exp_list[(log_list[a] + log_list[b]) % 0xFF]

def gf_pow(a: int, b: int):
    return exp_list[(b * log_list[a]) % 0xFF]

F = GF(2)['x']
p = x^8 + x^4 + x^3 + x^2 + 1
FF.<a> = GF(2^8, modulus=p)

for i in range(0, len(cl), 16):
    
    cd = cl[i:i+16]
    m = []
    v = []
    for j in range(16):

        s = 0
        for k in range(16):
            s = gf_add(s, gf_mul(gf_pow(gf_pow(2, j), k), cd[15 - k]))
        v.append(-FF.fetch_int(s))
        
        Row = []
        for k in range(8):
            Row.append(FF.fetch_int(gf_pow(gf_pow(2, j), 23 - k)))
        m.append(Row)
    
    m = matrix(m)
    v = vector(v)

    sol = m.solve_right(v)
    for i in range(8):
        print(chr(sol[i].integer_representation()), end='')