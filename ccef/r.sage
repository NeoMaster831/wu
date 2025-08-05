F = GF(2)['x']
p = x^8 + x^4 + x^3 + x^2 + 1
FF.<a> = GF(2^8, modulus=p)
#P.<c0, c1, c2, c3, c4, c5, c6, c7> = PolynomialRing(FF)

cl = bytes.fromhex("""
F3 BD 27 86 31 80 25 B9  61 6B A2 A9 B4 83 3E CA
49 23 96 70 ED 22 3C 17  10 70 5A BA 0C 6A 7C A5
8D 5B 99 D7 6B C2 02 7C  7F 0F 05 A5 64 4D 2A A4
62 0E 2A FF 56 83 28 97  5B 72 5B D7 EB 05 ED 6F
""")

for i in range(4):
    M = []
    ans_li = []
    for j in range(16):
        li = [FF.fetch_int(2) ** ((23 - k) * j) for k in range(8)]
        M.append(li)
        res = FF.fetch_int(0)
        for k in range(16):
            res += FF.fetch_int(cl[i*16+j]) * FF.fetch_int(2) ** ((15 - k) * j)
        ans_li.append(res * -1)
    ans = matrix(M).solve_right(vector(ans_li))
    for i in range(8):
        print(chr(ans[i].integer_representation()))