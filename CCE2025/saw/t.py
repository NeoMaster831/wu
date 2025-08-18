def decode(tokens, base):
    out = []
    i = j = 0           # i: 토큰 인덱스, j: base 인덱스
    while i < len(tokens):
        t = tokens[i]
        if t == 0x00:
            out.append(base[j]); j += 1; i += 1
        elif t == 0x01:
            out.append(tokens[i+1]); i += 2
        else:
            raise ValueError("bad token")
    return bytes(out)

test_token = bytes.fromhex("""
00 00 00 00 00  01 9F  01 DB  00  01 3F  01 53  00  01 F5  00
01 AB  01 E7  00 00 00  01 6D  01 D8  00  01 78  01 9A  00 00
01 9B  01 5F  00  01 1A  01 5B  00 00 00  01 BE  00  01 4F  01 5D
00 00  01 B5  01 56  01 FE  00 00  01 7D  00  01 B6  01 FF  00 00
01 EF  01 B3  00  01 EE  01 B7
""")

test_base = bytes.fromhex("""
C7 51 4D 29 3F F7 AE 2D 20 61 0C 39 BE 9A B1 71 33 F8 48
""")

print(decode(test_token, test_base))