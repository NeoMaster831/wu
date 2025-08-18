def decode(input_bytes):
    input_len = len(input_bytes)
    input_pos = 0
    output = bytearray()
    
    while input_pos + 3 < input_len:
        b1 = input_bytes[input_pos]
        b2 = input_bytes[input_pos + 1]
        b3 = input_bytes[input_pos + 2]
        b4 = input_bytes[input_pos + 3]
        
        out1 = (b1 << 2) | ((b4 & 0x30) >> 4)
        out2 = (b2 << 2) | ((b4 & 0x0C) >> 2)
        out3 = (b3 << 2) | (b4 & 0x03)
        
        output.append(out1)
        output.append(out2)
        output.append(out3)
        
        input_pos += 4
    
    return bytes(output)

gay = "4E6nQpOkBcWmIfXorxGhg_z81qC3sv79DlRSN5PHeUZAwVYuat0TF2djJbKLyMi"
ggg = "lScv9oQ6VgELTPBdHnxp9dND"
ggg_as_num = [ gay.index(c) for c in ggg ]

de = decode(ggg_as_num)

de += bytes([ 0xa5 ])
de = list(de)

def ROL(k, n):
    return ((k << n) | (k >> (8 - n))) & 0xFF

def ROR(x, n):
    return (x >> n) | ((x & ((1 << n) - 1)) << (8 - n))

assert(ROL(0x7d, 5) == ROR(0x7d, 3))

for i in range(17, -1, -1):
    de[i] = ROR(de[i], 4)
    de[i] ^= de[i + 1]
    de[i] = ROR(de[i], 5)
    de[i] ^= 0x44

print(bytes(de)[:18])
