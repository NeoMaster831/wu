from pwn import u32, p32

unk_0 = bytes.fromhex("""
5B 62 9C A1 FD 82 BA 96
FD 82 BA 96 6A F9 69 10  F1 30 AA 21 FE BB 86 3A
4B F2 8D 8D A7 E6 57 FF  35 29 8B C0 59 99 C9 2B
1C 6E F7 3B 42 86 F0 27  64 21 0F 45 F3 DA 65 DA
66 DD 27 BA 39 83 5E A6  0A DD B5 17 35 71 60 9A
""")

unk_sbox = bytes.fromhex("""
A6 0B 31 D1 AC B5 DF 98  DB 72 FD 2F B7 DF 1A D0
ED AF E1 B8 96 7E 26 6A  45 90 7C BA 99 7F 2C F1
47 99 A1 24 F7 6C 91 B3  E2 F2 01 08 16 FC 8E 85
D8 20 69 63 69 4E 57 71  A3 FE 58 A4 7E 3D 93 F4
""")

unk_sbox = [ u32(unk_sbox[i:i+4]) for i in range(0, len(unk_sbox), 4) ]
unk_0 = [ u32(unk_0[i:i+4]) for i in range(0, len(unk_0), 4) ]

"xor input0, unk0[0] -> k1"
"sbox[k1[2] & 0xF]"
"sbox[k1[1] & 0xF] + sbox[k1[0] & 0xF]"

def encrypt(orig):

    assert len(orig) == 8
    input0 = u32(orig[0:4][::-1])
    input1 = u32(orig[4:8][::-1])
    for i in range(16):
        k1 = input0 ^ unk_0[i]
        k1 = p32(k1)[::-1]
        a1 = (unk_sbox[k1[0] & 0xF] + unk_sbox[k1[1] & 0xF]) & 0xFFFFFFFF
        a2 = unk_sbox[k1[2] & 0xf] ^ a1
        a3 = (unk_sbox[k1[3] & 0xF] + a2) & 0xFFFFFFFF
        k2 = a3 ^ input1
        input1 = u32(k1[::-1])
        input0 = k2
    
    input0, input1 = input0, input1
    b5 = unk_0[0x10] ^ input0
    b6 = unk_0[0x11] ^ input1
    input0, input1 = b6, b5
    return p32(input0)[::-1] + p32(input1)[::-1]

def _F(x):
    b = p32(x & 0xFFFFFFFF)[::-1]
    a1 = (unk_sbox[b[0] & 0xF] + unk_sbox[b[1] & 0xF]) & 0xFFFFFFFF
    a2 = (unk_sbox[b[2] & 0xF] ^ a1) & 0xFFFFFFFF
    a3 = (unk_sbox[b[3] & 0xF] + a2) & 0xFFFFFFFF
    return a3 & 0xFFFFFFFF

def decrypt(ct):
    assert len(ct) == 8
    outL = u32(ct[0:4][::-1])
    outR = u32(ct[4:8][::-1])

    R = (outL ^ unk_0[0x11]) & 0xFFFFFFFF  # undo post XOR+swap
    L = (outR ^ unk_0[0x10]) & 0xFFFFFFFF

    for i in range(15, -1, -1):
        t = R
        R = (L ^ _F(t)) & 0xFFFFFFFF        # R_old
        L = (t ^ unk_0[i]) & 0xFFFFFFFF     # L_old

    return p32(L)[::-1] + p32(R)[::-1]



target = """
C2 E2 7C DC 6D C0 8B 9C  0C A5 43 2D 09 4A 6C 61
37 66 CE C4 75 C0 AE 4A  86 71 F5 7A D4 75 93 19
"""
#target = """86db214783a6a06d"""
target = bytes.fromhex(target)
flag = b""
for i in range(0, len(target), 8):
    block = target[i:i+8]
    block = decrypt(block)
    block = decrypt(block)
    flag += block

print(flag)