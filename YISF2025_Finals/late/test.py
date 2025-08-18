from Crypto.Cipher import AES

C190 = bytes.fromhex("DE AD BE EF CA FE BA BE  13 37 C0 DE F0 0D FE ED")  # xmmword_406190
C1A0 = bytes.fromhex("01 23 45 67 89 AB CD EF  FE DC BA 98 76 54 32 10")  # xmmword_4061A0
S130 = bytes.fromhex("3C 3F 42 45 48 4B 4E 51  54 57 5A 5D 60 63 66 69")  # xmmword_406130
S140 = bytes.fromhex("7E 83 88 8D 92 97 9C A1  A6 AB B0 B5 BA BF C4 C9")  # xmmword_406140
S150 = bytes.fromhex("91 93 95 97 99 9B 9D 9F  A1 A3 A5 A7 A9 AB AD AF")  # xmmword_406150
S160 = bytes.fromhex("A7 AA AD B0 B3 B6 B9 BC  BF C2 C5 C8 CB CE D1 D4")  # xmmword_406160

T0 = bytes.fromhex("93 24 09 F9 7A 0B 68 6C  2F EE 04 D0 59 E4 82 9A")  # xmmword_406170
T1 = bytes.fromhex("86 B5 47 D3 48 73 5F 4E  4F 52 93 8C F0 88 53 1C")  # xmmword_406180
def bxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def aes_dec(block: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(block)

def recover() -> bytes:
    KC190_0 = bxor(C190, S130)          # early const-layer key for block 0
    KC190_1 = bxor(C190, S140)          # early const-layer key for block 1
    KC1A0_0 = bxor(C1A0, S130)          # final const-layer key for block 0
    KC1A0_1 = bxor(C1A0, S140)          # final const-layer key for block 1
    y0 = aes_dec(bxor(T0, S150), KC1A0_0)
    y1 = aes_dec(bxor(T1, S160), KC1A0_1)
    w0 = aes_dec(bxor(y0, S150), KC190_0)
    w1 = aes_dec(bxor(y1, S160), KC190_1)
    return w0 + w1

print(recover().hex())