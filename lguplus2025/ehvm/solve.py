def Add64(a, b):
    return (a + b) & 0xffff_ffff_ffff_ffff

def Sub64(a, b):
    return (a + 0x1_0000_0000_0000_0000 - b) & 0xffff_ffff_ffff_ffff

def Mul64(a, b):
    return (a * b) & 0xffff_ffff_ffff_ffff

def Rol64(value, shift):
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & 0xffff_ffff_ffff_ffff

def Calculate(Input, Index):
    A = Add64(0x28d907cf0167397, 0xa4ab0f2275ce3e68)
    B = Sub64(A, 0x97e8e8ab9f6faa16)
    C = 0xfd4fc4c089886b5f ^ B
    D = C ^ Input
    print(f"D: {D:016x}")

    E = Add64(0xcca7f7b9c4abbf61, 0xb042ea61da7e06ab)
    F = Sub64(E, 0x3f62f253a32a2f55)
    G = 0x32006b623f980393 ^ F
    H = Add64(D, G)
    print(f"H: {H:016x}")

    I = Add64(0x919f853f6fc6859c, 0x47fe3d936f1ba847)
    J = Sub64(I, 0xe482744aa548067b)
    K = 0x4154b1a2d4cead0f ^ J
    L = Mul64(H, K)
    print(f"L: {L:016x}")

    M = Rol64(L, Index % 64)
    print(f"M: {M:016x}")
    return M

def Ror64(value, shift):
    shift &= 63
    return ((value >> shift) | ((value << (64 - shift)) & 0xffff_ffff_ffff_ffff)) & 0xffff_ffff_ffff_ffff

def modinv_odd_2p64(m):
    return pow(m, -1, 1 << 64)

def InverseCalculate(M, Index):
    A = Add64(0x028d907cf0167397, 0xa4ab0f2275ce3e68)
    B = Sub64(A, 0x97e8e8ab9f6faa16)
    C = 0xfd4fc4c089886b5f ^ B

    E = Add64(0xcca7f7b9c4abbf61, 0xb042ea61da7e06ab)
    F = Sub64(E, 0x3f62f253a32a2f55)
    G = 0x32006b623f980393 ^ F

    I = Add64(0x919f853f6fc6859c, 0x47fe3d936f1ba847)
    J = Sub64(I, 0xe482744aa548067b)
    K = 0x4154b1a2d4cead0f ^ J

    r = Index % 64
    L = Ror64(M, r)

    if (K & 1) == 0:
        raise ValueError
    
    invK = modinv_odd_2p64(K)

    H = Mul64(L, invK)
    D = Sub64(H, G)
    Input = C ^ D
    return Input

from pwn import u64, p64

calc = Calculate(u64(b"WaneLove"), 0)
assert InverseCalculate(calc, 0) == u64(b"WaneLove")

with open('enc.bin', 'rb') as f:
    enc = f.read()

flag = b""
for i in range(0, len(enc), 8):
    flag += p64(InverseCalculate(u64(enc[i:i+8]), i // 8))

print(flag)