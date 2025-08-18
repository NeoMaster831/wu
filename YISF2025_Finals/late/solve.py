# solver_please_dont_be_late.py
# -*- coding: utf-8 -*-
# 자세한 설명/로그는 코드 안 print 들을 참고하세요.

from ctypes import CDLL, c_uint, c_int
from hashlib import sha256

# ------------------ 유틸 ------------------
def bxor(a, b): return bytes(x ^ y for x, y in zip(a, b))
def b2hex(b):   return b.hex().upper()

def to_bytes_le(xmmhex: str) -> bytes:
    b = bytes.fromhex(xmmhex); assert len(b) == 16; return b[::-1]   # IDA xmmword 표기 → 메모리 LE

# ------------------ AES-128 ------------------
# (표준 FIPS-197 그대로, state는 column-major: state[r + 4*c])
SBOX = [
 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
INV_SBOX = [0]*256
for i,v in enumerate(SBOX): INV_SBOX[v]=i
RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def mul(a,b):
    p=0
    for _ in range(8):
        if b&1: p ^= a
        hi = a & 0x80
        a = (a<<1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p

def sub_word(w): return ((SBOX[(w>>24)&0xff]<<24)|(SBOX[(w>>16)&0xff]<<16)|(SBOX[(w>>8)&0xff]<<8)|SBOX[w&0xff])
def rot_word(w): return ((w<<8)&0xffffffff)|((w>>24)&0xff)

def key_expansion(key: bytes):
    assert len(key)==16
    w=[0]*44
    for i in range(4):
        w[i]=(key[4*i]<<24)|(key[4*i+1]<<16)|(key[4*i+2]<<8)|key[4*i+3]
    for i in range(4,44):
        t=w[i-1]
        if i%4==0: t=sub_word(rot_word(t)) ^ (RCON[i//4]<<24)
        w[i]=(w[i-4]^t)&0xffffffff
    rks=[]
    for r in range(11):
        rk=[]
        for i in range(4):
            word=w[4*r+i]
            rk.extend([(word>>24)&0xff,(word>>16)&0xff,(word>>8)&0xff,word&0xff])
        rks.append(rk)
    return rks

def add_round_key(s, rk): 
    for i in range(16): s[i]^=rk[i]

def sub_bytes(s):
    for i in range(16): s[i]=SBOX[s[i]]
def inv_sub_bytes(s):
    for i in range(16): s[i]=INV_SBOX[s[i]]

def shift_rows(s):
    t=s[:]
    s[1],s[5],s[9],s[13]=t[5],t[9],t[13],t[1]
    s[2],s[6],s[10],s[14]=t[10],t[14],t[2],t[6]
    s[3],s[7],s[11],s[15]=t[15],t[3],t[7],t[11]
def inv_shift_rows(s):
    t=s[:]
    s[1],s[5],s[9],s[13]=t[13],t[1],t[5],t[9]
    s[2],s[6],s[10],s[14]=t[10],t[14],t[2],t[6]
    s[3],s[7],s[11],s[15]=t[7],t[11],t[15],t[3]

def mix_columns(s):
    for c in range(4):
        i=4*c; a0,a1,a2,a3=s[i],s[i+1],s[i+2],s[i+3]
        s[i]   = mul(2,a0)^mul(3,a1)^a2^a3
        s[i+1] = a0^mul(2,a1)^mul(3,a2)^a3
        s[i+2] = a0^a1^mul(2,a2)^mul(3,a3)
        s[i+3] = mul(3,a0)^a1^a2^mul(2,a3)
def inv_mix_columns(s):
    for c in range(4):
        i=4*c; a0,a1,a2,a3=s[i],s[i+1],s[i+2],s[i+3]
        s[i]   = mul(0x0e,a0)^mul(0x0b,a1)^mul(0x0d,a2)^mul(0x09,a3)
        s[i+1] = mul(0x09,a0)^mul(0x0e,a1)^mul(0x0b,a2)^mul(0x0d,a3)
        s[i+2] = mul(0x0d,a0)^mul(0x09,a1)^mul(0x0e,a2)^mul(0x0b,a3)
        s[i+3] = mul(0x0b,a0)^mul(0x0d,a1)^mul(0x09,a2)^mul(0x0e,a3)

def aes_encrypt_block(pt: bytes, key: bytes, log_prefix=""):
    rk = key_expansion(key)
    s  = [pt[r+4*c] for c in range(4) for r in range(4)]
    if log_prefix: print(f"{log_prefix}AES-ENC start state={b2hex(bytes(s))} key={b2hex(key)}")
    add_round_key(s, rk[0]); 
    for r in range(1,10):
        sub_bytes(s); shift_rows(s); mix_columns(s); add_round_key(s, rk[r])
        if log_prefix: print(f"{log_prefix} Round{r:02d} -> {b2hex(bytes(s))}")
    sub_bytes(s); shift_rows(s); add_round_key(s, rk[10])
    if log_prefix: print(f"{log_prefix} Final     -> {b2hex(bytes(s))}")
    return bytes([s[r+4*c] for c in range(4) for r in range(4)])

def aes_decrypt_block(ct: bytes, key: bytes, log_prefix=""):
    rk = key_expansion(key)
    s  = [ct[r+4*c] for c in range(4) for r in range(4)]
    if log_prefix: print(f"{log_prefix}AES-DEC start state={b2hex(bytes(s))} key={b2hex(key)}")
    add_round_key(s, rk[10])
    for r in range(9,0,-1):
        inv_shift_rows(s); inv_sub_bytes(s); add_round_key(s, rk[r]); inv_mix_columns(s)
        if log_prefix: print(f"{log_prefix} InvRound{r:02d} -> {b2hex(bytes(s))}")
    inv_shift_rows(s); inv_sub_bytes(s); add_round_key(s, rk[0])
    if log_prefix: print(f"{log_prefix} Final     -> {b2hex(bytes(s))}")
    return bytes([s[r+4*c] for c in range(4) for r in range(4)])

# ------------------ .rodata 상수 (IDA 표기값 그대로) ------------------
RO = {
    "406130": "696663605D5A5754514E4B4845423F3C",
    "406140": "C9C4BFBAB5B0ABA6A19C97928D88837E",   # 앞 '0' 포함
    "406150": "AFADABA9A7A5A3A19F9D9B9997959391",   # 앞 '0' 포함
    # 406160/406180은 검증용이지만, P 역산에는 406160/406140이 직접 필요치 않음
    "406160": "D4D1CECBC8C5C2BFBCB9B6B3B0ADAAA7",    # 사람이 재구성(EDA 줄개행 오판 방지)
    "406170": "9A82E459D004EE2F6C680B7AF9092493",
    "406180": "1C5388F08C93524F4E5F7348D347B586",
    "406190": "EDFE0DF0DEC03713BEBAFECAEFBEADDE",   # 앞 '0' 포함
    "4061A0": "1032547698BADCFEEFCDAB8967452301",
}
def C(name, endian="le"): return to_bytes_le(RO[name]) if endian=="le" else bytes.fromhex(RO[name])

# ------------------ 핵심: 입력 1블록(16B) 역산 ------------------
# T0 = 406170,   C150=406150,  keyX130=(406190^406130), keyY130=(4061A0^406130)
C130, C150, C170, C190, C1A0 = C("406130"), C("406150"), C("406170"), C("406190"), C("4061A0")
keyX130 = bxor(C190, C130)
keyY130 = bxor(C1A0, C130)

print("[*] keyX130 =", b2hex(keyX130))
print("[*] keyY130 =", b2hex(keyY130))
print("[*] C150    =", b2hex(C150))
print("[*] TARGET0 =", b2hex(C170))

X   = bxor(C170, C150)
U0  = aes_decrypt_block(X, keyY130, log_prefix="INV1: ")
Y   = bxor(U0, C150)
P16 = aes_decrypt_block(Y, keyX130, log_prefix="INV2: ")

print("\n[RESULT] Recovered first 16 bytes P =", b2hex(P16))
P32 = P16 + bytes(16)  # 뒤 16바이트는 검증에 쓰이지 않으므로 0으로
print("[RESULT] Final 32-byte input P       =", b2hex(P32))
print("\nFlag =>  YISF{" + b2hex(P32) + "}")

# ------------------ (옵션) libc srand/rand 시연: 같은 초면 KDF가 동일 ------------------
try:
    libc = CDLL("libc.so.6")
    libc.srand.argtypes = [c_uint]
    libc.rand.restype   = c_int

    def kdf_from_t(t: int):
        libc.srand(c_uint(t))
        r1, r2 = libc.rand(), libc.rand()
        s = f"{r1}{r2}".encode()
        h = sha256(s).digest()
        kodd  = bytes(h[i] for i in range(1,32,2))
        keven = bytes(h[i] for i in range(0,32,2))
        return kodd, keven, s.decode()

    t = 1700000000
    kodd1, keven1, s1 = kdf_from_t(t)
    kodd2, keven2, s2 = kdf_from_t(t)
    print(f"\n[DEMO] t={t} -> s1='{s1}', s2='{s2}'  /  kodd1==kodd2? {kodd1==kodd2}, keven1==keven2? {keven1==keven2}")
except Exception as e:
    print("[DEMO] libc 확인 스킵:", e)
