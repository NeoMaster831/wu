from pwn import *
import random
import hashlib
from Crypto.Util.number import bytes_to_long

context.log_level = 'debug'

#p = process(['python3', 'chal.py'])
p = remote("16.184.46.213", 3502)

def generate_random_msg():
    msg = random.randbytes(16).hex()
    return msg, bytes_to_long(hashlib.sha512(msg.encode()).digest())

def save_to_json(sigs):

    signatures = []
    for h, r, s in sigs:
        signatures.append({"hash": h, "r": r, "s": s, "kp": 0})
    
    fmt = {
        "curve": "SECP521R1", # NIST521p
        "known_type": "MSB",
        "known_bits": 9,
        "signatures": signatures
    }

    with open('data.json', 'w') as f:
        import json
        json.dump(fmt, f, indent=4)

m = 344
sigs = []
p.recvline()
#d = int(p.recvline(), 16)

for i in range(m):
    msg, h = generate_random_msg()
    p.sendlineafter(b"Enter a message to sign : ", msg)
    raw_r_s = p.recvline().split(b" : ")[1].decode().strip()
    r, s = tuple(map(int, raw_r_s.strip("()").split(', ')))
    sigs.append((h, r, s))

    print(f"{h = }")
    print(f"{r = }")
    print(f"{s = }")

save_to_json(sigs)

#print(f"{hex(d) = }")
d = int(input("d? "), 16)

# Mt19937 Crack

from ecdsa import NIST521p
from Crypto.Util.number import long_to_bytes

n = int(NIST521p.order)

outs = []

for _ in range(624 // 16 + 5):
    msg, h = generate_random_msg()
    p.sendlineafter(b"Enter a message to sign : ", msg)
    raw_r_s = p.recvline().split(b" : ")[1].decode().strip()
    r, s = tuple(map(int, raw_r_s.strip("()").split(', ')))
    
    rbits = pow(s * pow(h + r * d, -1, n) % n, -1, n)

    o1 = long_to_bytes(rbits)[::-1] 
    pre_outs = [ u32(o1[i:i+4]) for i in range(0, len(o1), 4) ]
    outs.extend(pre_outs)

with open('tmpt.py', 'w') as f:
    f.write(f"{outs = }\n")

p.sendlineafter(b"Enter a message to sign : ", b"I'm ready")
p.recvline()
p.recvline()
msg = bytes.fromhex(p.recvline().split(b" : ")[1].decode().strip(".\n"))
rrs = p.recvline().split(b" : ")[1].decode().strip()
r, s = tuple(map(int, rrs.strip("()").split(', ')))

print(f"{msg.hex() = }")
m2 = bytes.fromhex(input(f"second msg (as hex)? ").strip())
k2 = int(input(f"k2? "), 16)

h2 = bytes_to_long(hashlib.sha512(m2).digest())

d = ( (s * k2 - h2) * pow(r, -1, n) ) % n

print(f"{hex(d) = }")

G = NIST521p.generator
def Sign(msg, d):
    h = bytes_to_long(hashlib.sha512(msg).digest()) # controllable? idk
    k = random.getrandbits(512) # should know
    r = (k * G).x() % n
    s = pow(k, -1, n) * (h + r * d) % n
    if r == 0 or s == 0:
        return Sign(msg, d)
    return (int(r), int(s))

r, s = Sign(msg, d)
p.sendline(f"({r}, {s})".encode())

p.interactive()