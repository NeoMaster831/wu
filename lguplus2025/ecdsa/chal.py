import random
from hashlib import sha512
from ecdsa import NIST521p, SigningKey
from Crypto.Util.number import bytes_to_long

n = int(NIST521p.order)
G = NIST521p.generator

def generate_keypair():
    sk = SigningKey.generate(curve=NIST521p)
    vk = sk.verifying_key
    return sk, vk

def sign(msg, sk):
    h = bytes_to_long(sha512(msg).digest()) # controllable? idk
    k = random.getrandbits(512) # should know
    r = (k * G).x() % n
    s = pow(k, -1, n) * (h + r * sk.secret_multiplier) % n
    if r == 0 or s == 0:
        return sign(msg, sk)
    return (int(r), int(s))

def verify(msg, sig, vk):
    r, s = sig
    if r <= 0 or r >= n or s <= 0 or s >= n:
        return False
    h = bytes_to_long(sha512(msg).digest())
    u1 = (h * pow(s, -1, n)) % n
    u2 = (r * pow(s, -1, n)) % n
    point = u1 * G + u2 * vk.pubkey.point
    return (point.x() % n == r)

print("Ready to sign some messages?")
sk, vk = generate_keypair()
#print(hex(sk.privkey.secret_multiplier))
while True:
    if (msg := input("Enter a message to sign : ")) == "I'm ready":
        break
    print(f"Signature : {sign(msg.encode(), sk.privkey)}")


print("\nLet's move on!!!!")
sk, vk = generate_keypair()

msg = random.randbytes(32)
print(f"Submit a signature for the following message : {msg.hex()}.")
print(f"Format : {sign(random.randbytes(32), sk.privkey)}")

sig = tuple(map(int, input().strip("()").split(', ')))

if verify(msg, sig, vk):
    with open("flag.txt") as f:
        print(f"{f.read()}")
else:
    print("Invalid signature.")
