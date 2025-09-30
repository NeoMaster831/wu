import random
from pwn import *
from Crypto.Util.number import long_to_bytes
random.seed(0)

rands_16 = b"".join([p32(random.getrandbits(32)) for _ in range(16)])

random.seed(0)

rand = long_to_bytes(random.getrandbits(512))

print(f"{rands_16 = }")
print(f"{rand = }")

assert(rand[::-1] == rands_16)