from Crypto.Util.number import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from flag import flag

p = getStrongPrime(512)
q = getStrongPrime(512)
n = p * q
e = 3

key = get_random_bytes(16)
key_int = bytes_to_long(key)

related_key_int = (2 * key_int + 1) % n
related_key = long_to_bytes(related_key_int)

c1 = pow(key_int, e, n)
c2 = pow(related_key_int, e, n)

print("n =", n)
print("e =", e)
print("c1 =", c1)
print("c2 =", c2)
print("# Hint: M2 = 2*M1 + 1")

aes_key = hashlib.sha256(key).digest()[:32]
cipher = AES.new(aes_key, AES.MODE_ECB)

flag_padded = flag + b'\x00' * (16 - len(flag) % 16)
encrypted_flag = cipher.encrypt(flag_padded)

print("encrypted_flag =", encrypted_flag.hex())