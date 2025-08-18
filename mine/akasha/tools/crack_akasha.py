from hashlib import sha384
from pwn import p64
import random

def p64b(x: int) -> bytes:
    return p64(x)[::-1]

def list_xor(a: list, b: list) -> list:
    return [x ^ y for x, y in zip(a, b)]

AKASHA_XOR_KEY = p64b(0x5aa5a55aa5a55aa5) + p64b(0x3cc3c33cc3c33cc3) + p64b(0x0ff0f00ff0f00ff0) + p64b(0x5555aaaa5555aaaa) + p64b(0x3333cccc3333cccc) + p64b(0x0f0f0f0f0f0f0f0f)
def akasha(data: bytes) -> bytes:
    return bytes(list_xor(sha384(data).digest(), list(AKASHA_XOR_KEY))).hex()

def crack_akasha(wanted: str) -> str:
    assert(len(wanted) == 6) # 3 bytes, 6 hex digits
    randstr = random.randbytes(16).hex()
    for cnter in range(1, int(1e9) + 1):
        cnter += 1
        if cnter % 1000000 == 0:
            print(f"Trying {cnter}...")

        payload = randstr + f"{cnter:016x}"
        payload = payload.encode('utf-8')

        encrypted = akasha(payload)
        if encrypted.startswith(wanted):
            print(f"Found: {payload}")
            return payload
    raise ValueError("Failed to find a match within the limit.")

if __name__ == "__main__":
    #print(crack_akasha("ffffff"))
    #print(crack_akasha("40255e"))
    #print(crack_akasha("000000"))
    print(crack_akasha("50255e"))