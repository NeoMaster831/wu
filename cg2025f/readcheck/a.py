code = b"""from pwn import *
r.recvuntil(b'Signature: ')
sig = bytes.fromhex(r.recvline().strip().decode())
r.recvuntil(b'Read Check')
r.send(sig + b'\\n')
print(r.recvall().decode())"""
print(code.hex())