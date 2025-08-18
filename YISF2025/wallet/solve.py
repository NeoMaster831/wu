from pwn import *

r = remote('211.229.232.98', 20799)
context.log_level = 'debug'

def find_key_with_pattern_fast(target, mode):
    p = process([ 'wallet-solve/target/release/wallet-solve', mode, target, '12' ])
    p.recvuntil(b"PrivateKey: ")
    sk = p.recvline().strip()
    p.close()
    return sk, None

for _ in range(100):
    r.recvuntil(b'[?]')
    l = r.recvline()

    if b'starting' in l:
        mode = 'prefix'
    elif b'ending' in l:
        mode = 'suffix'
    else:
        raise ValueError
    
    # It could be '0x....' instead of '....'
    target = l.split(b"'")[1].decode().strip()
    if target.startswith('0x'):
        target = target[2:]
    print("target =", target)
    print("mode =", mode)

    sk, _ = find_key_with_pattern_fast(target, mode)
    r.sendlineafter(b">>> Private key (hex): ", sk)

r.interactive()