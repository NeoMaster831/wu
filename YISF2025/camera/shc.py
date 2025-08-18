from unicorn import *
from unicorn.x86_const import *
from pwn import disasm

shc = """
EB 00 E8 CE 00 00 00  EB 00 40 07 00 00 F7 15
C0 2B 71 B0 A6 74 13 0E  3A 76 00 C0 05 00 69 30
A1 BE FF FF FF 1D 0F D7  99 FA AB 2F 0B 81 81 81
7D 03 8A C1 45 41 89 71  9F A7 60 33 02 DD 4E 22
D3 B5 A7 AC 49 F0 3D BD  A8 4E D0 26 B0 FF A5 23
6E E7 F6 9C 6A B3 D5 9A  7B C4 A6 D6 2E E3 93 F1
C8 9C D5 32 79 7D 01 57  9A 9A 24 76 1E 57 B0 FB
FE 8E D6 1B 9B 8C 4B 30  DC CA 83 92 F8 C6 17 3E
37 90 1B DC 60 F4 39 B9  05 F7 3A B0 B5 75 F8 B2
81 9D B1 B5 C2 B5 64 71  55 B7 BA 9C E1 D8 E9 DE
6F 0D 41 7C B1 A1 16 8F  74 A1 73 D1 A5 74 9B E8
70 C6 E5 77 DE AE A7 A0  CC 9F D4 35 71 60 AD CD
71 67 08 EB 26 46 F4 F5  32 D1 1C 9A 91 55 25 89
8F F0 F3 3E 38 D3 5A C1  4A 02 63 C1 42 06 73 EB
00 81 72 0A 71 B0 A6 C4  81 6A 0E D3 DD B5 67 EB
00 C1 4A 12 6E 81 6A 16  67 AC 92 A7 EB 00 F7 52
1A F7 52 1E 52 C3 00 00
"""

shc = bytes.fromhex(shc)
print(disasm(shc))

BASE = 0xffffc000
STACK_BASE = 0xFFFFD000
STOP_OFF = 0x26

mu = Uc(UC_ARCH_X86, UC_MODE_32)

mu.mem_map(BASE, 0x1000)
mu.mem_write(BASE, shc)
mu.mem_map(STACK_BASE, 0x2000)
mu.reg_write(UC_X86_REG_ESP, STACK_BASE + 0x2000)

STOP_ADDR = BASE + STOP_OFF
def code_hook(mu, addr, size, user_data):
    if addr == STOP_ADDR:
        shc_dec = mu.mem_read(BASE, 0x107)
        with open("shc_decoded.txt", "w") as f:
            f.write(shc_dec.hex())
        print("success")
        raise SystemExit(0)

mu.hook_add(UC_HOOK_CODE, code_hook)
mu.reg_write(UC_X86_REG_EIP, BASE)

try:
    mu.emu_start(BASE, BASE + len(shc))
except SystemExit:
    print('gracefully exit')
    exit(0)