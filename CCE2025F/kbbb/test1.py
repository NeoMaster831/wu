from ctypes import CDLL

libc = CDLL("libc.so.6")

libc.srand(99999)
print(hex(libc.rand() & 0xFF))
libc.srand(100000)
print(hex(libc.rand() & 0xFF))

print(0x37 - 12 - 32 )