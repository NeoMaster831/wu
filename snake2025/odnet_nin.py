from hashlib import sha1
import base64

OPERATION_ADD = 0
OPERATION_SUB = 1
OPERATION_AND = 2
OPERATION_OR = 3
OPERATION_XOR = 4
OPERATION_BSR = 5 # BITSHIFT_RIGHT
OPERATION_LDR = 6
OPERATION_STR = 7
OPERATION_LOADI = 8
OPERATION_ZERO = 9
OPERATION_ADDI = 10
OPERATION_JMP = 11
OPERATION_CALL = 12
OPERATION_BNZ = 14
OPERATION_SYSCALL = 15

class Opcode:
    def __init__(self, operation, reg1, v1, v2=None):
        if v2 == None:
            self.p2 = v1
        else:
            self.p2 = (v1 << 4) | v2
        self.p1 = (operation << 4) | reg1
    def build(self):
        return bytes([self.p1, self.p2])

from pwn import p64

def build_vm(opcodes=list[Opcode], initial_memory=[0] * 0x13):

    raw_opcodes = b""
    for opcode in opcodes:
        raw_opcodes += opcode.build()
    
    body = raw_opcodes + bytes(initial_memory)
    
    SIGNATURE = b"SNAK"
    ret = SIGNATURE + p64(len(raw_opcodes))[:2] + p64(len(initial_memory))[:2] + sha1(body).digest() + b"\x00" * 0x100 + body

    return base64.b64encode(ret).decode()


opcode_head = [
    Opcode(OPERATION_LOADI, 1, ord('r')), # Real mode, load 'r'
    Opcode(OPERATION_SYSCALL, 0, 3), # get char
    Opcode(OPERATION_SUB, 0, 0, 1), # Subtract, reg[0] -= reg[1]
]

opcode_body = [
    Opcode(OPERATION_SYSCALL, 0, 83) # load flag
]

for i in range(20):
    opcode_body += [
        Opcode(OPERATION_LOADI, 3, i + 51), # Initially 2
        Opcode(OPERATION_LDR, 0, 3, 0), # Add, reg[0] += reg[3]
        # now reg[0] contains flag.
        Opcode(OPERATION_SYSCALL, 0, 2), # test
        Opcode(OPERATION_LOADI, 0, 0)
    ]

# snakeCTF{4lw4ys_r0ll_y0ur_0wn_cryp70_18e201d9c3e71f5d}

opcode_head += [ Opcode(OPERATION_BNZ, 0, len(opcode_body)) ]

opcode_tail = [ Opcode(OPERATION_SYSCALL, 0, 1) ]
opcodes = opcode_head + opcode_body + opcode_tail

if __name__ == '__main__':
    print(f"Test: {build_vm(opcodes)}")