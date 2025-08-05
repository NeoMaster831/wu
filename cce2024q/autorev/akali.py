from pwn import remote, ELF
from base64 import b64decode
from capstone import *

#context.log_level = 'debug'

def ROR(v: int, k: int):
    BITS = 8
    k = k % BITS
    return (v >> k) | ((v << (BITS - k)) & (2 ** BITS - 1))

p = remote('52.231.139.116', 16185)

print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())

for t in range(50):
    if t >= 1:
        print(p.recvline())
        print(p.recvline())
    print(p.recvline())
    print(p.recvline())

    binary = b64decode(p.recvline()[:-2])

    with open('./binary', 'wb') as f:
        f.write(binary)

    elf = ELF('./binary')
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    main = elf.sym['main']
    pro = 0x1183

    insts = []
    d = 0
    for inst in md.disasm(binary[main:main+0x100], 0):
        insts.append("%d - 0x%x:\t%s\t%s" % (d, inst.address, inst.mnemonic, inst.op_str))
        d += 1

    assert('movabs\trax, ' in insts[3])
    assert('movabs\trdx, ' in insts[4])

    if 'mov\teax, 'in insts[7]:
        s2 = int(insts[7].split('mov\teax, ')[1], 16)
    elif 'qword ptr [rbp - 0xb0], ' in insts[7]:
        s2 = int(insts[7].split('qword ptr [rbp - 0xb0], ')[1], 16)
    else:
        raise NotImplementedError

    s0 = int(insts[3].split('movabs\trax, ')[1], 16)
    s1 = int(insts[4].split('movabs\trdx, ')[1], 16)

    last = b''
    last += s0.to_bytes(8, 'little')
    last += s1.to_bytes(8, 'little')
    last += s2.to_bytes(4, 'little')

    assert(len(last) == 20)

    insts = []
    d = 0
    for inst in md.disasm(binary[pro:pro+0x100], 0):
        insts.append("%d - 0x%x:\t%s\t%s" % (d, inst.address, inst.mnemonic, inst.op_str))
        d += 1

    assert('mov\teax, dword ptr [rbp - 0x14]' in insts[0])

    ptr = 0

    found = None
    shlval = None
    shrval = None
    subval = None
    addval = None
    xorval = None
    while 'add\tdword ptr [rbp - 0x14], 1' not in insts[ptr]:

        if 'sub' in insts[ptr]:
            subval = int(insts[ptr].split(', ')[1], 16)
            found = 'sub'
        elif 'xor' in insts[ptr]:
            xorval = int(insts[ptr].split(', ')[1], 16)
            found = 'xor'
        elif 'shl' in insts[ptr]:
            shlval = int(insts[ptr].split(', ')[1], 16)
            found = 'sh'
        elif 'shr' in insts[ptr]:
            shrval = int(insts[ptr].split(', ')[1], 16)
            found = 'sh'
        elif 'add\tedx' in insts[ptr]:
            addval = int(insts[ptr].split(', ')[1], 16)
            found = 'add'

        ptr += 1

    assert(found != None)

    payload = b''

    if found == 'sub':
        for i in last:
            payload += ((i + subval) % 0x100).to_bytes(1, 'big')

    elif found == 'add':
        for i in last:
            payload += ((i - addval + 0x100) % 0x100).to_bytes(1, 'big')

    elif found == 'xor':
        for i in last:
            payload += (i ^ (xorval & 0xff)).to_bytes(1, 'big')

    elif found == 'sh':

        if shlval is None: shlval = 8 - shrval
        
        for i in last:
            payload += ROR(i, shlval).to_bytes(1, 'big')

    print(payload)
    #p.interactive()
    p.sendlineafter(b'Input: ', payload)

print(p.recvall())