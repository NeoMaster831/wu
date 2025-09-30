with open('ehvm.bin', 'rb') as f:
    ehvm_code = f.read()

from pwn import u64

# Disassemble this VM
ip = 0
vm_size = len(ehvm_code)
while ip < vm_size:
    inst = ehvm_code[ip]
    if inst == 0x12:
        print(f"{ip:04x}: PUSH STACK[SP] (DUP)")
        ip += 1
    elif inst == 0x97:
        print(f"{ip:04x}: POP X, PUSH INPUT[X]:8")
        ip += 1
    elif inst == 0x10:
        print(f"{ip:04x}:", end=" ")
        ip += 1
        c = 0
        bits = 0
        v = None
        while v is None or v & 0x80:
            v = ehvm_code[ip]
            c |= (v & 0x7F) << bits
            bits += 7
            ip += 1
        #if v & 0x40:
        #    c = -((~c & 0xFFFFFFFFFFFFFFFF) + 1)
        print(f"PUSH {hex(c)}")
    elif inst == 0x27:
        print(f"{ip:04x}: POP X, POP Y, PUSH Y ^ X")
        ip += 1
    elif inst == 0x29:
        print(f"{ip:04x}: POP X, POP Y, PUSH Y == X")
        ip += 1
    elif inst == 0x28:
        print(f"{ip:04x}: IF (POP X) JUMP {hex(ip + 3 + (ehvm_code[ip + 1] << 8 | ehvm_code[ip + 2]))}")
        ip += 3
    elif inst == 0xe:
        print(f"{ip:04x}: PUSH {hex(u64(ehvm_code[ip+1:ip+9]))}")
        ip += 9
    elif inst == 0x22:
        print(f"{ip:04x}: POP X, POP Y, PUSH Y + X")
        ip += 1
    elif inst == 0x1c:
        print(f"{ip:04x}: POP X, POP Y, PUSH Y - X")
        ip += 1
    elif inst == 0x1e:
        print(f"{ip:04x}: POP X, POP Y, PUSH Y * X")
        ip += 1
    elif inst == 0x14:
        print(f"{ip:04x}: PUSH STACK[SP-1] (OVER)")
        ip += 1
    elif inst == 0x8:
        print(f"{ip:04x}: PUSH {hex(ehvm_code[ip+1])}")
        ip += 2
    elif inst == 0x1d:
        print(f"{ip:04x}: POP X, POP Y, PUSH Y % X")
        ip += 1
    elif inst == 0x24:
        print(f"{ip:04x}: POP X, POP Y, PUSH Y << X")
        ip += 1
    elif inst == 0x17:
        print(f"{ip:04x}: PUSH STACK[SP-1], PUSH STACK[SP] (DUP2)")
        ip += 1
    elif inst == 0x16:
        print(f"{ip:04x}: SWAP STACK[SP], STACK[SP-1] (SWAP)")
        ip += 1
    elif inst == 0x25:
        print(f"{ip:04x}: POP X, POP Y, PUSH Y >> X")
        ip += 1
    elif inst == 0x21:
        print(f"{ip:04x}: POP X, POP Y, PUSH Y | X")
        ip += 1
    elif inst == 0x98:
        print(f"{ip:04x}: POP X, POP Y, INPUT[X]:8 = Y")
        ip += 1
    else:
        raise NotImplementedError(f"Instruction {hex(inst)} not implemented")