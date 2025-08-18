from pwn import remote, ELF, context
from base64 import b64decode
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import angr
import claripy

def solve_one(input_len):
    proj = angr.Project('binary.elf', auto_load_libs=False)

    sym = claripy.BVS('inp', (input_len+1) * 8)
    state = proj.factory.entry_state(args=['binary.elf'], stdin=sym)
    bs = [sym.get_byte(i) for i in range(input_len + 1)]
    for i in range(input_len):
        state.solver.add(bs[i] >= 0x20, bs[i] <= 0x7e)
    state.solver.add(bs[input_len] == 0x0a)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=lambda s: b"ROUND" in s.posix.dumps(1))

    if simgr.found:
        return simgr.found[0].solver.eval(sym, cast_to=bytes)
    
    return None


p = remote('211.229.232.98', 20401)
context.log_level = 'debug'

def solve_round():
    p.recvuntil(b"--- GATE")
    p.recvuntil(b"---\n")

    with open(f'binary.elf', 'wb') as f:
        f.write(b64decode(p.recvline().decode().strip()))

    binary = ELF('binary.elf')

    code = binary.read(0x10e0, 0x200)

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    input_len = None
    for i in md.disasm(code, 0x10e0):
        if i.mnemonic == 'cmp':
            input_len = int(i.op_str.split('rax, ')[1], 16)
            break

    print(f"Input length: {input_len}")

    p.sendafter(b"INPUT> ", solve_one(input_len))

for _ in range(1337):
    solve_round()