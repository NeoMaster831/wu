from pwn import ELF
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from tqdm import tqdm

binary = ELF('./too_many_functions')

start_offset = 0x478727
end_offset = 0x59D6A7

code = binary.read(start_offset, end_offset - start_offset)

md = Cs(CS_ARCH_X86, CS_MODE_64)
calls = []
for insn in md.disasm(code, start_offset):
    try:
        calls.append(int(insn.op_str.split('0x')[1], 16))
    except:
        pass

call_sets = set(calls)
inst_maps = {}
for c in tqdm(call_sets):
    code = binary.read(c, 0x200)
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    shl_value = None
    shr_value = None
    xor_value = None
    for insn in md.disasm(code, c):
        if insn.mnemonic == 'shl':
            shl_value = int(insn.op_str.split("eax, ")[1], 16)
        elif insn.mnemonic == 'shr':
            shr_value = int(insn.op_str.split("al, ")[1], 16)
        elif insn.mnemonic == 'xor':
            xor_value = int(insn.op_str.split("edx, ")[1], 16)
        elif insn.mnemonic == 'ret':
            break

    if shl_value is None and shr_value is None and xor_value is None:
        raise ValueError(hex(c))
    
    if shl_value is not None:
        inst_maps[c] = ("rol", shl_value)
    
    if shr_value is not None:
        inst_maps[c] = ("ror", shr_value)

    if xor_value is not None:
        inst_maps[c] = ("xor", xor_value & 0xFF)

target = bytes.fromhex("""
53 73 47 6D 17 2D 8B 8B  8F 27 2B 8F 93 27 8F 2B
27 89 27 81 2D 89 8F 91  83 2B 27 23 8D 8F 8B 8B
2D 2B 8B 8B 8D 8F 2B 85  83 91 81 8D 29 27 8D 93
85 91 23 93 83 25 8B 2D  27 2D 85 93 8D 85 2B 85
87 89 25 91 91 2D 8D 85  91 25 8D 27 27 8F 93 85
25 25 81 89 89 83 23 83  8B 2D 2D 25 93 89 23 87
25 8F 27 85 89 29 91 2D  93 29 89 91 8B 2B 2D 27
8D 87 8D 8B 93 29 83 27  8B 85 85 27 8D 29 27 91
25 29 2D 91 23 1B
""")

def ror(value, shifts):
    return ((value >> shifts) | (value << (8 - shifts))) & 0xFF

def rol(value, shifts):
    return ((value << shifts) | (value >> (8 - shifts))) & 0xFF

for c in reversed(calls):
    mn, val = inst_maps[c]

    if mn == "rol":
        target = [ ror(b, val) for b in target ]
    elif mn == "ror":
        target = [ rol(b, val) for b in target ]
    elif mn == "xor":
        target = [ b ^ val for b in target ]

    target = bytes(target)

print(target)