insts = bytes.fromhex(
'''
14 00 01 14 01 02 0E 01  08 08 00 01 12 04 00 14
05 40 0D 04 05 0B 00 42  20 01 03 04 0D 03 05 0B
00 42 20 14 00 00 14 01  00 0E 01 08 08 00 01 02
00 03 14 01 AA 11 01 00  14 00 01 02 03 00 0A 00
1C 20 14 03 00 0D 03 05  0B 00 D3 20 14 00 00 14
01 00 0E 01 08 08 00 01  02 00 03 10 06 00 14 00
0D 01 01 03 04 00 01 14  01 07 02 00 01 14 01 FF
07 00 01 01 02 00 01 00  03 14 01 07 06 00 01 14
01 01 02 00 01 01 01 00  01 00 06 0F 00 01 09 00
02 14 01 2A 02 00 01 14  01 FF 07 00 01 14 01 00
14 02 01 0E 02 08 08 01  02 02 01 03 10 01 01 0D
00 01 0C 00 C0 20 14 00  01 02 03 00 0A 00 45 20
14 00 00 14 01 00 14 02  02 0E 02 08 08 01 02 11
00 01 00 14 00 01 14 01  00 14 02 02 0E 02 08 08
01 02 11 00 01 00 00 00  00 00 00 00 00 00 00 00
'''
)

class VVM:

    ip = 0
    v = [0 for _ in range(10000)]
    regs = [0 for _ in range(10000)]
    flags = 0

    def x14(self, v1, v2):
        self.regs[v1] = v2
        self.ip += 3

    def x13(self, v1, v2, v3):
        addr = v2 | (v3 << 8)
        self.v[addr] = self.regs[v1] & 0xFF
        self.v[addr + 1] = (self.regs[v1] >> 8) & 0xFF
        self.ip += 4

    def x12(self, v1, v2):
        self.regs[v1] = self.v[self.regs[v2]] | (self.v[self.regs[v2] + 1] << 8)
        self.ip += 3

    def x11(self, v1, v2):
        self.v[self.regs[v2]] = self.regs[v1] & 0xFF
        self.ip += 3
    
    def x10(self, v1, v2):
        self.regs[v1] = self.v[self.regs[v2]] & 0xFF
        self.ip += 3
    
    def xf(self, v1, v2):
        k = self.regs[v2] & 7
        v = self.regs[v1] & 0xFF
        self.regs[v1] = ((v >> k) | (v << (8 - k))) & 0xFF
        self.ip += 3
    
    def xe(self, v1, v2):
        self.regs[v1] = (self.regs[v1] << self.regs[v2]) & 0xFFFF
        self.ip += 3

    def xd(self, v1, v2):
        self.flags = (self.flags | 1) if self.regs[v1] == self.regs[v2] else (self.flags & ~1)
        self.ip += 3

    def xc(self, v1, v2, v3):
        self.ip = (self.ip + 4) if (self.flags & 1) else (self.regs[v1] if 1 <= v1 <= 7 else (v2 | (v3 << 8)))

    def xb(self, v1, v2, v3):
        self.ip = (self.regs[v2] if (self.flags & 1 and v1) else ((v2 | (v3 << 8)) if (self.flags & 1) else self.ip + 4))

    def xa(self, v1, v2, v3):
        self.ip = (self.regs[v2] if v1 else (v2 | (v3 << 8)))
    
    def x9(self, v1, v2):
        self.regs[v1] ^= self.regs[v2]
        self.ip += 3

    def x8(self, v1, v2):
        self.regs[v1] |= self.regs[v2]
        self.ip += 3
    
    def x7(self, v1, v2):
        self.regs[v1] &= self.regs[v2]
        self.ip += 3

    def x6(self, v1, v2):
        self.regs[v1] %= self.regs[v2]
        self.ip += 3
    
    def x5(self, v1, v2):
        self.regs[v1] //= self.regs[v2]
        self.ip += 3

    def x4(self, v1, v2):
        self.regs[v1] *= self.regs[v2]
        self.ip += 3
    
    def x3(self, v1, v2):
        self.regs[v1] -= self.regs[v2]
        self.ip += 3

    def x2(self, v1, v2):
        self.regs[v1] += self.regs[v2]
        self.ip += 3
    
    def x1(self, v1, v2):
        self.regs[v1] = self.regs[v2]
        self.ip += 3

# ------------------------------------------------------------
# mini-disassembler for the toy-VM
# ------------------------------------------------------------
from textwrap import indent

# ── 1. 오퍼코드 → 니모닉/길이/디코더 매핑 ────────────────────────
def decoder_mov_imm(buf, pc):      # 0x14 : MOVI Rn, imm8
    reg, imm = buf[pc+1], buf[pc+2]
    return f"MOVI   R{reg}, 0x{imm:02X}", 3

def decoder_storew(buf, pc):       # 0x13 : STOREW [imm16], Rn
    reg  = buf[pc+1]
    addr = buf[pc+2] | (buf[pc+3] << 8)
    return f"STOREW [0x{addr:04X}], R{reg}", 4

def decoder_ldw(buf, pc):          # 0x12 : LDW Rdst, [Rsrc]
    dst, src = buf[pc+1], buf[pc+2]
    return f"LDW    R{dst}, [R{src}]", 3

def decoder_stb(buf, pc):          # 0x11 : STB [Rsrc], Rdst(low8)
    dst, src = buf[pc+1], buf[pc+2]
    return f"STB    [R{src}], R{dst}.L", 3

def decoder_ldb(buf, pc):          # 0x10 : LDB Rdst, [Rsrc]
    dst, src = buf[pc+1], buf[pc+2]
    return f"LDB    R{dst}, [R{src}]", 3

def decoder_ror(buf, pc):          # 0x0F : ROR8 Rn, Rk
    dst, src = buf[pc+1], buf[pc+2]
    return f"ROR8   R{dst}, R{src}", 3

def decoder_shl(buf, pc):          # 0x0E : SHL Rn, Rk
    dst, src = buf[pc+1], buf[pc+2]
    return f"SHL    R{dst}, R{src}", 3

def decoder_cmp(buf, pc):          # 0x0D : CMP Rn, Rm   (ZF ← (==))
    r1, r2 = buf[pc+1], buf[pc+2]
    return f"CMP    R{r1}, R{r2}", 3

def decoder_jne(buf, pc):          # 0x0C : JNE  mode, operand
    mode, op_lo, op_hi = buf[pc+1:pc+4]
    if mode:
        return f"JNE    R{op_lo}", 4   # mode 1-7 → register
    addr = op_lo | (op_hi << 8)
    return f"JNE    0x{addr:04X}", 4

def decoder_je(buf, pc):           # 0x0B : JE   mode, operand
    mode, op_lo, op_hi = buf[pc+1:pc+4]
    if mode:
        return f"JE     R{op_lo}", 4
    addr = op_lo | (op_hi << 8)
    return f"JE     0x{addr:04X}", 4

def decoder_jmp(buf, pc):          # 0x0A : JMP  mode, operand
    mode, op_lo, op_hi = buf[pc+1:pc+4]
    if mode:
        return f"JMP    R{op_lo}", 4
    addr = op_lo | (op_hi << 8)
    return f"JMP    0x{addr:04X}", 4

def decoder_xor(buf, pc):          # 0x09
    r1, r2 = buf[pc+1], buf[pc+2]
    return f"XOR    R{r1}, R{r2}", 3

def decoder_or(buf, pc):           # 0x08
    r1, r2 = buf[pc+1], buf[pc+2]
    return f"OR     R{r1}, R{r2}", 3

def decoder_and(buf, pc):          # 0x07
    r1, r2 = buf[pc+1], buf[pc+2]
    return f"AND    R{r1}, R{r2}", 3

def decoder_mod(buf, pc):          # 0x06
    r1, r2 = buf[pc+1], buf[pc+2]
    return f"MOD    R{r1}, R{r2}", 3

def decoder_div(buf, pc):          # 0x05
    r1, r2 = buf[pc+1], buf[pc+2]
    return f"DIV    R{r1}, R{r2}", 3

def decoder_mul(buf, pc):          # 0x04
    r1, r2 = buf[pc+1], buf[pc+2]
    return f"MUL    R{r1}, R{r2}", 3

def decoder_sub(buf, pc):          # 0x03
    r1, r2 = buf[pc+1], buf[pc+2]
    return f"SUB    R{r1}, R{r2}", 3

def decoder_add(buf, pc):          # 0x02
    r1, r2 = buf[pc+1], buf[pc+2]
    return f"ADD    R{r1}, R{r2}", 3

def decoder_mov(buf, pc):          # 0x01
    dst, src = buf[pc+1], buf[pc+2]
    return f"MOV    R{dst}, R{src}", 3

def decoder_nop(buf, pc):          # 0x00
    return "NOP", 1


mnemonic_map = {
    0x14: decoder_mov_imm,
    0x13: decoder_storew,
    0x12: decoder_ldw,
    0x11: decoder_stb,
    0x10: decoder_ldb,
    0x0F: decoder_ror,
    0x0E: decoder_shl,
    0x0D: decoder_cmp,
    0x0C: decoder_jne,
    0x0B: decoder_je,
    0x0A: decoder_jmp,
    0x09: decoder_xor,
    0x08: decoder_or,
    0x07: decoder_and,
    0x06: decoder_mod,
    0x05: decoder_div,
    0x04: decoder_mul,
    0x03: decoder_sub,
    0x02: decoder_add,
    0x01: decoder_mov,
    0x00: None,
}

def disassemble(buf: bytes, start_pc: int = 0):
    pc = start_pc
    while pc < len(buf):
        opcode = buf[pc]
        decoder = mnemonic_map.get(opcode)
        if decoder is None:
            print(f"{pc:04X}: DB 0x{opcode:02X}")
            pc += 1
            continue

        asm, size = decoder(buf, pc)
        print(f"{pc:04X}: {asm}")
        pc += size


if __name__ == "__main__":
    disassemble(insts)
