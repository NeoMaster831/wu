from typing import List
import sys, binascii

OP_ARITH = {0:"mov",1:"add",2:"sub",3:"xor",4:"and",5:"or",6:"cmp"}
OP_CTRL  = {7:"jmp",8:"je",9:"jne",10:"call",11:"ret",12:"push",13:"pop",14:"leave",15:"syscall"}

def u64(b:bytes)->int: return int.from_bytes(b,"little")
def u32(b:bytes)->int: return int.from_bytes(b,"little") & 0xffffffff
def u48(b:bytes)->int: return int.from_bytes(b[:6],"little")

def reg_index(code:int)->int:
    if code < 20: return code // 5
    return 4 + (code - 20) // 4

def reg_name(code:int)->str:
    if code < 20:
        r = code // 5
        t = code % 5
        suf = ["","d","w","b","h"][t]
        return f"r{r}{suf}"
    code -= 20
    r = 4 + code // 4
    t = code % 4
    suf = ["","d","w","b"][t]
    return f"r{r}{suf}"

def base_mem(code:int)->str:
    return f"r{reg_index(code)}"

def mem_addr(base_code:int, plus:bool, disp:int)->str:
    if disp==0: return f"[{base_mem(base_code)}]"
    s = "+" if plus else "-"
    return f"[{base_mem(base_code)} {s} 0x{disp:x}]"

def dis_one(code:bytes, off:int):
    op = code[0]
    g  = op >> 3
    m  = op & 7
    A  = code[1:9]
    B  = code[9:17]

    if g in OP_ARITH:
        mn = OP_ARITH[g]
        if m==0:
            dst = reg_name(u32(A))
            imm = u64(B)
            return f"{mn} {dst}, 0x{imm:x}"
        if m==1:
            dst = reg_name(u32(A))
            src = reg_name(u32(B[:4]))
            return f"{mn} {dst}, {src}"
        if m==2:
            dst = reg_name(u32(A))
            base = B[0]
            plus = B[1]!=0
            disp = u48(B[2:8])
            return f"{mn} {dst}, {mem_addr(base,plus,disp)}"
        if m==3:
            base = A[0]
            plus = A[1]!=0
            disp = u48(A[2:8])
            src  = reg_name(B[0])
            return f"{mn} {mem_addr(base,plus,disp)}, {src}"
        if m==4:
            base = A[0]
            plus = A[1]!=0
            disp = u48(A[2:8])
            imm  = u64(B)
            return f"{mn} {mem_addr(base,plus,disp)}, 0x{imm:x}"
        return f"db 0x{op:02x}"
    if g in OP_CTRL:
        mn = OP_CTRL[g]
        if g in (7,8,9,10):
            return f"{mn} 0x{u64(A):x}"
        if g==11:
            return mn
        if g==12:
            return f"{mn} {reg_name(u32(A))}"
        if g==13:
            return f"{mn} {reg_name(u32(A))}"
        if g in (14,15):
            return mn
    return f"db 0x{op:02x}"

def disasm(blob:bytes, base:int=0)->List[str]:
    out=[]
    i=0
    n=len(blob)
    while i+17<=n:
        line = dis_one(blob[i:i+17], i)
        out.append(f"{base+i:016x}: {line}")
        i+=17
    if i<n:
        out.append(f"{base+i:016x}: db {blob[i:].hex()}")
    return out

if __name__=="__main__":
    from ops import data
    for l in disasm(data,0):
        print(l)
