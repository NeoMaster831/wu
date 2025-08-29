import ida_dbg
import idc
import json
import idaapi
from node import Node

DIR = "/home/wane/Chall/Wargame/DH/Reverse/zrq"
cnt = 0
BATCH = 1024
s = set()
buf = []

def flush():
    global buf
    if not buf:
        return
    with open(f"{DIR}/log.jsonl", "a", encoding="utf-8") as f:
        for rec in buf:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    buf = []

def snap_regs():
    names = ("rdi","r8")
    regs = {}
    for n in names:
        regs[n.upper()] = int(idc.get_reg_value(n))  # 안전하게 int 캐스팅
    return regs

def is_valid_addr(ea, size=1):
    try:
        data = idaapi.dbg_read_memory(ea, size)
        return data is not None
    except Exception as e:
        print(e)
        return False

def build_context(head_ptr, depth=0):
    if depth > 15:
        return []
    fd = idaapi.get_qword(head_ptr)
    bk = idaapi.get_qword(head_ptr + 8)
    fn = idaapi.get_qword(head_ptr + 16)
    content = idaapi.get_qword(head_ptr + 24)

    fg1 = Node(head_ptr, fd, bk, fn, content, f"mem_{head_ptr:X}")
    fg2 = build_context(fd, depth+1) if is_valid_addr(fd) else []
    return [ fg1 ] + fg2

class RegDumpHook(ida_dbg.DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        global cnt, buf
        regs = snap_regs()
        context = build_context(regs["RDI"])
        context = [ {"ea": int(node.ea), "fd": int(node.fd), "bk": int(node.bk), "fn": int(node.unk0), "content": int(node.content)} for node in context ]
        rec = {
            "ea": int(ea),
            "cnt": int(cnt),
            "r8": regs['R8'],
            "rdi": regs['RDI'],
            "context": context
        }
        buf.append(rec)
        cnt += 1

        if len(buf) >= BATCH:
            flush()
        return 0
    
    def dbg_suspend_process(self):
        ida_dbg.continue_process()

_reg_dump_hook = RegDumpHook()
_reg_dump_hook.hook()
print("[*] Hooked!")