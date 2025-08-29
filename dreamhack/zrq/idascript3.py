import idaapi
import idautils
import idc
import ida_bytes
from node import Node

DIR = "/home/wane/Chall/Wargame/DH/Reverse/zrq"

seg = idaapi.get_segm_by_name(".data")
start = seg.start_ea
end = seg.end_ea

desc = {}
for ea in idautils.Heads(start, end):
    name = idc.get_name(ea)
    if name.startswith("off_"):
        fd = ida_bytes.get_qword(ea) # +0x0, fd
        bk = ida_bytes.get_qword(ea + 8) # +0x8, bk
        unk0 = ida_bytes.get_qword(ea + 16) # +0x10, unk0
        content = ida_bytes.get_qword(ea + 24) # +0x18, content
        node = Node(ea, fd, bk, unk0, content, name)
        desc[ea] = node

with open(f"{DIR}/desc.py", "w") as f:
    f.write("from node import Node\n") # fd / bk / ea 와 desc 사이 강한 의존성이 생기지만 전혀 상관없음
    f.write("desc = {\n")
    for k, v in desc.items():
        f.write(f"    0x{k:X}: {v},\n")
    f.write("}\n")