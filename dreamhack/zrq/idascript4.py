import idautils
import ida_dbg

ea_base = 0x5644CF000000
FUNC_START_EA = ea_base + 0x2694
FUNC_END_EA = ea_base + 0x5820

for ea in idautils.Functions(FUNC_START_EA, FUNC_END_EA):
    ida_dbg.add_bpt(ea)
    print(f"[+] Added breakpoint at {hex(ea)}")