import idautils
import ida_hexrays
import ida_funcs
import ida_lines

DIR = "/home/wane/Chall/Wargame/DH/Reverse/zrq"
ea_base = 0x559EBC000000
FUNC_START_EA = ea_base + 0x2694
FUNC_END_EA = ea_base + 0x5820

total_text = ""

for ea in idautils.Functions(FUNC_START_EA, FUNC_END_EA):
    cf = ida_hexrays.decompile(ea)
    sv = cf.get_pseudocode()
    func_text = "\n".join(ida_lines.tag_remove(itm.line) for itm in sv)
    func_name = ida_funcs.get_func_name(ea)
    with open(f"{DIR}/cfuncs/{func_name}.c", "w") as f:
        f.write(func_text)
    print(f"[+] Decompiled {func_name}")

with open(f"{DIR}/decompiled_functions.txt", "w") as f:
    f.write(total_text)