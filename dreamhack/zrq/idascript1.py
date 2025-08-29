import idc
import idautils

ea_base = 0x5599C2000000
FUNC_START_EA = ea_base + 0x2694
FUNC_END_EA = ea_base + 0x5820

for ea in idautils.Functions(FUNC_START_EA, FUNC_END_EA):
    proto = f"void __fastcall sub_{ea:X}(Node *a1);"
    if not idc.SetType(ea, proto):
        raise RuntimeError(f"Failed to set type for function at {ea:X}")
    print(f"[+] Set type for function at {ea:X}")