import ida_dbg
import idc
import idaapi

class RegDumpHook(ida_dbg.DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        
        print(f"RAXVAL: {hex(idaapi.get_qword(int(idc.get_reg_value('RAX')) + 0x10))}")
        return 0
    
_reg_dump_hook = RegDumpHook()
_reg_dump_hook.hook()
print("[*] Hooked!")