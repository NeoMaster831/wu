#!/usr/bin/env python3
import angr, claripy as cp
from encrypt_proc import EncryptProc
from memcmp_proc import MemcmpCheck

BINARY = './chal'
proj   = angr.Project(BINARY, auto_load_libs=False)

ADDR_ENCRYPT = 0x401250
ADDR_ENCRYPT_END = 0x401820
ADDR_MEMCMP   = proj.loader.main_object.get_symbol('memcmp').rebased_addr
ADDR_SUCCESS  = 0x401AA0 
ADDR_FAIL     = 0x401B10

# ▸ ② 후킹
proj.hook(ADDR_ENCRYPT, EncryptProc(), length=ADDR_ENCRYPT_END-ADDR_ENCRYPT)
proj.hook(ADDR_MEMCMP, MemcmpCheck())

# ▸ ③ 초기 상태 : stdin 에 64-byte 심볼릭 + '\n'
flag = cp.BVS('flag', 64*8)
state = proj.factory.full_init_state(stdin=flag.concat(cp.BVV(0x0A,8)))
for c in flag.chop(8):
    state.add_constraints(c >= 0x20, c <= 0x7e)   # printable

simgr = proj.factory.simgr(state)
simgr.explore(find=ADDR_SUCCESS, avoid=ADDR_FAIL)

if simgr.found:
    m = simgr.found[0].solver.eval(flag, cast_to=bytes)
    print("★ FLAG =", m.decode())
else:
    print("solve failed")
