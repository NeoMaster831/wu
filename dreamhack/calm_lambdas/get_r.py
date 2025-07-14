#! /usr/bin/env gdb -x
import gdb

gdb.execute("file ./deploy/main.exe")
#gdb.execute("break *0x55555558B973")
#gdb.execute("break *0x000055555558B98A")
gdb.execute("break *0x000055555558B99F")
gdb.execute("run < input")

def parse(s):
    s = s.split(":\t")[1]
    return int(s, 16)

def do(reg):
    a = gdb.execute(f"x/gx ${reg}", to_string=True)
    b = gdb.execute(f"x/gx ${reg}+8", to_string=True)

    l = []

    while b != 1:
        l.append(parse(a))
        nxt = parse(b)
        try:
            a = gdb.execute(f"x/gx {nxt}", to_string=True)
            b = gdb.execute(f"x/gx {nxt+8}", to_string=True)
        except Exception as e:
            print(e)
            break
    return l

ignore_first = False
l1 = do("rax")
l2 = []
for i, v in enumerate(l1):
    v1 = parse(gdb.execute(f"x/gx {v}", to_string=True))
    if i == 0 and ignore_first: # first is always constant, not imaginary
        c = parse(gdb.execute(f"x/gx {v1}", to_string=True))
        l2.append(c)
        continue
    
    v2 = parse(gdb.execute(f"x/gx {v1}", to_string=True))
    v2_1 = parse(gdb.execute(f"x/gx {v1+8}", to_string=True))

    v3 = parse(gdb.execute(f"x/gx {v2}", to_string=True))
    v3_1 = parse(gdb.execute(f"x/gx {v2_1}", to_string=True))

    l2.append((v3, v3_1))

assert(len(l2) == 120)

import struct

def unpack_double(v):
    return struct.unpack("d", struct.pack("Q", v))[0]

#print(hex(l2[0]))

if ignore_first:
    l2[0] = (unpack_double(l2[0]), 0)

for i, v in enumerate(l2):
    if i == 0 and ignore_first:
        continue
    l2[i] = (unpack_double(v[0]), unpack_double(v[1]))

print(l2)

# 정상화
for i, v in enumerate(l2):
    l2[i] = (round(v[0], 3), round(v[1], 3))

print(l2)

exit()