#! /usr/bin/env gdb -x
import gdb

gdb.execute("file ./deploy/main.exe")
#gdb.execute("break *0x0000555555593ED5") # Constant Array 1
#gdb.execute("break *0x555555593F19") # Constant Array 2
#gdb.execute("break *0x0000555555593F5D") # Constant Array 3
#gdb.execute("break *0x0000555555593FA1") # Constant Array 4
#gdb.execute("break *0x0000555555593EDA") # become value 1
#gdb.execute("break *0x555555593F1E") # become value 2
#gdb.execute("break *0x0000555555593F62") # become value 3
gdb.execute("break *0x0000555555593FA6") # become value 4
gdb.execute("run < input0")

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

l1 = do("rax")
l1 = [ (l1[i] - 1) // 2 for i in range(len(l1)) ]
print(l1)

exit()