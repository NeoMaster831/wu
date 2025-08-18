#! /usr/bin/env gdb -x
import gdb
strt = "l = [[None] * 4] * 8\n"
gdb.execute("file ./deploy/main.exe")
gdb.execute("break *0x0000555555593EAB")

gdb.execute(f"run < input{0}")

for k in range(8):

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

    from pwn import p32

    p = do("rbx")

    p = [ parse(gdb.execute(f"x/gx {i}", to_string=True)) for i in p ]
    p = [ p32(i & 0xffffffff).decode('utf-8') for i in p ]

    strt += f"l[{k}] = {p}\n"

    gdb.execute("continue")


with open("strt2.py", "w") as f:
    f.write(strt)
