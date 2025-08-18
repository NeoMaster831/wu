#! /usr/bin/env gdb -x
import gdb

k = 0

gdb.execute("file ./deploy/main.exe")
gdb.execute("break *0x0000555555593ED5") # first (a)
gdb.execute("break *0x555555593F19") # second (b)
gdb.execute("break *0x555555593F5D") # third (c)
gdb.execute("break *0x555555593FA1") # fourth (d)

g = [None] * 210

for k in range(210):
    gdb.execute(f"run < input{k}")

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

    l1 = do("rbx")
    l1 = [ (l1[i] - 1) // 2 for i in range(len(l1)) ]
    #print(l1)

    gdb.execute("continue")

    l2 = do("rbx")
    l2 = [ (l2[i] - 1) // 2 for i in range(len(l2)) ]
    #print(l2)

    gdb.execute("continue")

    l3 = do("rbx")
    l3 = [ (l3[i] - 1) // 2 for i in range(len(l3)) ]
    #print(l3)

    gdb.execute("continue")

    l4 = do("rbx")
    l4 = [ (l4[i] - 1) // 2 for i in range(len(l4)) ]
    #print(l4)

    # check value is same for each list
    for i in range(len(l1) - 1):
        assert(l1[i] == l1[i + 1])

    for i in range(len(l2) - 1):
        assert(l2[i] == l2[i + 1])

    for i in range(len(l3) - 1):
        assert(l3[i] == l3[i + 1])

    for i in range(len(l4) - 1):
        assert(l4[i] == l4[i + 1])

    result = [ l1[0], l2[0], l3[0], l4[0] ]

    g[k] = result

print(g)