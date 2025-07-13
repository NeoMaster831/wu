from z3 import *

cmp_list = [
    33452, 49509, 25851, 6141, 34805, 16648, 10819, 14818, 5285, 35240, 4328, 30884, 6529, 46255, 49762, 57055, 4527, 2722, 33996, 1631, 50252, 39966, 41692, 12305, 50231, 29268, 38384, 32126, 9193, 59248, 30814, 1402, 8068
]
#cmp_list = [ 4416 ]

eqs = 0
flag = [ BitVec(f'x{i}', 16) for i in range(len(cmp_list) + 3) ]
#flag = list(b'DH{}')
print(flag)

s = Solver()

for i in flag:
    s.add(And(0x20 <= i, i < 0x7f))

for i in range(len(cmp_list) - 1, -1, -1):
    eqs += flag[i]
    eqs ^= flag[i + 2]
    eqs *= flag[i + 1]
    eqs -= flag[i + 3]
    eqs ^= flag[i + 2]
    s.add(eqs == cmp_list[i])
    assert(s.check() == sat)

m = s.model()

for i in flag:
    print(chr(m[i].as_long()), end='')
