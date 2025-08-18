from z3 import *

chunks = [
    0x312c010608070602,
    0x3101000002333400,
    0x2f282d0202010101,
    0x052a073532002e2f,
    0x2f3101003131032f,
    0x3202010102350501,
    0x320130040404332f,
    0x04030400002f002f,
    0x2c31010704020102,
    0x05302b0502020005,
    0x2322e0332302f2c,
    0x020104062f312e30,
    0x30060031042e0200,
    0x2012d2c05032f01,
    0x01342f022b31342e,
    0x002c023003042c30,
]

tbl = b''.join(int(v).to_bytes(8, 'little') for v in chunks)
diff = list(tbl[:127])

xs = [BitVec(f'x{i}', 8) for i in range(128)]
s = Solver()

for x in xs:
    s.add(Or(And(x >= 0x30, x <= 0x39), And(x >= 0x61, x <= 0x66)))

for i in range(127):
    a, b = xs[i], xs[i+1]
    d = If(UGE(a, b), a - b, b - a)
    s.add(d == BitVecVal(diff[i], 8))

sum16 = ZeroExt(8, xs[0])
for i in range(1, 128):
    sum16 = sum16 + ZeroExt(8, xs[i])
s.add(sum16 == BitVecVal(0x21e8, 16))

h = BitVecVal(0x1505, 64)
for i in range(128):
    h = (h * BitVecVal(33, 64)) + ZeroExt(56, xs[i])
s.add(h == BitVecVal(0x2ebd31af413b6c2d, 64))

if s.check() != sat:
    print("UNSAT")
else:
    m = s.model()
    body = ''.join(chr(m[x].as_long()) for x in xs)
    print(f"YISF{{{body}}}")
