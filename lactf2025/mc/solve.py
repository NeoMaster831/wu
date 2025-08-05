#v1 = [145, 47, 213, 185, 157, 86, 191, 221, 98, 106, 202, 28, 168, 217, 37, 236, 131, 20, 10, 31, 138, 148, 115, 125, 190, 52, 55, 165, 205, 57, 81, 122, 170, 234, 120, 125, 188, 218, 154, 206]
from sage.all import *
from mat import g
v2 = [137, 193, 59, 168, 164, 129, 35, 165, 159, 193,
           12, 170, 90, 182, 156, 214, 172, 62, 59, 106,
           175, 186, 174, 231, 160, 56, 67, 221, 44, 68,
           90, 244, 192, 123, 140, 245, 218, 169, 58, 8]

M = matrix(GF(251), g)
V = vector(GF(251), v2)

v1 = list(M.solve_right(V))
print(v1)

for i in range(40):
    a = 0
    for j in range(40):
        a += g[i][j] * v1[j]
    assert(a % 251 == v2[i])

def f5(x, y=6, z=251):
    return (y ** x) % z

v3 = [0] * 40

for i in range(40):
    found = False
    for j in range(256):
        if f5(j) == v1[i]:
            v3[i] = j
            found = True
            break
    assert(found)

for i in range(40):
    assert(f5(v3[i]) == v1[i])

def f4(x):
    return (x * 97 + 129) % 256

origin = 106

for i in range(40):
    origin = f4(origin)
    print(chr(origin ^ v3[i]), end="")
