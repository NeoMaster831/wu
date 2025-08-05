from z3 import *

last_state = [ 2, 1, 0, 2, 0, 1, 0, 1, 0, 2, 0, 0, 0, 0, 2, 0, 0, 1 ]
last_value = [ 0x27f9, 0x1FB3C, 0x18F04, 53325, 54980, 45659, 127536, 52798, 63346, 57365, 102582, 117554, 20346, 21686, 87331, 49286, 23640, 72246 ]

def Cit(_4, _5, _6, _7):
    return (_6 + _4 - _5) ^ _7

def Doc(_4, _5, _6, _7):
    return _6 ^ (_5 + _4) ^ _7

def Pol(_4, _5, _6, _7):
    return _5 ^ _4 ^ (_6 + _7)

def Maf(_4, _5, _6, _7):
    return _4 ^ _5 ^ _6 ^ _7

def Spy(_4, _5, _6, _7):
    return _6 ^ (_4 - _5) ^ _7

# Yun-Seok-Yul, in short.
def Yun(_4, _5, _6, _7):
    return (_5 + _4 - _6) ^ _7

flag = [ BitVec(f'x_{i}', 32) for i in range(8) ]

people = [
    [Cit, flag[0], flag[1], flag[2], flag[3]],
    [Doc, flag[4], flag[5], flag[6], flag[7]],
    [Pol, flag[0], flag[2], flag[4], flag[6]],
    [Maf, flag[1], flag[3], flag[5], flag[7]],
    [Spy, flag[0], flag[1], flag[6], flag[7]],
    [Yun, flag[2], flag[3], flag[4], flag[5]],
    [Yun, flag[4], flag[0], flag[6], flag[2]],
    [Spy, flag[4], flag[5], flag[6], flag[7]],
    [Maf, flag[0], flag[2], flag[4], flag[6]],
    [Pol, flag[1], flag[3], flag[5], flag[7]],
    [Doc, flag[0], flag[1], flag[6], flag[7]],
    [Cit, flag[6], flag[4], flag[2], flag[0]],
    [Cit, flag[3], flag[1], flag[7], flag[3]],
    [Doc, flag[0], flag[2], flag[2], flag[6]],
    [Pol, flag[7], flag[0], flag[4], flag[1]],
    [Maf, flag[5], flag[6], flag[0], flag[4]],
    [Spy, flag[1], flag[7], flag[3], flag[0]],
    [Yun, flag[2], flag[5], flag[6], flag[1]]
]

s = Solver()

for i, c in enumerate(people):
    for j in range(last_state[i] + 1):
        v = people[i][1]
        people[i][1] = people[i][2]
        people[i][2] = people[i][3]
        people[i][3] = people[i][4]
        people[i][4] = v
    ret = people[i][0](people[i][1], people[i][2], people[i][3], people[i][4])
    print(ret)
    s.add(ret == last_value[i])

print(s.check())
m = s.model()
print(m)
for i in flag:
    #print(hex(m[i].as_long()))
    print(hex(m[i].as_long() & 0xFFFF)[2:].rjust(4, '0'), end='')