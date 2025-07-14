import numpy as np
from bbb import fuck_carry, convert_to_int

from z3 import *

def solve_become_no_fft(Q, W, r):
    assert len(Q) == 60
    assert len(W) == 60

    n = 60
    L = 2 * n
    b = [x + 1 for x in Q] + [1] * n
    b2 = [x + 1 for x in W] + [1] * n
    conv = [0] * L
    for k in range(L):
        tot = 0
        for j in range(L):
            tot += b[j] * b2[(k - j) % L]
        conv[k] = tot

    conv[0] += 1

    conv_extended = conv + [0] * (L * 10)

    binary = []
    for i in range(len(conv_extended) - 1):
        conv_extended[i + 1] += conv_extended[i] // r
        binary.append(conv_extended[i] % r)

    return binary[:60][::-1]

LEN = 60
def solve_become(Q, W, r):

    assert(len(Q) == LEN)
    assert(len(W) == LEN)

    b = [] + Q
    b2 = [] + W

    for i in range(LEN):
        b.append(0)
        b2.append(0)

    assert(len(b) == LEN*2)
    assert(len(b2) == LEN*2)

    for i in range(LEN*2):
        b[i] += 1
        b2[i] += 1

    a = np.fft.fft(b)
    a2 = np.fft.fft(b2)

    a3 = [ a[i] * a2[i] for i in range(len(a)) ]
    
    for i in range(len(a3)):
        a3[i] += 1
        
    a4 = np.fft.ifft(a3)

    a4 = [ (round(v.real, 3), round(v.imag, 3)) for v in a4 ]
    a4 = [ int(v[0]) for v in a4 ]
    binary = fuck_carry(a4, r)

    return binary[:LEN][::-1]

# [1, 0, 3, 5] 0

def predict(q: str, C1, C2, C3, C4):

    tl = []
    for c in q:
        tl.append(get_emoji_index_as_abcd(c))
    
    #print(tl)

    Q = [a for a, _, _, _ in tl]
    W = [] + C1

    answer1 = solve_become(Q, W, 2)

    Q = [b for _, b, _, _ in tl]
    W = [] + C2

    answer2 = solve_become(Q, W, 3)

    Q = [c for _, _, c, _ in tl]
    W = [] + C3

    answer3 = solve_become(Q, W, 5)

    Q = [d for _, _, _, d in tl]
    W = [] + C4

    answer4 = solve_become(Q, W, 7)

    from bbb import get_emoji

    recovered = []

    for i in range(60):
        recovered.append(get_emoji(answer1[i], answer2[i], answer3[i], answer4[i]))

    recovered = recovered[::-1]

    return recovered

from ddd import get_c
C1, C2, C3, C4 = get_c(0)

mapping = {}

from strt import *
from bbb import get_abcd, get_emoji_index_as_abcd, get_emoji

for i in range(210):
    a, b, c, d = get_abcd(i)
    r = predict(get_emoji(a, b, c, d) * 60, C1, C2, C3, C4)
    g = l[i]

    for j in range(60):
        if r[j] not in mapping:
            mapping[r[j]] = g[j]
        else:
            assert(mapping[r[j]] == g[j])

print(mapping)

def predict_with_transform(q: str, C1, C2, C3, C4):
    return [ mapping[c] for c in predict(q, C1, C2, C3, C4) ]
