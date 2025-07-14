import numpy as np
from bbb import convert_to_int, fuck_carry

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
    #binary_int = convert_to_int(binary, r)

    #print(binary_int // (r ** (LEN * 2) - 1))
    return binary[:LEN][::-1]

def check(Q, W, r):
    assert len(Q) == LEN
    assert len(W) == LEN

    n = LEN
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

    
    #print(conv)

    conv_extended = conv + [0] * (L * 10)

    binary = []
    for i in range(len(conv_extended) - 1):
        conv_extended[i + 1] += conv_extended[i] // r
        binary.append(conv_extended[i] % r)

    return convert_to_int(binary, r)


def REV(res: list[int], f2: list[int], mod: int):
  returns = []
  orig_len = len(res)
  orig_mod = mod**orig_len
  product = int("".join(map(str, res)), mod)
  num = int("1" * (orig_len * 2), mod)
  num2 = int("".join(map(str, f2[::-1])), mod)
  for i in range(orig_len * 2, orig_len * 2 + (orig_len * 2) * (mod - 1)):
    lower = (product - (num * i + 1)) % orig_mod
    num1 = (lower * pow(num2, -1, orig_mod)) % orig_mod
    p = num1 * num2 + num * i + 1
    assert p % orig_mod == product
    f1 = []
    while num1:
      f1.append(num1 % mod)
      num1 //= mod
    f1 += [0] * (orig_len - len(f1))
    ans = solve_become(list(f1), list(f2), mod)
    if ans == res:
      returns.append(f1)
  return returns


"""
from tqdm import tqdm
def REV(target, W, r):

    print("Target", target)
    print("W", W)

    orig_target = [] + target
    target = convert_to_int(target[::-1], r) - 1

    wdigit_sum = sum(W)
    for pdigit_sum in tqdm(range(r * LEN)):
        for i in range(200):
            ex = pdigit_sum + wdigit_sum + LEN * 2
            ex_m = ex % (r - 1)
            gt = target + i - ex_m * convert_to_int([1] * LEN, r)
            
            # It is ALWAYS invertible yes
            expected_q = (pow(convert_to_int(W, r), -1, r ** LEN) * (gt % (r ** LEN))) % r ** LEN

            exql = []
            while expected_q != 0:
                exql.append(expected_q % r)
                expected_q //= r
            
            while len(exql) < LEN:
                exql.append(0)

            if solve_become(exql, W, r) == orig_target: # (1111 + q)(1111 + w) / (7 ** 120 - 1) = i
                return exql
    raise Exception("I got defeated maybe just quit")
"""
if __name__ == "__main__":

    import random
    for _ in range(100):
        
        r = 3
        w = [ random.randrange(0, r) for _ in range(LEN) ]
        h = [ random.randrange(0, r) for _ in range(LEN) ]
        w[0] = 1
        tar = solve_become(h, w, r)
        print("target", tar)
        aaa = REV(tar, w, r)
        print("recovered:", aaa)
        targ = solve_become(aaa, w, r)
        print("test", targ)

        assert(tar == targ)
