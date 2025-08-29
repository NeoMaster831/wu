def reshape(flat, r, c):
    return [flat[i * c:(i + 1) * c] for i in range(r)]

# There's no integer_representation in Sagemath 10.7 
def integer_representation(z) -> int:
    coeffs = z.list()
    coeffs += [0] * (8 - len(coeffs))
    return sum(int(coeffs[i]) << i for i in range(8))

M = bytes.fromhex("""
01 01 01 01 01 01 01 01  01 01 01 01 01 01 01 11
85 C6 B5 EF 32 87 B7 0E  ED 7A 94 BD EA 51 D4 40
E4 97 63 BE E6 D6 BC 5F  C5 2B BB EC 51 2C 5F FB
6F 6D 5D 05 D8 90 7E E4  07 BB EA 57 08 7B 38 AC
0A 3A 8F 52 29 C7 50 B3  BD EC 57 7B A6 13 23 85
11 52 21 29 7E C5 94 9A  79 EE
""")
M = reshape(list(M), 6, 15)
data_resembled = ...
data_0_end = 0xf8a2
data_1_start = 0xf8ac
data_0 = data_resembled[:data_0_end] + [ (0xFF, False) ] * 10
data_1 = data_resembled[data_1_start:]

assert(len(data_0) % 15 == 0)
assert(len(data_1) % 6 == 0)
assert(len(data_0) // 15 == len(data_1) // 6)

R.<x> = GF(2)[]
F.<a> = GF(2**8, modulus = x^8 + x^4 + x^3 + x^2 + 1)

original_data = []
for i in range(0, len(data_0) // 15):
    target = data_0[i*15:(i+1)*15]
    res = data_1[i*6:(i+1)*6]

    m = []
    v = []
    for j in range(6):
        if res[j][1] == True: # If the result is lost...
            continue

        v_1 = F._cache.fetch_int(res[j][0])
        m_1 = []
        for k in range(15):
            if target[k][1] == True: # If the result is lost...
                m_1.append(F._cache.fetch_int(M[j][k]))
            else:
                v_1 -= F._cache.fetch_int(M[j][k]) * F._cache.fetch_int(target[k][0])
        
        m.append(m_1)
        v.append(v_1)
    
    print(m, v)
    assert(len(m) == len(v))
    m = matrix(m)
    v = vector(v)
    sol = m.solve_right(v)
    l_wanted = len(sol)

    l = 0
    original_target = []
    for j in range(15):
        if target[j][1] == False: # If the result is ok...
            original_target.append(target[j][0])
        else:
            original_target.append(integer_representation(sol[l]))
            l += 1
    
    original_data += original_target

original_data = bytes(original_data)

# Remove \xFF padding at right
original_data = original_data[:-11]
with open('quiz.zrq.4', 'wb') as f:
    f.write(bytes(original_data))

print("done stage 4")
