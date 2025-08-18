from math import floor, pi, sqrt
from p import P
        
def find_closest_factor(n):
    l = floor(sqrt(n))
    while n % l != 0:
        l -= 1
    return l

def becalm(l, p):

    if len(l) == 1:
        return [ l[0] + 1 ]
    alpha = find_closest_factor(len(l)) # 120 -> 10
    beta = len(l) // alpha # 12
    pb = p * beta
    pa = p * alpha

    # beta등분
    a = []
    for i in range(beta):
        b = [ l[i + j * beta] for j in range(alpha) ]
        assert len(b) == alpha
        # 0, 12, 24, 36, 48, 60, 72, 84, 96, 108
        a.append(becalm(b, pb))

    pa_mat = [ [pa * i * j for j in range(beta)] for i in range(beta)]
    print(a)
    a = [item for sublist in a for item in sublist]

    result_vector = []
    for k in range(alpha):
        sub = [ a[i + k * beta] for i in range(beta) ]
        result_vector0 = []
        for i in range(beta):
            result = 0
            for j in range(beta):
                result += sub[j] * pa_mat[i][j].cos_theta
            result_vector0.append(result)
        result_vector.append(result_vector0)
    result_vector_flat = [item for sublist in result_vector for item in sublist]
    return result_vector_flat

print(P.from_angle(pi))
print(becalm([1, 1, 1, 1, 1, 0, 0, 0, 0, 0], P.from_angle(pi / 5)))