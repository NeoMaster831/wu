import numpy as np
from sage.all import *

def reverse_rotation(matrix):
    n = 24
    for i in range(12):
        for j in range(i, n-i):
            temp = matrix[j][i]
            matrix[j][i] = matrix[n-1-i][j]
            matrix[n-1-i][j] = matrix[n-1-j][n-1-i]
            matrix[n-1-j][n-1-i] = matrix[i][n-1-j]
            matrix[i][n-1-j] = temp
    return matrix

def reverse_matrix_mult(result, input_mat, mod=0xFFFF, mode='A'):
    R = IntegerModRing(mod)
    A = matrix(R, 24, 24, input_mat.flatten().tolist())
    C = matrix(R, 24, 24, result.flatten().tolist())
    
    try:
        if mode == 'A':
            X = C * A.inverse()
        else:
            X = A.inverse() * C
        return np.array(X).astype(np.int64)
    except Exception as e:
        print(e)
        return None

def reverse_counter_clockwise_rotation(matrix):
    n = 24
    for i in range(12):
        for j in range(i, n-i):
            temp = matrix[i][j]
            matrix[i][j] = matrix[j][n-1-i]
            matrix[j][n-1-i] = matrix[n-1-i][n-1-j]
            matrix[n-1-i][n-1-j] = matrix[n-1-j][i]
            matrix[n-1-j][i] = temp
    return matrix

def reverse_element_wise_addition(result_matrix, known_matrix, mod=0xFFFF):
    n = 24
    unknown_matrix = np.zeros((n, n), dtype=np.int64)
    
    for i in range(n):
        for j in range(n):
            unknown_matrix[i, j] = (result_matrix[i, j] - known_matrix[i, j]) % mod
    
    return unknown_matrix

x_mat = ...

from pwn import u32
x_mat = [u32(x_mat[i * 4:(i + 1) * 4]) for i in range(24 * 24)]
x_mat = np.array(x_mat)
x_mat = x_mat.reshape(24, 24)

from datas import dm1, dm2, dm3, dm4, target

target = reverse_element_wise_addition(target, dm3)
target = reverse_matrix_mult(target, dm2, mode='A')
target = reverse_element_wise_addition(target, dm1)
target = reverse_counter_clockwise_rotation(target)
target = reverse_matrix_mult(target, x_mat, mode='B')
target = reverse_matrix_mult(target, x_mat, mode='A')
target = reverse_rotation(target)

from z3 import *

bCodeGate = b"C0D3GAT3"
known_border = [ [0] * 26 for _ in range(26) ]
for i in range(1, 25):
    for j in range(1, 25):
        known_border[i][j]= bCodeGate[((i-1) + (j-1)) % 8]

for i in range(2, 24):
    for j in range(2, 24):
        known_border[i][j] = BitVec(f"known_border_{i}_{j}", 8)

solver = Solver()
for i in range(24):
    for j in range(24):
        s = 0
        for di in range(3):
            for dj in range(3):
                s += known_border[i+di][j+dj]
        solver.add(s == target[i][j])

print(solver.check())
m = solver.model()

print(type(m[known_border[i][0]]))

gay = b""
for i in range(2, 24):
    for j in range(2, 24):
        gay += bytes([ m[BitVec(f"known_border_{i}_{j}", 8)].as_long() ])
print(gay)
