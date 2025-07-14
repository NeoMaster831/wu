import math
from typing import Tuple

# === 유틸리티 함수 (기존과 동일) ===
def dot(u: Tuple[float, ...], v: Tuple[float, ...]) -> float:
    return sum(ui*vi for ui, vi in zip(u, v))

def norm3(v: Tuple[float, float, float]) -> float:
    return math.sqrt(dot(v, v))

# === 그람-슈미트 과정 함수 (기존과 동일) ===
def e1_components(p0: Tuple[int, int, int, int]) -> Tuple[float, float, float, float]:
    x0, y0, z0, w0 = p0
    n0 = math.sqrt(x0*x0 + y0*y0 + z0*z0)
    if n0 == 0: return (0.0, 0.0, 0.0, 0.0)
    return (x0/n0, y0/n0, z0/n0, w0/n0)

def e2_components(
    p0: Tuple[int, int, int, int],
    p1: Tuple[int, int, int, int]
) -> Tuple[float, float, float, float]:
    x0, y0, z0, w0 = p0
    x1, y1, z1, w1 = p1
    n0_3d = math.sqrt(x0*x0 + y0*y0 + z0*z0)
    if n0_3d == 0: return e1_components(p1) # p0가 0벡터면 p1로 e1 계산

    e1_3d = (x0/n0_3d, y0/n0_3d, z0/n0_3d)
    v1_3d = (x1, y1, z1)
    
    proj_scalar = dot(v1_3d, e1_3d)
    u_3d = (v1_3d[0] - proj_scalar*e1_3d[0],
            v1_3d[1] - proj_scalar*e1_3d[1],
            v1_3d[2] - proj_scalar*e1_3d[2])

    n1_3d = norm3(u_3d)
    if n1_3d == 0: return (0.0, 0.0, 0.0, 0.0)
    e2_x, e2_y, e2_z = (u_3d[0]/n1_3d, u_3d[1]/n1_3d, u_3d[2]/n1_3d)

    e1_w = w0 / n0_3d
    u_w = w1 - proj_scalar * e1_w
    e2_w = u_w / n1_3d

    return (e2_x, e2_y, e2_z, e2_w)

def e3_components(
    p0: Tuple[int, int, int, int],
    p1: Tuple[int, int, int, int],
    p2: Tuple[int, int, int, int]
) -> Tuple[float, float, float, float]:
    e1 = e1_components(p0)
    e2 = e2_components(p0, p1)

    e1_xyz, e1_w = (e1[0], e1[1], e1[2]), e1[3]
    e2_xyz, e2_w = (e2[0], e2[1], e2[2]), e2[3]

    x2, y2, z2, w2 = p2
    v2_xyz = (x2, y2, z2)

    proj1 = dot(v2_xyz, e1_xyz)
    proj2 = dot(v2_xyz, e2_xyz)

    u_xyz = (v2_xyz[0] - proj1 * e1_xyz[0] - proj2 * e2_xyz[0],
             v2_xyz[1] - proj1 * e1_xyz[1] - proj2 * e2_xyz[1],
             v2_xyz[2] - proj1 * e1_xyz[2] - proj2 * e2_xyz[2])

    n2 = norm3(u_xyz)
    if n2 == 0: return (0.0, 0.0, 0.0, 0.0)
    e3_x, e3_y, e3_z = (u_xyz[0]/n2, u_xyz[1]/n2, u_xyz[2]/n2)

    u_w = w2 - proj1 * e1_w - proj2 * e2_w
    e3_w = u_w / n2

    return (e3_x, e3_y, e3_z, e3_w)

# === 메인 실행 로직 ===

# 1. 입력 데이터 생성
ints = [ i for i in range(1, 301) ]
buckets = [ [] for _ in range(5)]
for i in range(0, len(ints) // 4):
    x, y, z, w = ints[i], ints[i + 75], ints[i + 150], ints[i + 225]
    buckets[(z + w) % 5].append((x, y, z, w))

# 2. bucket[0]에서 첫 세 점 추출
p0 = buckets[0][0]
p1 = buckets[0][1]
p2 = buckets[0][2]

print(f"p0 = {p0}")
print(f"p1 = {p1}")
print(f"p2 = {p2}\n")

# 3. e1, e2, e3 순차 계산 및 출력
e1 = e1_components(p0)
e2 = e2_components(p0, p1)
e3 = e3_components(p0, p1, p2)

print(f"e1 = ({e1[0]:.8f}, {e1[1]:.8f}, {e1[2]:.8f}, {e1[3]:.8f})")
print(f"e2 = ({e2[0]:.8f}, {e2[1]:.8f}, {e2[2]:.8f}, {e2[3]:.8f})")
print(f"e3 = ({e3[0]:.8f}, {e3[1]:.8f}, {e3[2]:.8f}, {e3[3]:.8f})")

with open('output', 'r') as f:
    output = f.read().strip()