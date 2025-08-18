import math
from typing import Tuple

# === 제공된 초기 코드 ===

ints = [ i for i in range(1, 301) ]
buckets = [ [] for _ in range(5)]
for i in range(0, len(ints) // 4):
    x, y, z, w = ints[i], ints[i + 75], ints[i + 150], ints[i + 225]
    buckets[(z + w) % 5].append((x, y, z, w))

def dot(u: Tuple[float, ...], v: Tuple[float, ...]) -> float:
    return sum(ui*vi for ui, vi in zip(u, v))

def norm3(v: Tuple[float, float, float]) -> float:
    return math.sqrt(dot(v, v))

def e1_components(p0: Tuple[int, int, int, int]) -> Tuple[float, float, float, float]:
    x0, y0, z0, w0 = p0
    n0 = math.sqrt(x0*x0 + y0*y0 + z0*z0)
    return (x0/n0, y0/n0, z0/n0, w0/n0)

def e2_components(
    p0: Tuple[int, int, int, int],
    p1: Tuple[int, int, int, int]
) -> Tuple[float, float, float, float]:
    x0, y0, z0, w0 = p0
    x1, y1, z1, w1 = p1
    n0 = math.sqrt(x0*x0 + y0*y0 + z0*z0)
    e1 = (x0/n0, y0/n0, z0/n0)
    v1 = (x1, y1, z1)
    proj = dot(v1, e1)
    u = (v1[0] - proj*e1[0], v1[1] - proj*e1[1], v1[2] - proj*e1[2])
    n1 = norm3(u)
    e2_x, e2_y, e2_z = (u[0]/n1, u[1]/n1, u[2]/n1)
    e1_w = w0 / n0
    u_w = w1 - proj * e1_w
    e2_w = u_w / n1
    return (e2_x, e2_y, e2_z, e2_w)

def e3_components(
    p0: Tuple[int, int, int, int],
    p1: Tuple[int, int, int, int],
    p2: Tuple[int, int, int, int]
) -> Tuple[float, float, float, float]:
    e1 = e1_components(p0)
    e2 = e2_components(p0, p1)
    e1_xyz = (e1[0], e1[1], e1[2])
    e1_w = e1[3]
    e2_xyz = (e2[0], e2[1], e2[2])
    e2_w = e2[3]
    x2, y2, z2, w2 = p2
    v2_xyz = (x2, y2, z2)
    proj1 = dot(v2_xyz, e1_xyz)
    proj2 = dot(v2_xyz, e2_xyz)
    u_x = v2_xyz[0] - proj1 * e1_xyz[0] - proj2 * e2_xyz[0]
    u_y = v2_xyz[1] - proj1 * e1_xyz[1] - proj2 * e2_xyz[1]
    u_z = v2_xyz[2] - proj1 * e1_xyz[2] - proj2 * e2_xyz[2]
    u_xyz = (u_x, u_y, u_z)
    n2 = norm3(u_xyz)
    e3_x, e3_y, e3_z = (u_xyz[0] / n2, u_xyz[1] / n2, u_xyz[2] / n2)
    u_w = w2 - proj1 * e1_w - proj2 * e2_w
    e3_w = u_w / n2
    return (e3_x, e3_y, e3_z, e3_w)

# === 잔차 계산 및 출력 코드 ===

# 1. buckets[0]의 첫 세 점을 사용하여 기저 벡터 e1, e2, e3를 계산합니다.
p0, p1, p2 = buckets[0][0], buckets[0][1], buckets[0][2]
e3 = e3_components(p0, p1, p2)

# 2. e3의 3D 부분(단위 벡터)을 추출합니다.
e3_xyz = (e3[0], e3[1], e3[2])

# 3. 네 번째 점부터 시작하여 각 점의 3D 부분을 e3_xyz에 투영(내적)합니다.
residuals = []
# buckets[0]는 총 15개의 점을 가집니다. (i_max = 14)
# 4번째 점(인덱스 3)부터 마지막 점까지 반복합니다.
for i in range(3, len(buckets[0])):
    p_i = buckets[0][i]
    v_i_xyz = (p_i[0], p_i[1], p_i[2]) # 점의 3D 부분
    
    # v_i_xyz를 e3_xyz에 투영한 스칼라 값을 계산합니다.
    residual_on_e3 = dot(v_i_xyz, e3_xyz)
    residuals.append(residual_on_e3)

# 4. 계산된 잔차 값의 첫 세 개를 출력하여 확인합니다.
print("Residuals on e3 direction:")
print(f"Point 4 (buckets[0][3]): {residuals[0]:.8f}")
print(f"Point 5 (buckets[0][4]): {residuals[1]:.8f}")
print(f"Point 6 (buckets[0][5]): {residuals[2]:.8f}")