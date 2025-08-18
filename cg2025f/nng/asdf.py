import numpy as np
from gen1 import f
# -----------------------------------------------------------------
# 1단계: NumPy를 사용한 입력 데이터 생성 및 버킷 분류
# -----------------------------------------------------------------

# 1부터 300까지의 정수 배열 생성 (float 타입으로 시작)
ints = np.array(f, dtype=np.float64)

# 75개의 4D 포인트를 NumPy의 배열 슬라이싱과 스태킹으로 한 번에 생성
# shape: (75, 4)
points = np.stack([
    ints[0:75],
    ints[75:150],
    ints[150:225],
    ints[225:300]
], axis=1)

# 모든 포인트에 대한 버킷 인덱스를 한 번에 계산
# z는 3번째 열(인덱스 2), w는 4번째 열(인덱스 3)
bucket_indices = ((points[:, 2] + points[:, 3]) % 5).astype(int)

# 5개의 빈 버킷 (NumPy 배열을 담을 리스트) 준비
buckets = [[] for _ in range(5)]
for i in range(5):
    # 해당 인덱스를 가진 모든 포인트를 필터링하여 버킷에 추가
    buckets[i] = points[bucket_indices == i]

print("--- 데이터 준비 완료 (NumPy) ---")
print(f"buckets[0]에 들어있는 점의 개수: {len(buckets[0])}")
print(f"buckets[0]의 첫 번째 점 (p0): {buckets[0][0]}")
print("\n")


# -----------------------------------------------------------------
# 2단계: NumPy를 사용한 특수 그람-슈미트 함수 정의
# -----------------------------------------------------------------
# 함수들은 입력과 출력으로 NumPy 배열을 사용합니다.

def e1_components_np(p0: np.ndarray) -> np.ndarray:
    """p0로부터 기저 벡터 e1을 계산합니다."""
    p0_xyz = p0[:3]
    n0_xyz = np.linalg.norm(p0_xyz)
    if n0_xyz == 0:
        return np.zeros(4)
    return p0 / n0_xyz

def e2_components_np(p0: np.ndarray, p1: np.ndarray) -> np.ndarray:
    p0_xyz, p1_xyz = p0[:3], p1[:3]
    n0_xyz = np.linalg.norm(p0_xyz)
    if n0_xyz == 0: return e1_components_np(p1)
    
    e1_xyz = p0_xyz / n0_xyz
    
    proj_scalar = np.dot(p1_xyz, e1_xyz)
    u2_xyz = p1_xyz - proj_scalar * e1_xyz
    
    n_u2_xyz = np.linalg.norm(u2_xyz)
    if n_u2_xyz == 0: return np.zeros(4)
    e2_xyz = u2_xyz / n_u2_xyz

    e1_w = p0[3] / n0_xyz
    u2_w = p1[3] - proj_scalar * e1_w
    e2_w = u2_w / n_u2_xyz
    
    return np.array([e2_xyz[0], e2_xyz[1], e2_xyz[2], e2_w])


p0 = buckets[0][0]  # 첫 번째 점
p1 = buckets[0][1]  # 두 번째 점
p2 = buckets[0][2]  # 세 번째 점
p3 = buckets[0][3]  # 네 번째 점 (검증용)
p4 = buckets[0][4]  # 다섯 번째 점 (검증용)
p5 = buckets[0][5]  # 여섯 번째 점 (검증용)

e1 = e1_components_np(p0)
e2 = e2_components_np(p0, p1)

print("--- 기저 벡터 계산 결과 (NumPy) ---")
print(f"e1 = {e1}")
print(f"e2 = {e2}")
print(f"p0 = {p0}")
print(f"p1 = {p1}")
print(f"p2 = {p2}")
print(f"p3 = {p3}")
print(f"p4 = {p4}")
print(f"p5 = {p5}")
print("\n")

print("--- 가설 검증: -dot((p1-p0)_xyz, e1_xyz) ---")

v_diff = p3 - p4
v2_diff = p4 - p5
print(f"p3 - p4: {v_diff}")

v_diff_xyz = v_diff[:3]
v2_diff_xyz = v2_diff[:3]
e1_xyz = e1[:3]
e2_xyz = e2[:3]

proj_1 = np.dot(v_diff_xyz, e1_xyz)
proj_2 = np.dot(v_diff_xyz, e2_xyz)

print(f"(p3 - p4) * e1: {proj_1:.8f}")
print(f"(p3 - p4) * e2: {proj_2:.8f}")

import math
unk0  = math.sqrt(np.dot(v_diff_xyz, v_diff_xyz) - proj_1**2 - proj_2**2)
print(f"unk0 (직교 성분의 크기, Correct): {unk0:.8f}")

with open('output', 'r') as f:
    outputs = list(map(int, f.read().split()))

outputs_25_split = [outputs[i:i + 25] for i in range(0, len(outputs), 25)]
#print(outputs_25_split)
print(len(outputs_25_split))

print(outputs_25_split[10])