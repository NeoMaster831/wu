import numpy as np
import math
import os

# -----------------------------------------------------------------
# 0단계: 테스트 환경 설정 (gen1.py 및 output 파일 임시 생성)
# -----------------------------------------------------------------
# 실제 f 데이터는 없으므로, 주어진 p0~p5가 버킷 0에 들어가도록 데이터를 재구성합니다.
# p0 = [137. 129. 133. 207.], (133+207)%5 = 0
# p1 = [ 42. 280. 299.  51.], (299+51)%5 = 0
# p2 = [ 35.  50. 205.  30.], (205+30)%5 = 0
# p3 = [136. 143. 225. 150.], (225+150)%5 = 0
# p4 = [ 13.  20.  16.  79.], (16+79)%5 = 0
# p5 = [  2. 108.   3.   7.], (3+7)%5 = 0

# gen1.py 생성
# 실제 f는 300개의 숫자지만, 테스트에 필요한 75개 포인트만 구성합니다.
# 버킷 0에 p0~p5가 순서대로 들어가도록 하고, 나머지는 더미 값으로 채웁니다.
f_data_points = np.zeros((75, 4))
f_data_points[0] = [137., 129., 133., 207.]
f_data_points[1] = [ 42., 280., 299.,  51.]
f_data_points[2] = [ 35.,  50., 205.,  30.]
f_data_points[3] = [136., 143., 225., 150.]
f_data_points[4] = [ 13.,  20.,  16.,  79.]
f_data_points[5] = [  2., 108.,   3.,   7.]

# f 배열 (300개) 재구성
f_array = np.concatenate([
    f_data_points[:, 0], f_data_points[:, 1], f_data_points[:, 2], f_data_points[:, 3]
])
with open("gen1.py", "w") as f:
    f.write(f"f = {f_array.tolist()}")

# -----------------------------------------------------------------
# 1단계: 데이터 로딩 및 버킷 분류 (사용자님 코드 기반)
# -----------------------------------------------------------------
from gen1 import f

ints = np.array(f, dtype=np.float64)
points = np.stack([
    ints[0:75], ints[75:150], ints[150:225], ints[225:300]
], axis=1)

bucket_indices = ((points[:, 2] + points[:, 3]) % 5).astype(int)
buckets = [points[bucket_indices == i] for i in range(5)]

print("--- 데이터 준비 완료 ---")
print(f"buckets[0]에 들어있는 점의 개수: {len(buckets[0])}")
print("\n")


# -----------------------------------------------------------------
# 2단계: 핵심 알고리즘 함수 정의 (사용자님 코드 기반)
# -----------------------------------------------------------------

def calculate_e1(p0: np.ndarray) -> np.ndarray:
    """p0로부터 기저 벡터 e1을 계산 (xyz 기준)"""
    p0_xyz = p0[:3]
    norm_xyz = np.linalg.norm(p0_xyz)
    if norm_xyz == 0: return np.zeros(4)
    # xyz 정규화 후, w도 동일한 값으로 나눠줌
    return p0 / norm_xyz

def calculate_e2(p0: np.ndarray, p1: np.ndarray) -> np.ndarray:
    """p0, p1로부터 기저 벡터 e2를 계산 (xyz 기준 그람-슈미트)"""
    p0_xyz, p1_xyz = p0[:3], p1[:3]
    norm_p0_xyz = np.linalg.norm(p0_xyz)
    if norm_p0_xyz == 0: return calculate_e1(p1)
    
    e1_xyz = p0_xyz / norm_p0_xyz
    
    # p1_xyz를 e1_xyz에 투영한 스칼라 값 계산
    proj_scalar = np.dot(p1_xyz, e1_xyz)
    
    # p1_xyz에서 투영 성분을 빼서 e1_xyz에 직교하는 u2_xyz를 구함
    u2_xyz = p1_xyz - proj_scalar * e1_xyz
    norm_u2_xyz = np.linalg.norm(u2_xyz)
    if norm_u2_xyz == 0: return np.zeros(4)
    
    # u2_xyz를 정규화하여 e2_xyz를 구함
    e2_xyz = u2_xyz / norm_u2_xyz

    # w 성분도 동일한 스칼라 연산을 적용
    e1_w = p0[3] / norm_p0_xyz
    u2_w = p1[3] - proj_scalar * e1_w
    e2_w = u2_w / norm_u2_xyz
    
    return np.array([*e2_xyz, e2_w])

def calculate_ortho_magnitude_xyz(v: np.ndarray, e1: np.ndarray, e2: np.ndarray) -> float:
    """
    벡터 v의 xyz 성분을 e1_xyz, e2_xyz 평면에 대한 직교 성분의 크기를 계산
    """
    v_xyz = v[:3]
    e1_xyz = e1[:3]
    e2_xyz = e2[:3]
    
    # v_xyz의 크기 제곱
    norm_v_sq = np.dot(v_xyz, v_xyz)
    
    # v_xyz를 e1_xyz, e2_xyz에 투영한 값
    proj1 = np.dot(v_xyz, e1_xyz)
    proj2 = np.dot(v_xyz, e2_xyz)
    
    # 피타고라스 정리: ||ortho||^2 = ||v||^2 - ||proj||^2
    # ||proj||^2 = proj1^2 + proj2^2 (e1_xyz, e2_xyz는 직교하므로)
    ortho_norm_sq = norm_v_sq - proj1**2 - proj2**2
    
    # 부동소수점 오류로 음수가 되는 경우 방지
    return math.sqrt(max(0, ortho_norm_sq))

# -----------------------------------------------------------------
# 3단계: 계산 및 최종 검증
# -----------------------------------------------------------------
all_outputs = []
for bucket in buckets:
    if len(bucket) > 5: # 최소 6개 점이 있어야 p0~p5 사용 가능
        p0, p1, p2, p3, p4, p5 = bucket[0], bucket[1], bucket[2], bucket[3], bucket[4], bucket[5]
        
        # 1. 기저 벡터 e1, e2 계산
        e1 = calculate_e1(p0)
        e2 = calculate_e2(p0, p1)
        
        # 2. 분석할 벡터 v1, v2 정의
        v1 = p3 - p4
        v2 = p5 - p0 # v2가 p5-p0인 것이 핵심
        
        # 3. 내적 계산 (xyz 공간에서만)
        dot1 = np.dot(v1[:3], e1[:3])
        dot2 = np.dot(v1[:3], e2[:3])
        
        # 4. 직교 성분 크기 계산
        ortho_mag1 = calculate_ortho_magnitude_xyz(v1, e1, e2)
        unk1 = calculate_ortho_magnitude_xyz(v2, e1, e2)
        
        # 결과 저장 (요청된 12개 값)
        # 실제로는 25개겠지만, 주어진 정보로 12개만 구성
        output_chunk = [
            *e1, *e2, dot1, dot2, ortho_mag1, unk1
        ]
        all_outputs.append(output_chunk)

# --- 결과 출력 ---
# 첫 번째 유효 버킷(bucket 0)의 결과만 출력하여 검증
if all_outputs:
    result = all_outputs[0]
    print("--- 최종 계산 결과 ---")
    print(f"e1 = [{result[0]:.8f}, {result[1]:.8f}, {result[2]:.8f}, {result[3]:.8f}]")
    print(f"e2 = [{result[4]:.8f}, {result[5]:.8f}, {result[6]:.8f}, {result[7]:.8f}]")
    print(f"p0 = {buckets[0][0]}")
    print(f"p1 = {buckets[0][1]}")
    print(f"p3 = {buckets[0][3]}")
    print(f"p4 = {buckets[0][4]}")
    print(f"p5 = {buckets[0][5]}")
    print("-" * 20)
    print(f"(p3 - p4)_xyz * e1_xyz = {result[8]:.8f}")
    print(f"(p3 - p4)_xyz * e2_xyz = {result[9]:.8f}")
    print(f"직교 성분의 크기        = {result[10]:.8f} (목표: 55.77...)")
    print(f"unk1 (p5-p0의 직교성분) = {result[11]:.8f} (목표: 70.17...)")