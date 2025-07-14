"""
3-stage SIMD 전처리 루틴의 파이썬 구현
────────────────────────────────────
입력  : bytes | bytearray  (임의 길이의 바이트 스트림)
출력  : np.ndarray  (shape = [8, 4, 8])   # 8 행 × 4 열 × 8 lane(float32)
단계  :
    1) 8-byte 슬라이딩 윈도(56→ … →-1 오프셋) → float32×8 벡터화
    2) 257 로 정규화 후 4가지 퍼뮤테이션(1B/6C/B1/D2) 적용
    3) 두 행씩 읽어 k-마스크(9A·65·4B·B4) 로 블렌드해 4 열 출력
"""
from __future__ import annotations
import struct, numpy as np

# ────────────────────────────────────
# 설정 상수
# ────────────────────────────────────
OFFSETS = [0x38, 0x2F, 0x27, 0x1F, 0x17, 0x0F, 0x07, -1]   # Stage-1 gather
PERM_IMM = (0x1B, 0x6C, 0xB1, 0xD2)                        # Stage-2 rotation
MASKS    = (0x9A, 0x65, 0x4B, 0xB4)                        # Stage-3 blend
K_SCALE  = 257.0                                           # vbroadcastss

# 임의의 8×8 가중치 테이블(디바이더 이후 곱해지는 값)
WEIGHT_TABLE = np.arange(64, dtype=np.float32).reshape(8, 8)

# ────────────────────────────────────
# 헬퍼들
# ────────────────────────────────────
def _permute_lane(vec: np.ndarray, imm: int) -> np.ndarray:
    """vpermilps 한 번(128-bit lane 내부만 4-float 셔플)"""
    pattern = [(imm >> (2 * i)) & 0b11 for i in range(4)]
    # 두 번째 128-bit 반쪽에도 동일 패턴
    return vec[np.array(pattern + [i + 4 for i in pattern], dtype=np.int8)]

def _blend(a: np.ndarray, b: np.ndarray, mask: int) -> np.ndarray:
    """vblendmps (32-bit lane 기준)"""
    sel = [(mask >> i) & 1 for i in range(8)]
    return np.where(sel, b, a)

# ────────────────────────────────────
# 1단계 : 바이트 → float32×8 를 32 B 간격으로 저장
# ────────────────────────────────────
def _stage1(byte_stream: bytes) -> np.ndarray:
    n = len(byte_stream) - OFFSETS[0]        # 슬라이딩 가능한 횟수
    out = np.empty((n, 8), dtype=np.float32)

    for i in range(n):
        vals = [int.from_bytes(byte_stream[i + off : i + off + 1],
                               "little", signed=True)
                 for off in OFFSETS]
        out[i] = np.array(vals, dtype=np.float32)
    return out                                # shape (N, 8)

# ────────────────────────────────────
# 2단계 : 257 로 나누고 4-패턴 회전 + 가중치 곱
# ────────────────────────────────────
def _stage2(rows: np.ndarray) -> np.ndarray:
    assert rows.shape[0] >= 8, "최소 8행 필요"
    processed = np.empty((8, 8), dtype=np.float32)

    for i in range(8):
        vec   = rows[i] / K_SCALE                 # 정규화
        vec   = _permute_lane(vec, PERM_IMM[i & 3])
        vec  *= WEIGHT_TABLE[i]                   # 임의 가중치
        processed[i] = vec
    return processed                              # shape (8, 8)

# ────────────────────────────────────
# 3단계 : 두 행씩 k-마스크 블렌드로 4 열 확장
# ────────────────────────────────────
def _stage3(mat8x8: np.ndarray) -> np.ndarray:
    out = np.empty((8, 4, 8), dtype=np.float32)   # 행, 열, lane
    for i in range(0, 8, 2):
        a, b = mat8x8[i], mat8x8[i + 1]
        out[i]     = [_blend(a, b, m) for m in MASKS]
        out[i + 1] = [_blend(b, a, m) for m in MASKS]  # 다음 행엔 a/b 뒤집기
    return out

# ────────────────────────────────────
# 전체 파이프라인
# ────────────────────────────────────
def preprocess_stream(src: bytes) -> np.ndarray:
    stage1_rows = _stage1(src)      # (N,8)  ── 슬라이딩 결과
    stage2_rows = _stage2(stage1_rows[:8])   # 앞 8 행만 사용
    return _stage3(stage2_rows)     # (8,4,8)

# ────────────────────────────────────
# 사용 예시
# ────────────────────────────────────
if __name__ == "__main__":
    # 0x00‥0xFF dummy 데이터
    dummy = bytes(range(256))
    result = preprocess_stream(dummy)

    print("shape :", result.shape)        # (8, 4, 8)
    print(result[0, 0])                   # 첫 행-첫 열 벡터
