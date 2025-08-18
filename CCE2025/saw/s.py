# saw_decode.py
import struct
from typing import Tuple

ORDER_CLUSTER_TO_RASTER = [4, 0, 1, 6, 2, 5, 7, 3]  # 네가 확인한 8바이트 순서 보정

def read_le32(b, off):
    return struct.unpack_from("<I", b, off)[0], off + 4

def decode_type2(body: bytes) -> bytes:
    """
    관찰 기반:
      [u32? 혹은 u8?] N-ish, 다음에 0x01, <seed:1>, <mask:m>
    실제 파일들에선 u32 대신 u8처럼 붙던 케이스가 있어 유연 처리.
    mask 길이 m는 남은 길이-2 로 추정. 최종 길이 = m*8 바이트,
    각 비트가 seed(1)/0(0) 을 의미.
    """
    off = 0
    # N(길이) 표기가 파일마다 1바이트/4바이트로 섞여 보여서 너그럽게 처리
    if len(body) >= 5:
        n32 = struct.unpack_from("<I", body, 0)[0]
        # 4바이트 쓰였으면 그 다음 바이트는 0x01일 가능성 높음
        if len(body) >= 6 and body[4] in (1,):
            off = 4
        else:
            # 1바이트로만 쓴 케이스
            n32 = body[0]
            off = 1
    else:
        n32 = body[0]
        off = 1

    if off >= len(body):
        raise ValueError("type=2: malformed (no seed header)")
    # seed 헤더
    # 보통 0x01, <seed>
    count = body[off]; off += 1
    if count != 1:
        raise ValueError("type=2: unexpected seed-count (expected 1)")

    seed = body[off]; off += 1
    mask = body[off:]
    m = len(mask)
    total = m * 8
    out = bytearray(total)
    pos = 0
    for byte in mask:
        for bit in range(7, -1, -1):
            out[pos] = seed if ((byte >> bit) & 1) else 0x00
            pos += 1
            if pos == total:
                break
        if pos == total:
            break
    # 일부 파일에서 total이 실제 필요한 바이트보다 많을 수 있으니 트리밍
    return bytes(out)

def lz_like_decode(stream: bytes, expect_len: int) -> bytes:
    """
    관찰 기반 간이 LZ:
      - 0xFF 0x00  : 리터럴 0xFF
      - 0xFF d l   : 직전 out에서 distance=d, length=l 만큼 복사
      - 0x00 x / 0x01 x : 리터럴 x  (덤프들에서 빈번)
      - 그 외 바이트  : 리터럴로 그대로
    expect_len 만큼 복호화되면 종료.
    """
    out = bytearray()
    i = 0
    while i < len(stream) and (expect_len <= 0 or len(out) < expect_len):
        b = stream[i]; i += 1
        if b == 0xFF:
            if i >= len(stream):
                break
            d = stream[i]; i += 1
            if d == 0x00:
                out.append(0xFF)
            else:
                if i >= len(stream):
                    break
                l = stream[i]; i += 1
                if d == 0 or l == 0:
                    continue
                for _ in range(l):
                    if d > len(out):
                        # 방어
                        out.append(0)
                    else:
                        out.append(out[-d])
        elif b in (0x00, 0x01):
            if i >= len(stream):
                break
            out.append(stream[i]); i += 1
        else:
            out.append(b)
    return bytes(out if expect_len <= 0 else out[:expect_len])

def decode_body(body: bytes) -> bytes:
    """
    바디 첫 4바이트 = 타입. (2 / 5 / 0x17 등)
    - type=2 : seed+mask
    - type=5/0x17 : 첫 바이트를 목표 길이로 가정 후 LZ 복호
    """
    if len(body) < 4:
        raise ValueError("body too short")
    typ = struct.unpack_from("<I", body, 0)[0]
    payload = body[4:]

    if typ == 2:
        return decode_type2(payload)

    # 0x05, 0x17 등: 첫 바이트를 목표 길이로 가정
    if not payload:
        return b""
    expect_len = payload[0]
    lz = payload[1:]
    return lz_like_decode(lz, expect_len)

def decode_saw(data: bytes, reorder_to_raster: bool = False) -> Tuple[bytes, int, int]:
    if len(data) < 16 or data[:4] != b"SAW\x00":
        raise ValueError("not a SAW file")
    w, h, _ = struct.unpack_from("<III", data, 4)
    body = data[16:]
    raw = decode_body(body)

    # 특정 8바이트만 필요하면 그대로, 또는 네가 말한 순서 보정
    if reorder_to_raster and len(raw) >= 8:
        raw8 = raw[:8]
        raw8 = bytes(raw8[i] for i in ORDER_CLUSTER_TO_RASTER)
        return raw8, w, h
    return raw, w, h

if __name__ == "__main__":
    import sys, binascii
    if len(sys.argv) < 2:
        print("usage: python saw_decode.py <file.saw> [--raster]")
        sys.exit(1)
    buf = open(sys.argv[1], "rb").read()
    reorder = ("--raster" in sys.argv)
    out, w, h = decode_saw(buf, reorder_to_raster=reorder)
    print((out, w, h))
    print("hex:", binascii.hexlify(out).decode())
