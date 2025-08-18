#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
current_error → embedded files 복구 스크립트
 - 1) Protobuf-like framing 파싱: [0x0A][varint len][message...]
      내부 메시지: field 1 = 파일명(string), field 2 = 데이터(bytes/base64)
 - 2) 폴백: 파일 전체에서 큰 base64 블록을 찾아 추가 복구
사용법:
    python recover_all.py current_error out_dir
"""
import argparse
import base64
import re
from pathlib import Path
from typing import Iterator, Tuple, Optional

# ---- Utilities ----------------------------------------------------------------

def read_varint(buf: memoryview, i: int) -> Tuple[int, int]:
    """LEB128 varint 읽기. (value, new_index) 반환."""
    shift = 0
    val = 0
    n = len(buf)
    while i < n:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if b < 0x80:
            return val, i
        shift += 7
        if shift > 63:  # sanity
            raise ValueError("varint too long")
    raise ValueError("truncated varint")

def is_likely_base64(b: bytes) -> bool:
    """텍스트가 base64로 보이는지 간단히 판별."""
    if not b:
        return False
    # ASCII 비율이 매우 높고 허용 문자만 포함되는지
    if not re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", b):
        return False
    # 길이 조건 (대충)
    if len(b) < 40:
        return False
    return True

MAGIC_TO_EXT = [
    (b"\xFF\xD8\xFF", ".jpg"),
    (b"\x89PNG\r\n\x1A\n", ".png"),
    (b"%PDF-", ".pdf"),
    (b"PK\x03\x04", ".zip"),
    (b"7z\xBC\xAF\x27\x1C", ".7z"),
    (b"\x1F\x8B", ".gz"),
]

def guess_ext(blob: bytes, default: str = ".bin") -> str:
    for sig, ext in MAGIC_TO_EXT:
        if blob.startswith(sig):
            return ext
    return default

def safe_filename(name: str) -> str:
    # OS-독립 안전화
    name = name.replace("\\", "_").replace("/", "_").strip()
    if not name:
        name = "unnamed"
    return name

# ---- Protobuf-like parser ------------------------------------------------------

def parse_embedded_files(data: bytes) -> Iterator[Tuple[str, bytes]]:
    """
    파일 전체에서, field key 0x0A (길이 구분)으로 감싼
    '중첩 메시지'를 찾아 (name, payload) 튜플을 yield.
    내부 메시지 포맷:
      0x0A <varint len> <filename bytes>
      0x12 <varint len> <payload bytes or base64 text>
    다른 필드는 무시.
    """
    buf = memoryview(data)
    i, n = 0, len(buf)
    while i < n:
        if buf[i] != 0x0A:  # field 1, wire-type 2 (length-delimited)
            i += 1
            continue
        i += 1
        try:
            msg_len, i2 = read_varint(buf, i)
        except Exception:
            i += 1
            continue
        j = i2
        k = j + msg_len
        if k > n:
            i = i2
            continue
        # 내부 메시지 파싱
        name: Optional[str] = None
        payload: Optional[bytes] = None
        p = j
        while p < k:
            key = buf[p]; p += 1
            wt = key & 0x07
            if wt == 0:  # varint
                try:
                    _, p = read_varint(buf, p)
                except Exception:
                    break
            elif wt == 2:  # length-delimited
                try:
                    l, p2 = read_varint(buf, p)
                except Exception:
                    break
                q = p2 + l
                if q > k:
                    break
                field_no = key >> 3
                field_bytes = bytes(buf[p2:q])
                if field_no == 1:  # name
                    try:
                        name = field_bytes.decode("utf-8", errors="replace")
                    except Exception:
                        name = "unnamed"
                elif field_no == 2:  # payload
                    payload = field_bytes
                # skip
                p = q
            else:
                # 다른 wire type은 스킵 불가 → 중단
                break

        if name is not None and payload is not None:
            yield (name, payload)

        i = k

# ---- Fallback: carve large base64 blobs ---------------------------------------

def carve_large_base64(data: bytes, min_chars: int = 200) -> Iterator[Tuple[int, bytes]]:
    """
    파일 전체에서 긴 base64 덩어리를 찾아 (offset, decoded_bytes)를 yield.
    """
    b64_re = re.compile(rb"(?:[A-Za-z0-9+/]{40,}={0,2})", re.DOTALL)
    for m in b64_re.finditer(data):
        s = m.group(0)
        if len(s) < min_chars:
            continue
        # 패딩 보정
        pad = (-len(s)) % 4
        s_padded = s + b"=" * pad
        try:
            blob = base64.b64decode(s_padded, validate=False)
        except Exception:
            continue
        if len(blob) < 64:
            continue
        yield (m.start(), blob)

# ---- Main ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Recover embedded files from current_error")
    ap.add_argument("input", type=Path, help="input file (e.g., current_error)")
    ap.add_argument("outdir", type=Path, help="output directory")
    ap.add_argument("--no-fallback", action="store_true", help="skip global base64 carving")
    args = ap.parse_args()

    data = args.input.read_bytes()
    args.outdir.mkdir(parents=True, exist_ok=True)

    recovered = []
    # 1) Protobuf-like parse
    for name, payload in parse_embedded_files(data):
        name = safe_filename(name)
        raw = payload
        # payload가 base64로 보이면 디코드 시도
        if is_likely_base64(payload):
            try:
                raw = base64.b64decode(payload, validate=False)
            except Exception:
                raw = payload  # 실패 시 원본 저장

        # 확장자 보정: 이름에 확장자가 없거나 '.bin'이면 매직으로 추정
        out_name = name
        if "." not in out_name:
            out_name += guess_ext(raw)
        out_path = args.outdir / out_name
        # 중복 처리
        stem, suf = out_path.stem, out_path.suffix
        c = 1
        while out_path.exists():
            out_path = args.outdir / f"{stem}_{c}{suf}"
            c += 1
        out_path.write_bytes(raw)
        recovered.append(out_path.name)

    # 2) Fallback: carve large base64 blobs across whole file
    carved = []
    if not args.no_fallback:
        seen_hashes = set()
        for off, blob in carve_large_base64(data):
            ext = guess_ext(blob)
            name = f"carved_{off:08x}{ext}"
            out_path = args.outdir / name
            # 중복 방지(내용 기준)
            h = (len(blob), blob[:16])
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            out_path.write_bytes(blob)
            carved.append(out_path.name)

    # 결과 출력
    print("[*] Recovered (protobuf):")
    for n in recovered:
        print("   -", n)
    if not args.no_fallback:
        print("[*] Carved (fallback base64):")
        for n in carved:
            print("   -", n)
    print(f"[*] Done. Output dir: {args.outdir.resolve()}")

if __name__ == "__main__":
    main()
