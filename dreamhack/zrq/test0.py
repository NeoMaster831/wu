from typing import List

def lzw_encode_codes(data: bytes) -> List[int]:
    if not data:
        return []
    dict_ = {bytes([i]): i for i in range(256)}
    next_code = 256
    out = []
    w = bytes([data[0]])
    for k in data[1:]:
        wk = w + bytes([k])
        if wk in dict_:
            w = wk
        else:
            out.append(dict_[w])
            dict_[wk] = next_code
            next_code += 1
            w = bytes([k])
    out.append(dict_[w])
    return out

def _perm_bytes(seed: int) -> bytes:
    a, c, m = 1103515245, 12345, 2**31
    x = seed & 0x7FFFFFFF
    keys = []
    for i in range(256):
        x = (a * x + c) % m
        keys.append((x, i))
    keys.sort()
    return bytes([i for _, i in keys])

def _gen_chunk_series(seed: int):
    base = _perm_bytes(seed)
    step = 37
    k = 0
    while True:
        rot = (k * step) & 0xFF
        chunk = bytes(((base[(i + rot) & 0xFF] ^ ((k * 0xA7) & 0xFF)) & 0xFF) for i in range(256))
        yield chunk
        k += 1

def make_buffer_with_n_tokens(N: int, seed: int = 2025) -> bytes:
    if N < 2:
        raise ValueError("N must be >= 2 (tail b'//' alone already yields 2 tokens).")

    tail = b"//"
    body = bytearray()
    chunks = _gen_chunk_series(seed)

    def toklen(prefix_len: int) -> int:
        return len(lzw_encode_codes(bytes(body[:prefix_len]) + tail))

    while toklen(len(body)) < N:
        body.extend(next(chunks))

    lo, hi = 0, len(body)
    while lo < hi:
        mid = (lo + hi) // 2
        if toklen(mid) >= N:
            hi = mid
        else:
            lo = mid + 1

    start = max(0, lo - 1024)
    i = start
    cur = toklen(i)
    while True:
        if cur == N:
            return bytes(body[:i] + tail)
        i += 1
        if i > len(body):
            body.extend(next(chunks))
        cur = toklen(i)

buf = make_buffer_with_n_tokens(35611, seed=83636)
codes = lzw_encode_codes(buf)
assert len(codes) == 35611
assert buf.endswith(b"//")

print(f"{codes = }")

with open('quiz_last', 'wb') as f:
    f.write(buf[:-2][::-1])