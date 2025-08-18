ALPHA = "6TUPHY14S509CFOLKMXGUAZBJDEINQRVW"  # byte_805DD0F의 32글자
TABLE = {ch:i for i,ch in enumerate(ALPHA)}

def b32_custom_decode(s):
    s = s.strip().rstrip("=")
    bitbuf = 0
    bits = 0
    out = bytearray()
    for ch in s:
        val = TABLE[ch]
        bitbuf = (bitbuf << 5) | val
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((bitbuf >> bits) & 0xFF)
    return bytes(out)

print(b32_custom_decode("LYUZKJITFAM1SQ9GCAD41DK=").decode(errors="ignore"))
