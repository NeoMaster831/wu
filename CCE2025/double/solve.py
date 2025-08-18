from Crypto.Cipher import AES

def rc4(key: bytes, data: bytes) -> bytes:
    if not key:
        raise ValueError("key must be non-empty")
    S = list(range(256))
    j = 0
    for i in range(256):                      # KSA
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:                            # PRGA
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        out.append(b ^ k)
    return bytes(out)

rc4_key = bytes.fromhex("8F 1B C3 47 D2 9A 6E 55  0F A8 34 21 7C E9 12 BD")
aes_key = bytes.fromhex("2B 7E 15 16  28 AE D2 A6 AB F7 15 88 09 CF 4F 3C 76 2E 7E 15  16 28 AE D2 A6 AB F7 15 88 09 CF 4F")

aes = AES.new(aes_key, AES.MODE_ECB)

with open("output.txt.bak", 'r') as f:
    data = bytes.fromhex(f.read().strip())
    
flag = aes.decrypt(data)
flag = rc4(rc4_key, flag)

print(flag)