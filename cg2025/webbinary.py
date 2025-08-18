def decode_custom_encoding(local_200):
    decoded = bytearray()
    i = 0
    
    while i < len(local_200):
        chunk = local_200[i:i+4]
        i += len(chunk)
        if len(chunk) < 4:
            if len(chunk) >= 1:
                b1 = (chunk[0] << 2) | ((chunk[1] & 0x30) >> 4 if len(chunk) > 1 else 0)
                decoded.append(b1)
            
            if len(chunk) >= 2:
                b2 = ((chunk[1] & 0x0F) << 4) | ((chunk[2] & 0x3C) >> 2 if len(chunk) > 2 else 0)
                decoded.append(b2)
            
            if len(chunk) >= 3:
                b3 = ((chunk[2] & 0x03) << 6) | (chunk[3] if len(chunk) > 3 else 0)
                decoded.append(b3)
        else:
            # 정상적인 4바이트 처리
            b1 = (chunk[0] << 2) | ((chunk[1] & 0x30) >> 4)
            b2 = ((chunk[1] & 0x0F) << 4) | ((chunk[2] & 0x3C) >> 2)
            b3 = ((chunk[2] & 0x03) << 6) | chunk[3]
            
            decoded.append(b1)
            decoded.append(b2)
            decoded.append(b3)
    
    return decoded

data = [
    0xd, 0x33, 0x00, 0x39, 0xe,0x3,0x1,0x23,0xd,0x16,
    0x4,0x32,0x19,0x13,0x08,0x31,0xe,0x13,0x5,0x21,0xc,0x16,0x11,0x24,0x0c,
    0x03,0x8,0x30,0x18,0x36,0x10,0x35,0x0c,0x23,0x1d,0x24,0x19,0x06,0x11,0x24,
    0x19,0x06,0x14
]
print(len(data))

def reverse_transform(local_200):
    return decode_custom_encoding(local_200)

print(reverse_transform(data))
