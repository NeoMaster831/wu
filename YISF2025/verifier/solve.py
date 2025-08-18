serial = "312a-91ac-41ca-5132"
unk_2139_hex = "ACF51C3EE7F41B6D"
unk_2139 = bytes.fromhex(unk_2139_hex)

def blocks_to_v3_little_endian(blocks):
    vals = [int.from_bytes(b.encode('ascii'), 'little') for b in blocks]
    return sum(vals) & 0xFFFFFFFF

def recover_name(unk_2139: bytes, serial: str):
    blocks = serial.split('-')
    v3 = blocks_to_v3_little_endian(blocks)
    key4 = v3.to_bytes(4, 'little')
    name_bytes = bytes(unk_2139[i] ^ key4[i % 4] for i in range(8))
    return name_bytes

name = recover_name(unk_2139, serial)
print(name.hex())
print(name.decode('ascii', errors='replace'))
