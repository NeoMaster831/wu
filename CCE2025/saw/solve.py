from pwn import u32

with open("complex.saw", 'rb') as f:
    saw_data = f.read()

header = saw_data[:4]
assert header == b'SAW\x00'

w = u32(saw_data[4:8])
h = u32(saw_data[8:12])

print(f"Width: {w}, Height: {h}")

buf_total_length = u32(saw_data[12:16])

print(f"Total buffer length: {buf_total_length}")

block_count = u32(saw_data[16:20])