import os

flag = b''

for root, dirs, files in os.walk("./container"):
    dirs.sort(reverse=True)
    files.sort(reverse=True)
    for file_name in files:
        file_path = os.path.join(root, file_name)
        with open(file_path, 'rb') as f:
            flag += b"".join(f.readlines())

import hashlib


with open('./container/flag.py', 'rb') as f:
    print(f.readlines())
sha256_hash = hashlib.sha256()

sha256_hash.update(flag)
hash_result = sha256_hash.hexdigest()

print(f"pokactf2024{{{hash_result}}}")