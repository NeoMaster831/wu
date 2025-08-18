import base64

with open('./plain.txt.base62', 'rb') as f:
    plain = f.read()

with open('./plain.txt.encode', 'rb') as f:
    cipher = f.read()

print(len(plain))
print(len(cipher))