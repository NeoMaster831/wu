key_table = b"aZ8bY7cX6dW5eV4fU3gT2hS1iR0jQ9kP8lO7mN6nM5oL4pK3jI2qH1rG_F-E+D_C@B_A"

key = [None] * 16
for i in range(16):
    key[i] = key_table[(7 * i + 13) % len(key_table)]
key = bytes(key)
iv = [ b ^ 0xae for b in bytes(b"YISF" * 4)]
iv = bytes(iv)

print("Key:", key)
print("IV:", iv)

from Crypto.Cipher import AES

cipher = AES.new(key, AES.MODE_CBC, iv)

with open('firmware.bin.enc', 'rb') as f:
    encrypted_data = f.read()

decrypted_data = cipher.decrypt(encrypted_data)
with open('firmware.bin', 'wb') as f:
    f.write(decrypted_data)