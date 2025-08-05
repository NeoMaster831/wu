target = b'73bbdca066fef716faaafe787e559bc4b1d7e4a5e4bccbcbc3184055ab5fd051'
#########b'73bbdca066fef716faaafe787e559bc4b1d7e4a5e4bccbcbc3184055ab5fd051'
helloworld = """aasaasaassaasssasaassaasssasaasssasaassaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaasssasaassaasssasaassaassaasssasaasssasaassaasssasaassaasssasaassaassaasssasaasssasaassaasssasaassaasssasaassaasssasaasssasaassaassaasssasaassaasssasaassaassaasssasaassaasssasaasssasaassaasssasaassaassaassaasssasaasssasaassaasssasaassaasssasaassaassaassaassaassaasssasaassaasssasaasssasaassaasssasaassaassaasssasaassaasssasaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaasssasaasssasaasssasaasssasaassaasssasaassaasssasaassaasssasaassaassaasssasaassaasssasaasssasaassaassaasssasaassaasssasaassaasssasaassaassaasssasaasssasaassaasssasaassaasssasaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaassaassaasssasaasssasaasssasaassaasssasaassaassaassaasssasaasssasaasssasaassaasssasaassaassaassaasssasaasssasaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaasssasaasssasaasssasaassaasssasaassaasssasaasssasaassaassaasssasaassaasssasaassaassaasssasaassaassaassaassaasssasaassaasssasaasssasaassaassaasssasaasssasaassaasssasaassaasssasaasssasaasssasaasssasaassaasssasaassaasssasaasssasaasssasaasssasaasssasaassaasssasaassaasssasaasssasaasssasaasssasaasssasaassaasssasaassaassaasssasaassaasssasaasssasaasssasaassaasssasaassaassaasssasaasssasaassaasssasaassaasssasaassaassaasssasaassaasssasaassaasssasaassaasssasaasssasaasssasaassaassaasssasaassaasssasaassaassaasssasaasssasaassaassaasssasaassaasssasaassaassaasssasaasssasaasssasaassaasssasaassaasssasaasssasaassaassaassaasssasaassaasssasaasssasaassaassaasssasaasssasaassaasssasaassaasssasaasssasaasssasaasssasaassaasssasaassaasssasaasssasaasssasaassaassaasssasaassaasssasaassaassaassaasssasaasssasaassaasssasaassaasssasaasssasaasssasaasssasaasssasaasssasaassaasssasaassaasssasaasssasaasssasaasssasaassaasssasaassaasssasaasssasaasssasaassaassaasssasaassaasssasaassaassaasssasaasssasaassaasssasaassaasssasaassaassaasssasaassaasssasaasssasaassaasssasaassaassaasssasaassaasssasaasssasaassaasssasaassaassaasssasaasssasaassaasssasaassaasssasaassaassaasssasaassaasssasaasssasaassaasssasaassaassaasssasaasssasaassaasssasaassaasssasaassaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaassaasssasaasssasaassaasssasaassaassaasssasaassaassaassaassaasssasaassaasssasaasssasaasssasaassaassaassaasssasaassaasssasaassaassaassaassaassaasssasaassaasssasaasssasaasssasaasssasaasssasaassaasssasaassaasssasaasssasaasssasaasssasaasssasaasssasaassaasssasaassaassaassaasssasaasssasaasssasaassaasssasaassaassaasssasaasssasaassaassaasssasaassaasssasaasssasaasssasaasssasaasssasaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaassaasssasaasssasaassaassaassaasssasaassaasssasaassaassaassaassaassaasssasaassaasssasaasssasaasssasaasssasaasssasaassaasssasaassaasssasaassaassaasssasaass"""
bits = [ 0 for _ in range(1000) ]

toggle_flag = False
io_flag = False
ptr = 3

res = 0
for l, i in enumerate(helloworld):
    if l == 19:
        print(ptr, toggle_flag, io_flag)
    if i == 'a':
        if ptr == 1:
            if io_flag:
                res += bits[2]
                res *= 2
                print(bits[2], hex(res), l)
                io_flag = False
            else:
                io_flag = True
        else:
            io_flag = False

        toggle_flag = True
        bits[ptr] = 1 - bits[ptr]

    elif i == 's':
        if toggle_flag:
            ptr -= 1
        else:
            ptr += 1
        toggle_flag = False

res //= 2

#print(bin(res))

from Crypto.Util.number import long_to_bytes

print(long_to_bytes(res))
from Crypto.Util.number import bytes_to_long

n = bytes_to_long(target)
n_bits = bin(n)[2:].rjust(len(target) * 8, '0')

print(n_bits)

payload = b'aasaas'

# Assume it is at 1, toggle flag is not set
def gat():
    ret = b's' # go right
    ret += b'as' # toggle and go back
    return ret

n_bits = "0" + n_bits
for i in range(1, len(n_bits)):
    if n_bits[i - 1] != n_bits[i]:
        payload += gat()
    payload += b'aass'

print(payload)