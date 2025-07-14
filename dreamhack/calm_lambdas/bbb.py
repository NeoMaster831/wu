from pwn import *

elf = ELF("./deploy/main.exe")

emojis = []

# Get the address of the symbol
for i in range(35, 35 + 210):
    symbol_addr = elf.sym[f'camlDune__exe__Main.{i}']
    symbol_bytes = elf.read(symbol_addr, 4)
    emojis.append(symbol_bytes.decode('utf-8'))

def get_emoji(a, b, c, d):
    return emojis[(1 - a) * 105 + b * 35 + c * 7 + d]

def get_index(a, b, c, d):
    return (1 - a) * 105 + b * 35 + c * 7 + d

def get_emoji_index(k):
    return emojis.index(k)

def get_abcd(k):
    d = k % 7
    k //= 7
    c = k % 5
    k //= 5
    b = k % 3
    a = k // 3
    return 1 - a, b, c, d

def get_emoji_index_as_abcd(k):
    return get_abcd(get_emoji_index(k))

def fuck_carry(l: list, r):

    a = []
    k = [] + l + [0] * len(l)
    for i in range(len(k) - 1):
        k[i + 1] += k[i] // r
        a.append(k[i] % r)
    
    return a

def convert_to_int(l: list, r: int):
    return sum([l[i] * (r ** i) for i in range(len(l))])


if __name__ == "__main__":
    for i, v in enumerate(emojis):
        with open(f"input{i}", "w") as f:
            f.write(v * 60)
