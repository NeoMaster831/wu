BITS = None
from tqdm import tqdm

def pad(k):
    return f"{k:0{BITS}b}"
def bin_to_hex(st):
    return hex(int(st, 2))[2:]

def lzw_decode(tokens):
    if not tokens:
        return b""

    dict_ = {i: bytes([i]) for i in range(256)}
    out = bytearray()

    prev = dict_[tokens[0]]
    out += prev
    next_code = 256

    for code in tokens[1:]:
        if code in dict_:
            entry = dict_[code]
        elif code == next_code:            # KwKwK case
            entry = prev + prev[:1]
        else:
            raise ValueError(f"invalid code {code} with dict size {len(dict_)}")

        out += entry
        dict_[next_code] = prev + entry[:1]
        next_code += 1
        prev = entry

    return dict_, bytes(out)

def make_fastbin_or_smallbin_block(block):
    return [block[0]] + block[1:][::-1]

def make_unsortedbin_block(block):
    return block[::-1]


def recover_stage0(hex_str):

    hex_str = bytes.fromhex(hex_str).hex()
    ret = []
    for i in range(0, len(hex_str), BITS*2):
        if i + BITS*2 > len(hex_str):
            left = hex_str[i:]
            left_bin = bin(int(left, 16))[2:].zfill(len(left)*4)
            for j in range(0, len(left_bin), BITS):
                if j + BITS <= len(left_bin):
                    ret.append(int(left_bin[j:j+BITS], 2))
                    print(f"Partial: {left_bin[j:j+BITS]} -> {chr(int(left_bin[j:j+BITS], 2))}")
                else:
                    print(f"Leftover bits: {left_bin[j:]}, ignored")
            break
        hex_t_str = hex_str[i:i+BITS*2]
        b = bin(int(hex_t_str, 16))[2:].zfill(BITS * 8)
        ret += [int(b[i:i+BITS], 2) for i in range(0, BITS * 8, BITS)]
    print(len(ret))
    #print(''.join([zrqs[c].decode() for c in ret]))

    from pol import codes
    g_codes = codes[::-1]

    # Okay, let's rebase it
    # First, we rebase tcache first
    tcache_0 = ret[:7]
    
    assert(tcache_0 == g_codes[-7:])

    g_codes = g_codes[:-7]
    ret = ret[7:]

    #parse fastbins
    FASTBIN_SIZE = 176
    assert(FASTBIN_SIZE % 8 == 0)
    fastbin = []
    for i in range(0, FASTBIN_SIZE, 8):
        fastbin += make_fastbin_or_smallbin_block(ret[i:i+8])

    assert(fastbin == g_codes[:FASTBIN_SIZE])
    ret = ret[FASTBIN_SIZE:]
    g_codes = g_codes[FASTBIN_SIZE:]

    # Let's swap all of them to fastbin blocks
    ret_swapped = []
    for i in range(0, len(ret), 8):
        ret_swapped += make_fastbin_or_smallbin_block(ret[i:i+8])

    I = [459]
    for _ in range(1000):
        I += [470, 469, 469]
    
    total = tcache_0
    for index, i in enumerate(I[:74]):
        test = ret_swapped[:i]
        if test != g_codes[-i:]:
            raise ValueError(f"Mismatch at step {index}")
        total = test + total
        g_codes = g_codes[:-i]
        ret_swapped = ret_swapped[i:]

    
    j1 = ret_swapped[471-5:471]
    assert(j1 == g_codes[-5:])

    j2 = ret_swapped[:460]
    assert(j2 == g_codes[-9-460:-9])

    print(len(g_codes[:-9-460]))

    for i in range(-5, 0):
        g_codes[i] = None
    for i in range(-9-460, -9):
        g_codes[i] = None
    for i in range(471-5, 471):
        ret_swapped[i] = None
    for i in range(460):
        ret_swapped[i] = None

    idxmap = [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, 698, 699, 700, 701, 6, 7, None, None, None, None, None, 5, 14, 15, 0, 1, 2, 3, 4, 13, 22, 23, 8, 9, 10, 11, 12, 21, 30, 31, 16, 17, 18, 19, 20, 29, 38, 39, 24, 25, 26, 27, 28, 37, 46, 47, 32, 33, 34, 35, 36, 45, 54, 55, 40, 41, 42, 43, 44, 53, 62, 63, 48, 49, 50, 51, 52, 61, 70, 71, 56, 57, 58, 59, 60, 69, 78, 79, 64, 65, 66, 67, 68, 77, 86, 87, 72, 73, 74, 75, 76, 85, 94, 95, 80, 81, 82, 83, 84, 93, 102, 103, 88, 89, 90, 91, 92, 101, 110, 111, 96, 97, 98, 99, 100, 109, 118, 119, 104, 105, 106, 107, 108, 117, 126, 127, 112, 113, 114, 115, 116, 125, 134, 135, 120, 121, 122, 123, 124, 133, 142, 143, 128, 129, 130, 131, 132, 141, 150, 151, 136, 137, 138, 139, 140, 149, 158, 159, 144, 145, 146, 147, 148, 157, 166, 167, 152, 153, 154, 155, 156, 165, 174, 175, 160, 161, 162, 163, 164, 173, 182, 183, 168, 169, 170, 171, 172, 181, 190, 191, 176, 177, 178, 179, 180, 189, 198, 199, 184, 185, 186, 187, 188, 197, 206, 207, 192, 193, 194, 195, 196, 205, 214, 215, 200, 201, 202, 203, 204, 213, 222, 223, 208, 209, 210, 211, 212, 221, 230, 231, 216, 217, 218, 219, 220, 229, 236, 237, 224, 225, 226, 227, 228, 235, 232, 233, 234]
    tmp = [None] * 238 + j2 + [None] * 4 + j1

    for i in range(len(tmp)):
        if idxmap[i] is not None:
            tmp[idxmap[i]] = ret_swapped[i]
            g_codes[idxmap[i]] = None
            ret_swapped[i] = None
    print(ret_swapped)

    total = fastbin + tmp + total
    cnt = 0
    for a, b in zip(total, codes[::-1]):
        if a != b:
            cnt += 1
    
    print(f"{cnt}/35611")

    """
    counts = {}
    for c in ret_swapped:
        counts[c] = counts.get(c, 0) + 1

    idxmap = [None] * len(ret_swapped) # ret_swapped에서의 i가
    for k, v in counts.items():
        if v == 1:
            idxmap[ret_swapped.index(k)] = g_codes.index(k)
    
    #assert(g_codes[idxmap[-1]] == ret_swapped[-1])
    
    print(idxmap)
    """
    

    #print(counts)
    #print(ret_swapped)
    #print(g_codes)

if __name__ == '__main__':
    #with open('quiz.zrq.2', 'rb') as f:
    with open('qu.z.1', 'rb') as f:
        data = f.read()
    BITS = data[0]
    print("BITS:", BITS)

    recover_stage0(data[1:].hex())