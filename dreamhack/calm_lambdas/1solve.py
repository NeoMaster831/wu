from aa import REV

target = bytes.fromhex("""
F0 9F 97 87 F0 9F 95 83
F0 9F 95 B2 F0 9F 94 AB  F0 9F 94 A4 F0 9F 94 A8
F0 9F 94 8B F0 9F 96 8D  F0 9F 94 BE F0 9F 97 8A
F0 9F 94 8E F0 9F 95 8D  F0 9F 94 99 F0 9F 96 91
F0 9F 94 88 F0 9F 96 BD  F0 9F 95 91 F0 9F 95 B8
F0 9F 94 8F F0 9F 95 8F  F0 9F 96 8C F0 9F 96 8C
F0 9F 95 AD F0 9F 94 80  F0 9F 94 84 F0 9F 94 86
F0 9F 96 85 F0 9F 95 B5  F0 9F 96 92 F0 9F 96 8D
F0 9F 96 80 F0 9F 96 A9  F0 9F 96 B4 F0 9F 96 B4
F0 9F 94 B9 F0 9F 96 B8  F0 9F 96 BC F0 9F 95 86
F0 9F 96 9D F0 9F 96 84  F0 9F 94 A4 F0 9F 94 A0
F0 9F 96 AE F0 9F 94 AD  F0 9F 94 91 F0 9F 96 AE
F0 9F 94 A3 F0 9F 96 93  F0 9F 95 BE F0 9F 95 B0
F0 9F 95 BD F0 9F 94 85  F0 9F 94 93 F0 9F 96 8C
F0 9F 95 95 F0 9F 96 BA  F0 9F 95 98 F0 9F 97 8F
F0 9F 96 BF F0 9F 94 BA
""").decode("utf-8")

target = list(target)

assert(len(target) == 60)

print(target)

from ddd import get_c
from aaa import mapping, get_emoji_index_as_abcd, get_emoji, predict
import itertools

mapping_rev = { v: k for k, v in mapping.items() }

def predict_rev(target, C1, C2, C3, C4):

    target = target[::-1]

    tl = []
    for c in target:
        tl.append(get_emoji_index_as_abcd(c))
    
    Q = [a for a, _, _, _ in tl]
    W = [] + C1

    a1 = REV(Q, W, 2)

    Q = [b for _, b, _, _ in tl]
    W = [] + C2

    a2 = REV(Q, W, 3)
    
    
    Q = [c for _, _, c, _ in tl]
    W = [] + C3

    a3 = REV(Q, W, 5)

    Q = [d for _, _, _, d in tl]
    W = [] + C4

    a4 = REV(Q, W, 7)

    all_combs = list(itertools.product(a1, a2, a3, a4))
    print(len(all_combs))

    for comb in all_combs:
        rl = [(comb[0][i], comb[1][i], comb[2][i], comb[3][i]) for i in range(60)]
        rl = [ get_emoji(v[0], v[1], v[2], v[3]) for v in rl ]
        yield rl

def dfs(stage, tg):
    
    if stage == -1:
        return tg
    
    print("Stage:", stage)

    c1, c2, c3, c4 = get_c(stage)
    
    tg_ = [ mapping_rev[c] for c in tg ]
    
    for recovered in predict_rev(tg_, c1, c2, c3, c4):
        v = dfs(stage - 1, recovered)
        if v is not None:
            return v
    
    return None


if __name__ == "__main__":
    #print(dfs(7, target))
    print(''.join(['🖦', '🔐', '🗁', '🖿', '🕁', '🔟', '🖈', '🔫', '🔚', '🔀', '🕻', '🖯', '🕆', '🗎', '🕳', '🕿', '🕝', '🔿', '🔁', '🖀', '🕓', '🕝', '🖩', '🕟', '🔒', '🕍', '🖱', '🕩', '🖗', '🖇', '🔯', '🔁', '🖹', '🔯', '🕔', '🕳', '🖺', '🔆', '🔷', '🖰', '🕪', '🕒', '🔝', '🕙', '🗏', '🔄', '🖭', '🕪', '🖰', '🖦', '🕣', '🕻', '🔺', '🔩', '🔵', '🕀', '🔊', '🔂', '🔣', '🕐']))

