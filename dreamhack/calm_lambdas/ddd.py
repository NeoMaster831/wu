
from strt2 import l
from bbb import get_emoji_index_as_abcd

def get_c(tries):
    al =  [ get_emoji_index_as_abcd(c) for c in l[tries] ]

    C1 = [a for a, _, _, _ in al]
    C2 = [b for _, b, _, _ in al]
    C3 = [c for _, _, c, _ in al]
    C4 = [d for _, _, _, d in al]

    return C1, C2, C3, C4

if __name__ == "__main__":
    print(get_c(0))
