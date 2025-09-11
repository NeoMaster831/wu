from hashlib import sha256
import sys
sys.setrecursionlimit(999999)

def build_except_key_header(basename: str, body_nonce: bytes):
    basename_sha = sha256(basename.encode()).digest()
    bodynonce_sha = sha256(body_nonce).digest()
    return basename_sha + bodynonce_sha

def build(basename: str, header_nonce: bytes, body_nonce: bytes, key: bytes):
    return build_except_key_header(basename, body_nonce) + header_nonce + key

def recover_m_by_modgcd(c1, c2, K, e, N, n_primes=20, bits=31):
    roots, mods = [], []
    used = 0
    while used < n_primes:
        p = next_prime(ZZ.random_element(2**(bits-1), 2**bits))
        if gcd(p, N) != 1 or gcd(e, p) == 0:
            continue
        Fp = GF(p); R.<X> = PolynomialRing(Fp)
        f = X**e - Fp(c1); g = (X + Fp(K))**e - Fp(c2)
        d = f.gcd(g)
        if d.degree() != 1:
            continue
        mp = (-d.monic()[0]) % p
        roots.append(mp); mods.append(p)
        used += 1
    m = crt(roots, mods) % N
    # 검증
    if pow(m, e, N) != c1 % N: raise ValueError("fail v1")
    if pow((m + K) % N, e, N) != c2 % N: raise ValueError("fail v2")
    return ZZ(m)

if __name__ == "__main__":

    from Crypto.Util.number import bytes_to_long, long_to_bytes
    
    flag_png_nonce = b"\\" * 12
    defence_png_nonce = b"\xf8" * 12

    N = bytes.fromhex("d7dd82fdc6921c455c92033bb6f51045afe2ba908c3c13c643b7bc87f96135dbe9a97c364ad5a82e47a1556860f170147a6f9f9fdaf4f308fc6bccf57a7d86582b2794c19c90839c3cfcbe75edbc57e7125e378ccce1d6c320e6983361fd6cb1e5ae78520384979dca7461c7b2574153d9ff4bdb47e60bbe9728b9d51c491a69")
    N = bytes_to_long(N)
    e = 65537

    with open('defence.png.CCE2025', 'rb') as f:
        c1 = bytes_to_long(f.read()[-0x80:])
    with open('flag.png.CCE2025', 'rb') as f:
        c2 = bytes_to_long(f.read()[-0x80:])

    R.<X> = PolynomialRing(Zmod(N))

    A = bytes_to_long(build_except_key_header("defence.png", defence_png_nonce))
    B = bytes_to_long(build_except_key_header("flag.png", flag_png_nonce))
    K = ((B - A) * 2**(8 * (32 + 12))) % N

    g1 = X^e - c1
    g2 = (X + K)^e - c2
    while g2 != 0:
        g1, g2 = g2, g1 % g2
        print(g2.degree())
    
    flag = ZZ(-g1.monic()[0])

    print(long_to_bytes(flag))