from Crypto.Cipher import AES
import hashlib

n = int("""110790383562224253098510939599833933412428635357837953728395109179813960729182816107988681436513743812819358361106923862730885343138633519926798065820463768625037480979941578471147298188077046651038356798626165262785021225924385199218137272470067134655209051616396196905472279764342469817762560739073895016319""")
e = 3
c1 = int("""4610221918541732456982225818778964440222694135208177035261128329594842025185271874296613353670426002500580058027573""")
c2 = int("""36881775348333859655857806550231715522113954192783716553668510157805153166687553732032350748348907488640828368419875""")
enc_hex = """c7b357b8147b2c1aab85b8303a62019834a5e832cc16b52b598772734a90660562c881c06b74ca4cbea351e07c9e4435"""

def icbrt(n: int) -> int:
    if n < 0:
        raise ValueError("nonnegative only")
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            break
        x = y
    while (x + 1) * (x + 1) * (x + 1) <= n:
        x += 1
    while x * x * x > n:
        x -= 1
    return x


m1 = icbrt(c1)
assert m1 ** 3 == c1
m2 = icbrt(c2)
assert m2 ** 3 == c2 and m2 == 2 * m1 + 1
key = m1.to_bytes(16, "big")

aes_key = hashlib.sha256(key).digest()
cipher = AES.new(aes_key, AES.MODE_ECB)

ct = bytes.fromhex(enc_hex)
pt = cipher.decrypt(ct).rstrip(b"\x00")
print(pt.decode(errors="ignore"))
