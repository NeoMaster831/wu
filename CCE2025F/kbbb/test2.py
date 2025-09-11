from base64 import b64decode

defencedata = b64decode("vpo+odMRqW7M4qsfiMpdbg==")
pngdata = b64decode("vJM5o5MCoifg0JC7LG75yg==")

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

flag_png_nonce = b"\\" * 12
defence_png_nonce = b"\xf8" * 12

a = b"flag.png" + flag_png_nonce
b = b"defence.png"

c = xor(pngdata, defencedata)

print(xor(c, a))
