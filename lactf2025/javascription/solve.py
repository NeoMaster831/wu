import base64
import urllib.parse

def decode_final(final: str) -> str:
    step4 = base64.b64decode(final).decode('utf-8')
    step3 = urllib.parse.unquote(step4)
    step2 = step3.replace("[OLD_DATA]", "Z")
    step1 = step2[::-1]
    flag = base64.b64decode(step1).decode('utf-8')
    return flag

target = "JTNEJTNEUWZsSlglNUJPTERfREFUQSU1RG85MWNzeFdZMzlWZXNwbmVwSjMlNUJPTERfREFUQSU1RGY5bWI3JTVCT0xEX0RBVEElNURHZGpGR2I="
recovered_flag = decode_final(target)
print(recovered_flag)
