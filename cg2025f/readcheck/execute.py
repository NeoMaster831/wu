getprocess = '''
from pwn import *
r = process('/home/ctf/server', shell=True)
'''

payload = bytes.fromhex(input('python code to execute (hex): ')).decode()

blacklist = ['server', 'home', 'ctf', 'open']
for word in blacklist:
    if word in payload:
        print('not permitted')
        exit()

open('/home/ctf/payload.py', 'w').write(getprocess + payload)

import subprocess
p = subprocess.Popen('python3 -u /home/ctf/payload.py', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

while p.poll() == None:
	out = p.stdout.readline()
	print(out.decode(), end='')