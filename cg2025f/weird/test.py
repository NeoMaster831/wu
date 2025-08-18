import subprocess
from tqdm import tqdm

for a in range(16):
    for b in tqdm(range(16)):
        for c in range(16):
            for d in range(16):
                payload = f'{a:01X}{b:01X}{c:01X}{d:01X}' + '0'*60

                result = subprocess.run(['sde64', '-skx', '--', './3asdf'], input=payload.encode(), capture_output=True)
                if result.returncode == 1:
                    print('asdf')
                    print(payload)
                    exit(0)