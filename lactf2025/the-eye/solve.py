import sys, time, ctypes
libc=ctypes.CDLL("libc.so.6")
libc.rand.restype=ctypes.c_int
libc.srand.argtypes=[ctypes.c_uint]
f=sys.stdin.readline().rstrip("\n")
n=len(f)
now=int(time.time())
for seed in range(now-60,now+61):
    libc.srand(seed)
    ops=[]
    for _ in range(22):
        for i in range(n-1,-1,-1):
            r=libc.rand()% (i+1)
            ops.append((i,r))
    a=list(f)
    for i,r in reversed(ops):
        a[i],a[r]=a[r],a[i]
    final = "".join(a)
    if "lactf" in final:
        print(seed, final)
        break
