with open('quiz4.zrq', 'rb') as f:
    data = f.read()

assert(len(data) % 21 == 0)
data_resembled = [None] * len(data)
cnt = 0
i = -5
while i != 16:
    i += 5
    i %= 21

    for j in range(i, len(data), 21):
        data_resembled[j] = (data[cnt], None)#(data[cnt], True if cnt >= lost_index else False) # (?, lost)
        cnt += 1

print(f"{data_resembled = }")
with open('quiz4.zrq.3', 'wb') as f:
    f.write(b''.join([bytes([d[0]]) for d in data_resembled]))