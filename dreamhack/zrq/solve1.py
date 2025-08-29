with open('quiz4.zrq.3', 'rb') as f:
    data = f.read()

with open('quiz4.zrq.1', 'wb') as f:
    f.write(data[:0x75757])