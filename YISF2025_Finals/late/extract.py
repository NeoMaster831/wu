with open('prob', 'rb') as f:
    content = f.read()


with open('compressed.gz', 'wb') as f:
    f.write(content[1003:1003+13420])