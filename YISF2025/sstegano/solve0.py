with open('logo_v3.png', 'rb') as f:
    img_data = f.read()

# find IEND
iend = img_data.find(b'IEND')

truncated = img_data[iend+8:]

with open('truncated_logo_v3.wav', 'wb') as f:
    f.write(truncated)