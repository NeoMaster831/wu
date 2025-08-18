f = [ i for i in range(1, 301) ]

import random
random.shuffle(f)

for i in f:
    print(i, end=' ')