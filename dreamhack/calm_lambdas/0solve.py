# 정연산

from aaa import predict_with_transform
from ddd import get_c

origin = "🕶🕶🖕🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🕶🖕🖕🖕🖕🖕"
for i in range(8):
    c1, c2, c3, c4 = get_c(i)
    origin = predict_with_transform(origin, c1, c2, c3, c4)

print(origin)