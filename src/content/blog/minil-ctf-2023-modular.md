---
title: 'MiniL CTF 2023 - Modular'
description: '通过 BKZ 规约恢复 shared_secret，再按常规流程解出 AES 密钥。'
timeLabel: 2023
timeOrder: 2023
topic: 'Lattice Cryptanalysis'
competition: 'MiniL CTF'
pubDate: 2026-03-11T16:45:00+08:00
---

## Modular

比较简单的题目

```
from data import t,h,p
m = len(t)
s = Matrix(ZZ, m+3 ,m+2)
for i in range(m):
    s[i, i] = p
    s[-3, i] = t[i]
    s[-2,i] = h[i]
    s[-1,i] = h[i]*t[i]

s[-2,-2] = 1
s[-1,-1] = 2**2048
s = s.BKZ(block_size = 10)
k = 0
for i in range(m+3):
    v = s[i]
    if v[-1] == 2**2048:
        s = v[-2]

print(bytes_to_long(sha256(long_to_bytes(s)).digest()[:16]))
```

得到 shared_secret，直接 AES 正常解密即可。
