---
title: '强网杯 s9 2025 - ezran'
description: '利用 gift 中泄露的 bit 线性约束恢复 MT 初始状态，再逆出多次 shuffle 后的 flag。'
timeLabel: 2025
timeOrder: 2025
topic: 'RNG Attack'
competition: '强网杯 s9'
pubDate: 2026-03-11T16:45:00+08:00
---

阅读题目：

```python
from Crypto.Util.number import *
from random import *

f = open('flag.txt', 'r')
flag = f.read().encode()

gift=b''
for i in range(3108):
    r1 = getrandbits(8)
    r2 = getrandbits(16)
    x=(pow(r1, 2*i, 257) & 0xff) ^ r2
    c=long_to_bytes(x, 2)
    gift+=c

m = list(flag)
for i in range(2025):
    shuffle(m)

c = "".join(list(map(chr,m)))

f = open('output.txt', 'w')
f.write(f"gift = {bytes_to_long(gift)}\\n")
f.write(f"c = {c}\\n")
```

观察到题目生成了3180组c，之后队flag进行shuffle操作之后输出，显然我们尝试从gift中生成初始的state，一共624*32个bit

我们看看泄露出来的有多少个 bit。`pow(r1, 2*i, 257)` 最多可充当 8 个 bit 的掩码，假设我们直接取高位 8 个 bit，也就是 $8 \times 3108 = 24864$ 个 bit，看起来是可以的，但是我自己写脚本试了一下，这个时候只泄露了高位的信息，秩可能远小于维数，可能不存在解。所以我们要尽可能选择比较全面的 bit，注意到，在 $i \bmod 64 = 0$ 的时候，由二次剩余和欧拉定理可以推出此时泄露出了高 15 比特；在 $i \bmod 64 \ne 0$ 时，最少泄露出 8 bit。然后发现此时还是没有解，所以我们可以通过添加一些约束，如 $[1,0,\ldots]=[0]$，来缩小其解空间，这时候求出其解空间之后，我们需要遍历的大小也随之缩小。

恢复的逻辑大概是MT内部都是线性运算，我们令x为初始状态state，A是内部线性变换的矩阵，我们可以令上面泄露的bit为b，我们可以通过Ax=b来求出初始状态x。

那我们之后的问题就规约到如何去求A，A矩阵可以通过把初始状态state设置为单位向量，我们记录单位向量在我们进行getrandbits时，此时b'中泄露的位置就是A中相应的列。

整体的思路就是想办法要泄露足够多的bit，如果不满秩，尝试增加约束，减小解空间。

以下为完整解题代码：

```python
from Crypto.Util.number import *
from random import *
from tqdm import *
from sage.all import *
import os
import sys

gift = ...
c = ')9Lsu_4s_eb__otEli_nhe_tes5gii5sT@omamkn__ari{efm0__rmu_nt(0Eu3_En_og5rfoh}nkeoToy_bthguuEh7___u'

gift = long_to_bytes(gift)
RNG = Random()

def construct_a_row(RNG):
    row = []
    for i in range(len(gift) // 2):
        RNG.getrandbits(8)
        if i % 64 == 0:
            row += list(map(int, (bin(RNG.getrandbits(16) >> 1)[2:].zfill(15))))
        else:
            row += list(map(int, (bin(RNG.getrandbits(16) >> 8)[2:].zfill(8))))
    return row

L = []
for i in trange(19968):
    state = [0] * 624
    temp = "0" * i + "1" * 1 + "0" * (19968 - 1 - i)
    for j in range(624):
        state[j] = int(temp[32 * j:32 * j + 32], 2)
    RNG.setstate((3, tuple(state + [624]), None))
    L.append(construct_a_row(RNG))

L = Matrix(GF(2), L)

R = []
for i in trange(len(gift) // 2):
    if i % 64 == 0:
        R += list(
            map(
                int,
                (bin(bytes_to_long(gift[2 * i:2 * i + 2]) >> 1)[2:].zfill(15)),
            )
        )
    else:
        R += list(
            map(
                int,
                (bin(bytes_to_long(gift[2 * i:2 * i + 2]) >> 8)[2:].zfill(8)),
            )
        )
R = vector(GF(2), R)

L1 = L
R1 = R.list()
for _ in range(2, 32):
    L1 = L1.augment(vector(GF(2), [0] * (_ - 2 + 1) + [1] + [0] * (19968 - _)))
    R1.append(0)

s = L1.solve_left(vector(GF(2), R1))

init = "".join(list(map(str, s)))
state = []
for i in range(624):
    state.append(int(init[32 * i:32 * i + 32], 2))

RNG1 = Random()
RNG1.setstate((3, tuple(state + [624]), None))

######################################################### part2 set seed and recover shuffle
rank = L1.rank()
print("L 在 GF(2) 上的秩：", rank)
Ker = L1.left_kernel().basis()
from itertools import *

for i in product([0,1], repeat=6):
    si = vector(GF(2), i)*Matrix(GF(2), Ker) + s
    init = "".join(list(map(str,si)))
    state = []
    for i in range(624):
        state.append(int(init[32*i:32*i+32],2))
    RNG1 = Random()
    RNG1.setstate((3,tuple(state+[624]),None))
    c = ")9Lsu_4s_eb__otEli_nhe_tes5gii5sT@omamkn__ari{efm0__rmu_nt(0Eu3_En_og5rfoh}nkeoToy_bthguuEh7___u"

    ######################################################### part2 set seed and recover shuffle
    for i in range(3108):
        RNG1.getrandbits(8)
        RNG1.getrandbits(16)
    x = [i for i in range(len(c))]

    for i in range(2025):
        RNG1.shuffle(x)

    flag = ""
    for i in range(len(c)):
        flag += c[x.index(i)]
    if b"flag{" in flag.encode():
        print(flag)
```
