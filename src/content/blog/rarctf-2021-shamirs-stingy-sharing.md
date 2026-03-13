---
title: RaRCTF 2021 - Shamir's Stingy Sharing 题解
description: 把求值接口当成大整数进位系统来利用，直接从一次查询里得到 `poly[0]`，再复现随机流解密 flag。
timeLabel: 2021
timeOrder: 2021
topic: Secret Sharing
competition: RaRCTF
pubDate: 2026-03-08T17:14:00+08:00
---

题目的名字叫 `Shamir's Stingy Sharing`，源码会生成一个长度为 30 的 `poly` 数组，每个系数都是 128 bit 随机数。服务端先用 `poly[0]` 作为随机数种子生成 keystream，把 flag 做一次 `bxor` 后输出；然后只允许你提交一次整数 `x`，服务端返回 `sum(poly[i] * x^i)`。


```python
import random, sys
from crypto.util.number import long_to_bytes


def bxor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


bits = 128
shares = 30

poly = [random.getrandbits(bits) for _ in range(shares)]
flag = open('/challenge/flag.txt', 'rb').read()

random.seed(poly[0])
print(bxor(flag, long_to_bytes(random.getrandbits(len(flag) * 8))).hex())

try:
    x = int(input('Take a share... BUT ONLY ONE. '))
except:
    print('Do you know what an integer is?')
    sys.exit(1)
if abs(x) < 1:
    print('No.')
else:
    print(sum(map(lambda i: poly[i] * pow(x, i), range(len(poly)))))
```

在普通大整数上直接把多项式值打出来

因为一旦是在整数环里算，`x` 就不只是“取值点”，还可以被拿来当进位基数。那接下来要做的就不是恢复整条多项式，而是想办法把高次项全挤到高位去，让最低位只留下常数项

如果把多项式写成

$$
P(x)=a_0+a_1x+a_2x^2+\cdots+a_dx^d
$$

并且所有系数都小于 $2^{129}$，那么当我们取 $x=2^{129}$ 时有

$$
P(2^{129}) \equiv a_0 \pmod{2^{129}}
$$

因为所有 $i\ge 1$ 的项都至少带有一个 $2^{129}$ 因子。

## 知识补充

- [Positional notation - Wikipedia](https://en.wikipedia.org/wiki/Positional_notation)
- [Python random module documentation](https://docs.python.org/3/library/random.html)

## 解题思路

直接选 `x = 2^129` 去问一次值。由于每个系数都只有 128 bit，高次项都会被推到更高位，对结果取模 `2^129` 以后，剩下来的就只会是 `poly[0]`。

而题目最开始拿来异或 flag 的随机流正是用 `poly[0]` 做种子生成的，所以常数项一到手，随机流也就能完整复现。最后把密文和同长度 mask 异或一下，flag 就回来了。

```python
def recover_seed(query_once):
    x = 1 << 129
    return query_once(x) % x


def unmask_flag(ciphertext, seed):
    rng = random.Random(seed)
    mask = bytes(rng.getrandbits(8) for _ in range(len(ciphertext)))
    return bytes(c ^ m for c, m in zip(ciphertext, mask))
```

## 参考资料

- [CTFtime: Shamir's Stingy Sharing](https://ctftime.org/writeup/29892)
- [Qiita: RaRCTF writeup with Shamir's Stingy Sharing section](https://qiita.com/sathukin/items/dc4a6d04a0fdb04cc2f8)
- [CTFtime task page: Shamir's Stingy Sharing](https://ctftime.org/task/16995)
