---
title: Crypto CTF 2024 - Melek 题解
description: 先用拉格朗日插值恢复 Shamir 多项式常数项，再借助模平方根从 `m^e mod p` 还原明文。
timeLabel: 2024
timeOrder: 2024
topic: Secret Sharing
competition: Crypto CTF
pubDate: 2026-03-08T17:10:00+08:00
---


题目的提示语是：`Melek is a secret sharing scheme that may be relatively straightforward to break - what are your thoughts on the best way to approach it?` 给出的脚本会把 flag 转成整数 `m`，随机取素数 `p` 和指数 `e`，然后在 `GF(p)` 上构造一个多项式。这个多项式的常数项并不是 `m`，而是 `pow(m, e, p)`；题目最终只输出 `e`、`p` 和若干个点值 `PT = [(x_i, f(x_i))]`，目标是恢复 flag。


下面这段来自公开 writeup 引用的原题附件 `encrypt` 函数，本身就是题目生成实例时用的脚本：

```python
#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag


def encrypt(msg, nbit):
    m, p = bytes_to_long(msg), getPrime(nbit)
    assert m < p
    e, t = randint(1, p - 1), randint(1, nbit - 1)
    C = [randint(0, p - 1) for _ in range(t - 1)] + [pow(m, e, p)]
    R.<x> = GF(p)[]
    f = R(0)
    for i in range(t):
        f += x ** (t - i - 1) * C[i]
    P = [list(range(nbit))]
    shuffle(P)
    P = P[:t]
    PT = [(a, f(a)) for a in [randint(1, p - 1) for _ in range(t)]]
    return e, p, PT


nbit = 512
enc = encrypt(flag, nbit)
print(f'enc = {enc}')
```


这题第一眼其实很像普通 Shamir：给你若干个点，让你把多项式插回来。真动手算一算就会发现没那么老实，因为常数项不是明文 `m`，而是 `m^e mod p`。如果顺手按 RSA 的习惯去想，多半第一反应就是去找 `e^{-1} mod (p - 1)`，然后马上撞墙：这里根本没有这个逆元。

所以这题别一股脑往一个方向冲，得拆开看。前半截就是秘密共享恢复，后半截才是模指数和开方。先把 `f(0)` 拿出来，再考虑怎么把 `m^e` 拉回到 `m`，整题就顺很多了。

先用拉格朗日插值直接在 $x = 0$ 处求值：

$$
f(0)=\sum_i y_i\prod_{j\ne i}\frac{-x_j}{x_i-x_j}\pmod p
$$

恢复到常数项以后，我们拿到的是

$$
c \equiv m^e \pmod p
$$

由于 $\gcd(e, p-1)=2$，不能直接求 $e^{-1}$，但可以找一个指数 $d$ 满足

$$
ed \equiv 2 \pmod{p-1}
$$

于是有

$$
c^d \equiv m^2 \pmod p
$$

最后再对 $m^2$ 在模 $p$ 下开平方即可。

## 知识补充

- [Shamir's Secret Sharing - Wikipedia](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [Lagrange polynomial - Wikipedia](https://en.wikipedia.org/wiki/Lagrange_polynomial)
- [Tonelli-Shanks algorithm - Wikipedia](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm)

## 解题思路

做法其实很直接。先拿 `PT` 在 `x = 0` 处做拉格朗日插值，把常数项 `c = m^e mod p` 算出来。到这一步先别急着硬求指数逆，因为这里最关键的信息就是 `gcd(e, p - 1) = 2`，说明你最多只能先把它还原到平方。

于是换个想法，找一个指数 `d` 满足 `ed ≡ 2 (mod p - 1)`，这样就能从 `c` 算出 `m^2`。最后在模 `p` 下开平方，两个候选根再按 flag 格式筛一下，基本就结束了。

```python
def lagrange_at_zero(points, p):
    acc = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (-xj)) % p
            den = (den * (xi - xj)) % p
        acc = (acc + yi * num * pow(den, -1, p)) % p
    return acc


def recover_message(points, p, e):
    c = lagrange_at_zero(points, p)
    d = pow(e // 2, -1, (p - 1) // 2)
    m_sq = pow(c, d, p)
    roots = tonelli_shanks(m_sq, p)
    return next(root for root in roots if long_to_bytes(root).startswith(b'CCTF{'))
```

## 参考资料

- [CTFtime: Crypto CTF 2024 - Melek writeup](https://ctftime.org/writeup/39181)
- [CTFtime task page: Melek](https://ctftime.org/task/28526)
- [GitHub writeup and challenge files](https://github.com/ksaweryr/ctf-writeups/blob/master/2024/cryptoctf/Melek/README.md)
