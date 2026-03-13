---
title: 'MiniL CTF 2023 - Curvesignin_Revenge'
description: '把群阶分解后用 Pohlig-Hellman、BSGS 和 CRT 求离散对数，恢复 DH 私钥。'
timeLabel: 2023
timeOrder: 2023
topic: 'Elliptic Curve Cryptography'
competition: 'MiniL CTF'
pubDate: 2026-03-11T16:45:00+08:00
---

## Curvesignin_Revenge

一眼 DH，所以大方向比较清晰：寻找私钥。

解题思路：N, e 比较小，简单认为是 DLP 就行。（~~废话~~）

很容易观察到这是一个 cyclic group，群的阶为 $N+1$，生成元是 $G$。由于 $N+1$ 是一个光滑数，所以我们考虑 Pohlig-Hellman、BSGS 和 CRT 的组合。若预先对 $N+1$ 分解，时间复杂度非常小，约等于：

$$
O\left(\sqrt{\max(p_1,\ldots,p_k)}\right)
$$

```
from sage.rings import integer_ring
Z = integer_ring.ZZ
def bsgs_alg(a, b, bounds):

    identity = Point(x = 1 , y = 0)
    lb, ub = bounds
    if lb < 0 or ub < lb:
        raise ValueError("bsgs() requires 0<=lb<=ub")

    ran = 1 + ub - lb   # the length of the interval
    # c = op(inverse(b), multiple(a, lb, operation=operation))
    c = add(mul(b , N), mul(a , lb))

    if ran < 30:    # use simple search for small ranges
        d = c
        for i0 in range(ran):
            i = lb + i0
            if d == identity:        # identity == b^(-1)*a^i, so return i
                return Z(i)
            d = add(a, d)
        raise ValueError("No solution in bsgs()")

    m = ran.isqrt() + 1  # we need sqrt(ran) rounded up
    table = dict()       # will hold pairs (a^(lb+i),lb+i) for i in range(m)

    d = c
    for i0 in xsrange(m):
        i = lb + i0
        if d == identity:        # identity == b^(-1)*a^i, so return i
            return Z(i)
        table[d] = i
        d = add(d, a)

    c = add(c, mul(d , N))     # this is now a**(-m)
    d = identity
    for i in xsrange(m):
        j = table.get(d)
        if j is not None:  # then d == b*a**(-i*m) == a**j
            return Z(i * m + j)
        d = add(c, d)

    raise ValueError("Log of %s to the base %s does not exist in %s." % (b, a, bounds))

def discrete_log_new(a, base = G, ord=N + 1):
    try:
        f = factor(ord)
        f = list(f)
        # print(f)
        l = [0] * len(f)
        for i, (pi, ri) in enumerate(f):
            for j in range(ri):
                c = bsgs_alg(mul(base , (ord // pi)),
                            mul((add(a ,  mul(base , l[i]*N))) , (ord // pi**(j + 1))),
                            (0, pi))
                l[i] += c * (pi**j)
        from sage.arith.all import CRT_list
        return CRT_list(l, [pi**ri for pi, ri in f])
    except ValueError:
        raise ValueError("No discrete log of %s found to base %s" % (a, base))

bsk = discrete_log_new(Bob , G , N+1)
print(bsk)
```

得到 Bob 的私钥，按 DH 协议得到共享密钥，AES 正常解密即可（脚本小子）。
