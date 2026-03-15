---
title: '0ctf 2025 - ZKpuzzle3'
description: '把四立方和重新参数化成二元对角二次型，用 `BinaryQF` 在整数上直接找 witness。'
timeLabel: 2025
timeOrder: 2025
topic: 'Zero-Knowledge Cryptography'
competition: '0ctf'
pubDate: 2026-03-14T10:25:00+08:00
---

```python
from sage.all import EllipticCurve, Zmod, is_prime, randint, inverse_mod
from ast import literal_eval
from secret import flag
import signal, sys

def handler(signum, frame):
    sys.exit(1)


class proofSystem:
    def __init__(self, p1, p2):
        assert is_prime(p1) and is_prime(p2)
        assert p1.bit_length() == p2.bit_length() == 256 and p1 != p2
        self.E1 = EllipticCurve(Zmod(p1), [0, 137])
        self.E2 = EllipticCurve(Zmod(p2), [0, 137])

    def myrand(self, E1, E2):
        F = Zmod(E1.order())
        r = F.random_element()
        P = r * E2.gens()[0]
        x = P.x()
        return int(r * x) & (2**128 - 1)

    def verify(self, E, r, k, w):
        assert len(w) == 4 and type(w) == list
        assert max(wi.bit_length() for wi in w) < 260
        G = E.gens()[0]
        P = (r*k) * G
        Q = (w[0]**3 + w[1]**3 + w[2]**3 + w[3]**3) * inverse_mod(k**2, G.order()) * G
        return P.x() == Q.x() and (int(w[0])**3 + int(w[1])**3 + int(w[2])**3 + int(w[3])**3) == int(k)**3*int(r)


def task():
    ROUND = 1000
    threshold = 940
    print("hello hello")
    p1, p2 = map(int, input("Enter two primes: ").split())

    proofsystem = proofSystem(p1, p2)
    print("N0n3 passes by and decides to steal some rounds. :D")
    ROUND = ROUND - bin(p1).count("1") - bin(p2).count("1")
    print(f"You need to succese {threshold} times in {ROUND} rounds.")
    r = min(proofsystem.myrand(proofsystem.E1, proofsystem.E2), proofsystem.myrand(proofsystem.E2, proofsystem.E1))
    success = 0
    for _ in range(ROUND):
        k = 1 # let's make situation simple! :P
        w = literal_eval(input(f"Prove for {r}, this is your mask: {k}, now give me your witness: "))
        if proofsystem.verify(proofsystem.E1, r, k, w) and proofsystem.verify(proofsystem.E2, r, k, w):
            print(f"Good!")
            success += 1
        r += 1

    if success > threshold:
        print("You are master of math!")
        print(flag)


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(90)
    try:
        task()
    except Exception:
        exit()
```

## 题目解析

第三阶段把 `k` 固定成了 `1`，而且检查也从模方程变成了精确整数等式：四个 witness 的立方和必须真的等于 `r`。曲线部分依旧还是 Stage 2 那套 2-cycle 约束，所以这题的实质已经完全变成整数上的四立方和。

这里直接把四立方和重新参数化，写成

$$
r = (u+x)^3 + (-x)^3 + (v+y)^3 + (-y)^3
$$

这个拆法，因为它展开后可以自然压成一个二元对角二次型。

## 解题思路

把上式展开，再令

$$
A = 2x + u, \qquad B = 2y + v,
$$

就能得到

$$
\frac{4r - u^3 - v^3}{3} = u A^2 + v B^2.
$$

这已经是标准的 diagonal binary quadratic form。直接固定 `u = 1`，再枚举一个不大的 `v`，把目标

$$
t = \frac{4r - 1 - v^3}{3}
$$

交给 `BinaryQF(1, 0, v).solve_integer(t)` 去解。如果找到 `(A, B)`，再检查 `A` 和 `v - B` 的奇偶性，就能反推出

$$
x = \frac{A - 1}{2}, \qquad y = \frac{B - v}{2},
$$

最后把 witness 还原成

$$
[1 + x,\ -x,\ v + y,\ -y].
$$

## 解题脚本

下面这份 Sage 脚本就是对应的核心版本：

```python
from sage.all import *

def solve_one(r, limit=20000):
    r = ZZ(r)
    for v in range(1, limit):
        t = 4 * r - 1 - v**3
        if t % 3:
            continue
        try:
            A, B = BinaryQF(1, 0, v).solve_integer(t // 3)
        except Exception:
            continue

        if A % 2 != 1:
            continue
        if (B - v) % 2:
            continue

        x = (A - 1) // 2
        y = (B - v) // 2
        w = [1 + x, -x, v + y, -y]

        if max(abs(ZZ(wi)).nbits() for wi in w) >= 260:
            continue
        if sum(ZZ(wi)**3 for wi in w) == r:
            return w

    raise ValueError("witness not found")

if __name__ == "__main__":
    for r in [12345678901234567890, 98765432109876543210]:
        print(r, solve_one(r))
```

## 参考资料

- [题目归档 ZKpuzzle3](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/0CTF/2025/crypto/ZKpuzzle3)
- [补充题解](https://rechn0.github.io/2025/12/22/2025-0ctf/)
