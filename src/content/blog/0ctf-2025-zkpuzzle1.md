---
title: '0ctf 2025 - ZKpuzzle1'
description: '选 anomalous curve 绕开曲线约束后，把条件化成整数上的四立方和，再用标准恒等式拆出 witness。'
timeLabel: 2025
timeOrder: 2025
topic: 'Zero-Knowledge Cryptography'
competition: '0ctf'
pubDate: 2026-03-14T10:05:00+08:00
---

```python
from sage.all import EllipticCurve, Zmod, is_prime, randint, inverse_mod
from ast import literal_eval
from secret import flag

class proofSystem:
    def __init__(self, p1, p2):
        assert is_prime(p1) and is_prime(p2)
        assert p1.bit_length() == p2.bit_length() == 256
        self.E1 = EllipticCurve(Zmod(p1), [0, 137])
        self.E2 = EllipticCurve(Zmod(p2), [0, 137])

    def myrand(self, E1, E2):
        F = Zmod(E1.order())
        r = F.random_element()
        P = r * E2.gens()[0]
        x = P.x()
        return int(r * x) & (2**128 - 1)

    def verify(self, E, r, k, w):
        G = E.gens()[0]
        P = (r*k) * G
        Q = (w[0]**3 + w[1]**3 + w[2]**3 + w[3]**3) * inverse_mod(k**2, G.order()) * G
        return P.x() == Q.x()


def task():
    ROUND = 1000
    threshold = 999
    print("hello hello")
    p1, p2 = map(int, input("Enter two primes: ").split())

    proofsystem = proofSystem(p1, p2)
    print(f"You need to succese {threshold} times in {ROUND} rounds.")
    r = proofsystem.myrand(proofsystem.E1, proofsystem.E2)
    success = 0
    for _ in range(ROUND):
        k = proofsystem.myrand(proofsystem.E2, proofsystem.E1)
        w = literal_eval(input(f"Prove for {r}, this is your mask: {k}, now give me your witness: "))
        assert len(w) == 4
        assert max(wi.bit_length() for wi in w) < 200
        print("pass the bit check")
        if proofsystem.verify(proofsystem.E1, r, k, w) and proofsystem.verify(proofsystem.E2, r, k, w):
            print(f"Good!")
            success += 1
        r += 1


    if success > threshold:
        print("You are master of math!")
        print(flag)


if __name__ == "__main__":
    try:
        task()
    except Exception:
        exit()
```

## 题目解析

这题名字带 ZK，核心在曲线怎么选和四个 witness 怎么构造。最先要注意的是 `myrand()`：它会把 `r` 当成 `E1.order()` 上的元素，再去乘 `E2.gens()[0]`。如果两边的群结构对不上，`int(r * x)` 这里就会直接炸掉，所以先处理曲线约束。

最省事的做法是令 `p1 = p2 = p`，再找一条 anomalous curve 让 `#E(F_p) = p`。这样 `E1` 和 `E2` 实际上就是同一条曲线，两次 `verify()` 也退化成同一个模 `p` 的条件。原题看起来像是“同时过两条曲线”，真正做起来就是找四个小整数，让

$$
\sum_{i=0}^3 w_i^3 \equiv r k^3 \pmod p
$$

成立，而且每个 `w_i` 都小于 `2^200`。

## 解题思路

这里直接用标准恒等式

$$
(u+v)^3 + (u-v)^3 + (-u+w)^3 + (-u-w)^3 = 6u(v-w)(v+w).
$$

所以只要把目标改写成

$$
r k^3 + t p = 6u(v-w)(v+w)
$$

就能从整数分解里直接反推出一组四立方和。赛里常见的写法是从 `t = r k^3 mod p` 开始不断加 `p`，每次尝试把 `t / 6` 分解成三个大小比较均衡的因子，然后把它们塞回上面的恒等式里。只要因子分桶别太偏，`u,v,w` 的 bit 长度自然能压在 200 bit 以内。

最后再把这一组整数整体乘上 `k` 就行，因为验证式里本来就有 `inverse_mod(k^2, G.order())`，代回去后正好只剩下目标里的 `r k`。

## 解题脚本

下面这份脚本就是对应的核心版本：先固定一条 anomalous curve，再枚举 `t` 并做整数分解。

```python
from sage.all import *
from pwn import *
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import queue

# Optimal anomalous prime with smooth p-1
p = 57896044618658097711785492504344103875898860550630966617243435388673817800277
inv24 = inverse_mod(24, p)

SMALL_PRIMES = list(primes(100000))

def trial_divide(n):
    factors = []
    for pr in SMALL_PRIMES:
        if pr * pr > n:
            break
        while n % pr == 0:
            factors.append(pr)
            n //= pr
    return factors, n

def balance_factors(all_factors):
    all_factors.sort(reverse=True)
    buckets = [1, 1, 1]
    for f in all_factors:
        idx = min(range(3), key=lambda i: buckets[i].bit_length())
        buckets[idx] *= f
        if buckets[idx].bit_length() > 198:
            return None
    return tuple(buckets)

def try_factor_candidate(num):
    if num <= 0:
        return None
    factors, remainder = trial_divide(num)
    if remainder == 1:
        return factors
    if remainder.bit_length() <= 170:
        try:
            for fac, exp in factor(remainder, proof=False):
                if fac.bit_length() > 190:
                    return None
                factors.extend([fac] * exp)
            return factors
        except Exception:
            return None
    return None

def compute_witness_from_factors(factors):
    if factors is None:
        return None
    buckets = balance_factors(factors)
    if buckets is None:
        return None
    a, b, c = buckets
    w = (a + b + c, a - b - c, -a + b - c, -a - b + c)
    if all(abs(wi).bit_length() < 200 for wi in w):
        return w
    return None

def get_witness_fast(r, k, max_l=3000):
    base_pos = (r * pow(k, 3, p) * inv24) % p
    base_neg = ((-r % p) * pow(k, 3, p) * inv24) % p
    for l in range(max_l):
        for base in [base_pos, base_neg]:
            num = base + l * p
            w = compute_witness_from_factors(try_factor_candidate(num))
            if w is not None:
                return w
    return None

def main():
    io = remote("instance.penguin.0ops.sjtu.cn", 18529)
    io.recvuntil(b"two primes: ")
    io.sendline(f"{p} {p}".encode())
    for _ in range(1000):
        line = io.recvuntil(b"witness: ").decode()
        r = int(line.split("Prove for ")[1].split(",")[0])
        k = int(line.split("mask: ")[1].split(",")[0])
        io.sendline(str(get_witness_fast(r, k)).encode())
    io.interactive()

if __name__ == "__main__":
    main()
```

## 参考资料

- [题目归档 ZKpuzzle1](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/0CTF/2025/crypto/ZKpuzzle1)
- [补充题解](https://rechn0.github.io/2025/12/22/2025-0ctf/)
