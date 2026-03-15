---
title: '0ctf 2025 - ZKpuzzle2'
description: '先选满足 2-cycle 的两条曲线，再把四立方和约束拆到 mod p 和 mod q 两边分别求解后拼起来。'
timeLabel: 2025
timeOrder: 2025
topic: 'Zero-Knowledge Cryptography'
competition: '0ctf'
pubDate: 2026-03-14T10:15:00+08:00
---

```python
from sage.all import EllipticCurve, Zmod, is_prime, randint, inverse_mod
from ast import literal_eval
from secret import flag


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
        assert max(wi.bit_length() for wi in w) < 400
        G = E.gens()[0]
        P = (r*k) * G
        Q = (w[0]**3 + w[1]**3 + w[2]**3 + w[3]**3) * inverse_mod(k**2, G.order()) * G
        return P.x() == Q.x()


def task():
    ROUND = 1000
    threshold = 940
    print("hello hello")
    p1, p2 = map(int, input("Enter two primes: ").split())

    proofsystem = proofSystem(p1, p2)
    print("N0n3 passes by and decides to steal some rounds. :D")
    ROUND = ROUND - bin(p1).count("1") - bin(p2).count("1")
    print(f"You need to succese {threshold} times in {ROUND} rounds.")
    r = proofsystem.myrand(proofsystem.E1, proofsystem.E2)
    success = 0
    for _ in range(ROUND):
        k = proofsystem.myrand(proofsystem.E2, proofsystem.E1)
        w = literal_eval(input(f"Prove for {r}, this is your mask: {k}, now give me your witness: "))
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

第二阶段把 `p1 = p2` 这条路堵上了，代码明确要求 `p1 != p2`，而且总轮数还会被 `bin(p1).count("1") + bin(p2).count("1")` 扣掉。所以这题的关键先变成了选一对真正能跑通 `myrand()` 的曲线：既要满足 `E1.order() = p2`、`E2.order() = p1`，又要让两边的汉明重量尽量小。

这正是 2-cycle curves 的定义。这里直接用 Zcash Pasta 曲线生成器给出的一组 256 位素数 `p, q`，它们既满足 `E_i.p = E_{2-i}.order`，又足够 NTT-friendly，拿来做这题正合适。

## 解题思路

Stage 1 的整数分解做法这里就不方便了，因为目标已经变成 512 bit 量级的 `r k^3 + t p q`。但这次 bit 限制放宽到了 `2^400`，反而给了一个更直接的拆法。用恒等式

$$
(u+a)^3 + (-u)^3 = (3u^2 + 3ua + a^2)a
$$

可知只要令 `a = t p`，左边就在模 `p` 下自动消掉。于是可以把目标分成两半：

$$
(u+t p)^3 + (-u)^3 \equiv r k^3 \pmod q,
$$

$$
(v+s q)^3 + (-v)^3 \equiv r k^3 \pmod p.
$$

这样只要在 `F_q` 里解一个三次方程得到 `u`，再在 `F_p` 里解一个三次方程得到 `v`，最后把四个数拼成

$$
[u+t p,\ -u,\ v+s q,\ -v]
$$

就能同时通过模 `p` 和模 `q` 的检查，而且四个数的规模仍然只有 256 bit 左右。

## 解题脚本

```python
from sage.all import *
from pwn import *
import ast, tqdm

def attack(r, k, p, q):
    x = GF(q)["x"].gen()
    targ = int(r * pow(k, 3, q) % q)
    for t in range(1000):
        f = (x + t * p)**3 + (-x)**3 - targ
        ans = f.roots()
        if ans:
            u = int(ans[0][0])
            return [u + t * p, -u]

p = 0b1100000000110000000000110000000000000000000000000000000000000000000000000000000000000000000000000000000000011000000000110000000000010000100000010000000000000000000000100000100000000000000000001000001000010000000000001100000000001000000000000000000000000001
q = 0b1100000000110000000000110000000000000000000000000000000000000000000000000000000000000000000000000000000000011000000000110000000110010000101100010000000000000000000000100000100000000000000000000100000100010000000000001100000000000100000110000000000000000001

io = process(["python", "task.py"])
io.sendlineafter(b"Enter two primes: ", f"{p} {q}".encode())
io.recvuntil(b"You need to succese 940 times in ")
ROUND = ast.literal_eval(io.recvuntil(b" ").strip().decode())

for _ in tqdm.trange(ROUND):
    io.recvuntil(b"Prove for ")
    r = ast.literal_eval(io.recvuntil(b",").strip().decode()[:-1])
    io.recvuntil(b"this is your mask: ")
    k = ast.literal_eval(io.recvuntil(b",").strip().decode()[:-1])
    ws = attack(r, k, p, q) + attack(r, k, q, p)
    io.sendlineafter(b"witness: ", str(ws).encode())

io.interactive()
```

## 参考资料

- [题目归档 ZKpuzzle2](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/0CTF/2025/crypto/ZKpuzzle2)
- [补充题解](https://rechn0.github.io/2025/12/22/2025-0ctf/)
- [另一份 solve](https://github.com/vinsoc-cyber/Writeups-0CTF-2025/tree/main/crypto/zkpuzzle2/solve)
