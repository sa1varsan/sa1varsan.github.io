---
title: '强网杯 s9 2025 - blurred'
description: '先在 x=-1 处区分 NTRU 样本和随机样本，再用 gf2bv 预测 MT19937 并解密。'
timeLabel: 2025
timeOrder: 2025
topic: 'Post-Quantum Cryptography'
competition: '强网杯 s9'
pubDate: 2026-03-11T16:45:00+08:00
---

观察这个题目，发现这个题目解题思路大概分为两步：第一步进行随机数预测。随机数预测就需要我们对随机 bit 和 NTRU 的公钥进行区分。

有 20259 次交互机会。对于每次交互：

- 若选择 `2`：通过 `random.getrandbits` 生成密钥来加密 flag 并发出。
- 若选择 `1`：常见套路是能规约出 ((f_2,g_1))，但这里的 (g_1=1031) 太大，在有限时间内很难规约出目标向量；且这样只能用到生成样本 ((pk_1,pk_2)) 中的一个多项式，所以需要换方法。

我们利用对任意正奇数 $k$ 有：

$x^{\ell}+1=(x+1)\left[\sum_{i=0}^{k-1}(-1)^i x^i\right].$

因为我们不需要恢复 $f_2$，只要区分伪造样本是否来自 `GenNTRU` 还是随机样本，所以只考虑在

$$
R = (\mathbb{Z}/q\mathbb{Z})[x]/(x^\ell+1)
$$

上进行区分。

我们知道在

在 $R = (\mathbb{Z}/q\mathbb{Z})[x]/(x^\ell+1)$ 中，$x=-1$ 是多项式 $x^n+1$ 的一个根，因此存在 evaluation homomorphism：

$$
\phi:R\to \mathbb{Z}_q,\qquad [P(x)]\mapsto P(-1)\bmod q
$$

也就是说，环上的等式

$g_1(x)\equiv f(x)h_1(x)\pmod{(x^n+1,q)}$

在 $x=-1$ 处降维为整数环上的等式：

$$g_1(-1)\equiv f(-1)h_1(-1)\pmod q.$$

同理对 (g_2) 成立。于是：

$$
\begin{aligned}
g_1 &= h_1 f_2, \\
g_2 &= h_2 f_2
\end{aligned}
\Longrightarrow
\begin{aligned}
g_1(-1) &\equiv h_1(-1)f_2(-1)\pmod q, \\
g_2(-1) &\equiv h_2(-1)f_2(-1)\pmod q.
\end{aligned}
$$

再看 `sample(prandom)` 产生的系数在 $\{0, \pm 1\}$，所以 $f, g_1, g_2$ 的系数都极小，因此：

$|f(-1)|,\ |g_1(-1)|,\ |g_2(-1)|\le n=1031.$

更重要的是，按中心极限定理，实际大小一般只有 $O(\sqrt{n})$（大概几十量级）；而随机情况下三坐标近似是随机模 $q$ 的，长度是 $O(q)$ 量级（约 $10^6$）。此时格子里最短向量的典型长度约 $\approx q \sim 10^6$，远大于 100。所以我们对比规约出来的小向量的范数 `norm`，以 100 为界。

根据上述可以构造矩阵：

$B= \begin{pmatrix} 1 & h_1(-1) & h_2(-1) \\ 0 & q & 0 \\ 0 & 0 & q\end{pmatrix}.$

区分出来之后直接用 `gf2bv` 进行随机数预测（MT19937）。注意：打 MT19937 时，使用 `gf2bv` 会存在 `mt[0]` 高位取 0 与 1 的分支问题，因此要两次尝试。

```python
from sage.all import *
from pwn import *
from tqdm import trange
from gf2bv import LinearSystem
from gf2bv.crypto.mt import MT19937
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

q = 1342261
n = 1031
PR = PolynomialRing(Zmod(q), "x")
x = PR.gens()[0]
Q = PR.quotient(x**n + 1)

sh = process(["python", "server.py"])

bits = []
for i in trange(19968):
    sh.sendlineafter(b"c :", b"1")
    res = sh.recvline().strip().decode().split(":")[-1]

    start1 = res.find("[")
    end1 = res.find("]")
    h1 = Q(eval(res[start1:end1 + 1]))

    start2 = res.find("[", end1)
    end2 = res.find("]", end1 + 1)
    h2 = Q(eval(res[start2:end2 + 1]))

    h1_value = h1.lift()(-1)
    h2_value = h2.lift()(-1)

    L = Matrix(ZZ, [
        [1, h1_value, h2_value],
        [0, -q, 0],
        [0, 0, -q]
    ])

    line = L.LLL()[0]
    if int(line.norm()) < 100:
        bits.append(0)
    else:
        bits.append(1)

sh.sendlineafter(b"c :", b"2")
sh.recvuntil(b"Flag: ")
enc_flag = eval(sh.recvline().strip())
print(f"enc_flag = {enc_flag}")
print(f"bits = {bits}")

def mt19937(out, ch):
    hig = [int(0x00000000), int(0x80000000)]
    lin = LinearSystem([32] * 624)
    mt = lin.gens()

    rng = MT19937(mt)
    zeros = []
    for o in out:
        zeros.append(rng.getrandbits(1) ^ int(o))
    zeros.append(mt[0] ^ hig[ch])

    for sol in lin.solve_all(zeros):
        rng = MT19937(sol)
        pyrand = rng.to_python_random()
        RNG = pyrand

        STATE = RNG.getstate()[1][:-1]
        STATE = STATE + (len(STATE),)
        RNG.setstate((3, STATE, None))

        for i in trange(19968):
            RNG.getrandbits(1)

        SHA = SHA256.new()
        SHA.update(str(RNG.getrandbits(256)).encode())
        KEY = SHA.digest()

        cipher = AES.new(KEY, AES.MODE_ECB)
        flag = cipher.decrypt(enc_flag)
        if b"flag" in flag:
            print(f"high = {ch}")
            print(f"{flag = }")

RNG = mt19937(bits, 0)
RNG = mt19937(bits, 1)
```
