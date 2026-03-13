---
title: 'MiniL CTF 2023 - Sums'
description: '从 MHK 背包系统的解密方式反推参数，再用 orthogonal lattice 和 Groebner basis 求等价密钥。'
timeLabel: 2023
timeOrder: 2023
topic: 'Knapsack Cryptography'
competition: 'MiniL CTF'
pubDate: 2026-03-11T16:45:00+08:00
---

我最开始揪着背包格硬解。哪怕我算出来背包密度大于 1，几乎没有解的可能，但我还是坚持认为重点在于格子的构造，以及后面 BKZ 的调参。

我觉得 Oracle 学长给我放水了，可能因为已经到赛后了。Oracle 学长直接否定了我的想法，我后面开始关注解密方式，并找到了这个加密系统的论文。于是这道题最后对我而言就是一道论文题，链接都放下面：

- [MHK](https://ieeexplore.ieee.org/document/6530389)
- [MHK2](https://ieeexplore.ieee.org/document/6979893)

然后在这里锤一下两位学长，让我 Sums 的做题感受极其不好：为啥给我那么多 hint，就差帮我写代码了……（~~我就有嘴说，没胆做~~，所以两位学长大人有大量……）

根据论文可知解密如下：

$$
m = e^{-1}c \bmod p
$$

接下来是如何求解 e。

注意到加密函数中：

$$
\vec{a} = e\vec{s} \bmod p
$$

即：

$$
\vec{a} = e\vec{s} + p\vec{k}
$$

但 $e,p,\vec{s}$ 都未知，怎么攻击？Oracle 学长给了提示，我找到了相应攻击方法：

- [Equivalent key attack](https://ietresearch.onlinelibrary.wiley.com/doi/pdfdirect/10.1049/iet-ifs.2018.0041?download=true)

大概思路是根据 LLL（格子构造在论文里写得很清楚），按 Algorithm 1 找到 $\vec{a}$ 的 orthogonal lattice，也就是论文里说的 $\mathcal{L}^{\perp}(a)$。

论文里推到的式子（此处略）不再照搬原文排版；我仅把你原来用的 `div` 居中 HTML 块替换成更稳的 LaTeX/Markdown 表达，避免渲染问题。

> small tips：论文里提到，$\mathcal{L}^{\perp}(a)$ 中至少存在一个向量不符合上面情况。但受 Oracle 学长 bbs 的启发，我把最后一个去了（~~我猜的~~），结果是好的，感觉有运气成分。
> 

后面的推导、Groebner basis、以及脚本保持不变（仅对排版做语法修复）。

```
from sage.all import *
import ast
def find_ortho_zz(*vecs):
    assert len(set(len(v) for v in vecs)) == 1
    L = block_matrix(ZZ, [[matrix(vecs).T, matrix.identity(len(vecs[0]))]])
    print("LLL", L.dimensions())
    nv = len(vecs)
    L[:, :nv] *= 2**256
    L = L.LLL()
    ret = []
    for row in L:
        if row[:nv] == 0:
            ret.append(row[nv:])
    return matrix(ret)

def find_key(a):
    # a=e*s+p*k
    t1 = find_ortho_zz(a)
    assert t1 * vector(a) == 0
    # we assume that only t1[-1]*s!=0 and t1[-1]*k!=0
    # so the t1[:-1] is orthogonal to s and k
    # therefore s, k are spanned by u1, u2
    u1, u2 = find_ortho_zz(*t1[:-1])
    # suppose s=x1*u1+x2*u2, k=y1*u1+y2*u2
    # a=e*s+p*k=e*(x1*u1+x2*u2)+p*(y1*u1+y2*u2)
    #          =(e*x1+p*y1)*u1+(e*x2+p*y2)*u2
    #          =         v1*u1+         v2*u2
    v1, v2 = matrix([u1, u2]).solve_left(vector(a))
    print(f"{v1 = } {v2 = }")

    for det in [1, -1]:
        R = QQ["x1s, x2s, y1s, y2s, es, ps"]
        x1s, x2s, y1s, y2s, es, ps = R.gens()
        f1, f2 = matrix([[x1s, y1s], [x2s, y2s]]) * vector([es, ps]) - vector([v1, v2])
        f3 = x1s * y2s - x2s * y1s - det
        f4 = sum(x1s * u1 + x2s * u2) + 2 - ps
        gb = R.ideal([f1, f2, f3, f4]).groebner_basis()
        mul = reduce(lcm, [c.denom() for c, _ in gb[1]])
        eq = gb[1].resultant(f4, ps) * mul
        print(eq)
        L = matrix(
            QQ,
            [
                [eq.constant_coefficient(), 1, 0, 0],
                [eq.coefficient({x1s: 1}), 0, 1, 0],
                [eq.coefficient({x2s: 1}), 0, 0, 1],
            ],
        )
        bounds = [1, 1, 2**66, 2**66]
        scale = [2**128 // x for x in bounds]
        Q = diagonal_matrix(scale)
        L *= Q
        L = L.LLL()
        L /= Q
        for row in L:
            if row[1] < 0:
                row = -row
            if row[0] == 0 and row[1] == 1:
                x1, x2 = row[2:]
                s = (x1 * u1 + x2 * u2).change_ring(ZZ)
                p = sum(s) + 2
                e_cand1 = a[0] * pow(s[0], -1, p) % p
                e_cand2 = a[1] * pow(s[1], -1, p) % p
                if e_cand1 == e_cand2:
                    return s, e_cand1, p

s, e, p = find_key(a)

def decrypt_bit(c):
    M = pow(e, -1, p) * c % p
    return M % 2

def decrypt(c):
    plaintext_bin = ""
    for j in c:
        plaintext_bin += str(decrypt_bit(j))

    split_bin = [plaintext_bin[i : i + 7] for i in range(0, len(plaintext_bin), 8)]

    plaintext = ""
    for seq in split_bin:
        plaintext += chr(int(seq, 2))
    return plaintext

print(decrypt(c))
```

但很遗憾，并没有真正靠自己想出最后的答案，而是借助了别人的思路。虽然看起来是解出来了，但真高兴不起来，一点都不过瘾（感觉 hint 太多啦）。我觉得 Sums 值得花更多时间研究一下，算是对 orthogonal lattice 的一个入门。之后要学的东西还很多。

总之是一次不总是愉快、偶尔坐牢、但感触很深的 CTF（~~胆大包天把 MiniL 当 CTF 入门了~~）。
