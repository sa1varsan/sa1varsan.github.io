---
title: zer0pts CTF 2020 - dirty laundry 题解
description: 从 `g = 1 + key * n` 的特殊结构入手恢复 PRNG 输出，剥掉 Paillier 随机项和 noise，再还原二次多项式常数项。
timeLabel: 2020
timeOrder: 2020
topic: Secret Sharing
competition: zer0pts CTF
pubDate: 2026-03-08T17:15:00+08:00
---

题目描述：Do you wanna air my dirty laundry?

附件里给了一份把 Shamir secret sharing 和 Paillier 混在一起的实现：先用一个二次多项式 `f(x) = secret + ax + bx^2 (mod PRIME)` 生成 5 份 share，再把每份 `f(x) + noise` 用不同的 Paillier 公钥加密后公开

```python
def make_shares(secret, k, shares, prime=PRIME):
    PR, x = PolynomialRing(GF(prime), name='x').objgen()
    f = PR([secret] + [ZZ.random_element(prime) for _ in range(k - 1)])
    xy = []
    pubkey = []
    for x in range(1, shares + 1):
        noise = prng.rand()
        n, g, y = paillier_enc(f(x) + noise, prime, noise)
        pubkey.append([n, g])
        xy.append([x, y])
    return pubkey, xy


def paillier_enc(m, p, noise):
    p = next_prime(p + noise)
    q = getStrongPrime(512)
    n = p * q
    g = (1 + prng.rand() * n) % n ** 2
    c = pow(g, m, n ** 2) * pow(prng.rand(), n, n ** 2) % n ** 2
    return n, g, c
```

Paillier 在题目的特殊生成方式下满足

$$
g = 1 + kn
$$

因此可以直接恢复

$$
k = \frac{g-1}{n}
$$

而密文在去掉随机项以后会近似落成

$$
c \equiv (1+kn)^m \equiv 1 + kmn \pmod{n^2}
$$

这就把原本的 Paillier 乘法结构压回了一阶线性关系。

先从每组公钥里的 `g` 直接算出对应的 `k = (g - 1) // n`，然后顺着这些连续输出去恢复 PRNG 状态。状态一旦拿到，Paillier 里用到的随机量和额外加的 noise 也就都能一起复原。

接着把密文里的随机项剥掉，再利用 `(1 + k * n)^m` 的展开把它压回一阶线性关系，最后就能拿回每个点的真实多项式值。到这一步题目又变回一个普通二次多项式，最后常数项就是 flag。

```python
def key_from_g(g, n):
    return (g - 1) // n


def linearized_plain(c, n, k, rn_inv):
    cleaned = (c * rn_inv) % (n * n)
    return ((cleaned - 1) // n) * pow(k, -1, n) % n
```

## 参考资料

- [CTFtime: dirty laundry writeup](https://ctftime.org/writeup/18677)
- [S3v3ru5: zer0pts CTF 2020 Dirty Laundry](https://s3v3ru5.github.io/notes/zer0ptsctf-2020-dirty-laundry/)
- [CTFtime task page: dirty laundry](https://ctftime.org/task/10647)
