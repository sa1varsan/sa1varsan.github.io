---
title: SCTF-XCTF 2020 - Lattice 题解
description: 题目本质是标准的 NTRU lattice attack，构造 `2n x 2n` 格基后用 LLL 直接把私钥候选规约出来。
timeLabel: 2020
timeOrder: 2020
topic: Lattice Cryptanalysis
competition: SCTF-XCTF
pubDate: 2026-03-08T17:20:00+08:00
---

题目直接给了典型的 NTRU 风格参数，在多项式环上的公开参数 `h`、密文多项式 `e`，以及 `n = 109, q = 2048, p = 3`。目标是恢复私钥并解出明文。

后出题组在官方仓库的 write-up 里提到本来想考另一条格攻击路线，但最后因为前测失误，直接套前一篇文章里的 NTRU attack 就能过。

SCTF 官方仓库里其实公开了题目附件目录

```python
from base64 import b16encode

Zx.<x> = ZZ[]

n = 109
q = 2048
p = 3
Df = 9
Dg = 10
Dr = 11


def mul(f, g):
    return (f * g) % (x ^ n - 1)


def bal_mod(f, q):
    g = list(((f[i] + q // 2) % q) - q // 2 for i in range(n))
    return Zx(g)


def random_poly(d):
    assert d <= n
    result = n * [0]
    for j in range(d):
        while True:
            r = randrange(n)
            if not result[r]:
                break
        result[r] = 1 - 2 * randrange(2)
    return Zx(result)


def keygen():
    f = random_poly(Df)
    while True:
        try:
            fp = inv_mod_prime(f, p)
            fq = inv_mod_powerof2(f, q)
            break
        except:
            f = random_poly(Df)
    g = random_poly(Dg)
    h = bal_mod(p * mul(fq, g), q)
    pub_key = h
    pri_key = [f, fp]
    return pub_key, pri_key


def encrypt(m, h):
    r = random_poly(Dr)
    e = bal_mod(mul(h, r) + m, q)
    return e


if __name__ == '__main__':
    pub_key, pri_key = keygen()
    flag = b'SCTF{***********}'[5:-1]
    m = Zx(list(bin(int(b16encode(flag), 16))[2:]))
    print(m)
    e = encrypt(m, pub_key)
    print('pub_key=')
    print(pub_key)
    print('e=')
    print(e)
```

标准 NTRU lattice attack

本题的难点在于把环上的关系写成格

NTRU 的公开键关系可以写成

$$
f \cdot h \equiv g \pmod q
$$

把它改写成整数关系，就是

$$
f \cdot h = g + kq
$$

于是 $(f, g)$ 会作为一条短向量落到 NTRU lattice 中，LLL 的目标就是把这条短向量规约出来。

## 知识补充

- [NTRUEncrypt - Wikipedia](https://en.wikipedia.org/wiki/NTRUEncrypt)
- [LatticeHacks: NTRU](https://latticehacks.cr.yp.to/ntru.html)

## 解题思路

先根据公开键把对应的循环卷积矩阵搭出来，拼成标准的 NTRU lattice basis。然后直接 LLL，盯着规约后的短向量找一个能在模 `p` 下可逆的候选 `f`。

一旦这个私钥候选成立，后面就完全按标准 NTRU 解密公式走：乘密文、做平衡化约简、再乘模 `p` 的逆元得到消息。整体上属于非常标准的格题。

```python
def build_ntru_basis(h_circ, q):
    n = h_circ.nrows()
    return block_matrix([
        [identity_matrix(ZZ, n), h_circ],
        [zero_matrix(ZZ, n, n), q * identity_matrix(ZZ, n)],
    ])


def recover_private_vector(reduced_basis):
    for row in reduced_basis.rows():
        f = balanced_poly(vector(row[: row.length() // 2]))
        if is_invertible_mod_p(f):
            return f
    raise ValueError('short vector not found')
```

## 参考资料

- [SCTF-XCTF official write-up repository](https://github.com/SycloverSecurity/SCTF2020/blob/master/Crypto/Lattice/Write-up/README.md)
- [CTFtime: SCTF-XCTF 2020 - Lattice](https://ctftime.org/writeup/22161)
- [LatticeHacks: NTRU](https://latticehacks.cr.yp.to/ntru.html)
