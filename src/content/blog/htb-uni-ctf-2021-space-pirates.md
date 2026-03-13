---
title: HTB Uni CTF 2021 Quals - Space Pirates 题解
description: 利用 MD5 链式生成系数的错误设计，在只给一个 share 的情况下直接恢复 secret 并解出 AES 密钥。
timeLabel: 2021
timeOrder: 2021
topic: Secret Sharing
competition: HTB Uni CTF Quals
pubDate: 2026-03-08T17:09:00+08:00
---

Jones and his crew have started a long journey to discover the legendary treasure ... We managed to get his last message, sent to his best friend. Could you help us decrypt it?

题目给了一段实现 Shamir secret sharing 的 Python 代码，以及一份 `msg.enc`。这份文件里只给出了一组 `(x, y)` share、一个 `coefficient`，以及用 AES-ECB 加密后的密文。目标是解出最后那段消息。

```python
from sympy import *
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randint, randbytes, seed

FLAG = b'HTB{dummyflag}'


class Shamir:
    def __init__(self, prime, k, n):
        self.p = prime
        self.secret = randint(1, self.p - 1)
        self.k = k
        self.n = n
        self.coeffs = [self.secret]
        self.x_vals = []
        self.y_vals = []

    def next_coeff(self, val):
        return int(md5(val.to_bytes(32, byteorder='big')).hexdigest(), 16)

    def calc_coeffs(self):
        for i in range(1, self.n + 1):
            self.coeffs.append(self.next_coeff(self.coeffs[i - 1]))

    def calc_y(self, x):
        y = 0
        for i, coeff in enumerate(self.coeffs):
            y += coeff * x ** i
        return y % self.p

    def create_pol(self):
        self.calc_coeffs()
        self.coeffs = self.coeffs[:self.k]
        for _ in range(self.n):
            x = randint(1, self.p - 1)
            self.x_vals.append(x)
            self.y_vals.append(self.calc_y(x))

    def get_share(self):
        return self.x_vals[0], self.y_vals[0]


def main():
    sss = Shamir(92434467187580489687, 10, 18)
    sss.create_pol()
    share = sss.get_share()
    seed(sss.secret)
    key = randbytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    enc_FLAG = cipher.encrypt(pad(FLAG, 16)).hex()
    print(sss.coeffs)

    f = open('msg.enc', 'w')
    f.write('share: ' + str(share) + '\n')
    f.write('coefficient: ' + str(sss.coeffs[1]) + '\n')
    f.write('secret message: ' + str(enc_FLAG) + '\n')
    f.close()


if __name__ == '__main__':
    main()
```

这题只给一组 share，按正常 Shamir 来看根本不够。真正该看的不是 share 数量，而是代码怎么生成系数。往下读很快就会发现，除了常数项 `secret` 之外，后面的系数根本不是随机取的，而是拿前一项一路 MD5 链下去。

因为第二个系数都已经给出来了，后面整条链其实都能顺着推完。也就是说，多项式里真正未知的只剩常数项一个量，而这偏偏可以用那一组 `(x, y)` 直接解出来。

题目的多项式其实是

$$
f(x)=s+a_1x+a_2x^2+\cdots+a_tx^t \pmod p
$$

而这些系数满足链式关系

$$
a_{i+1}=\mathrm{MD5}(a_i)
$$

因此在知道 $a_1$ 的情况下，可以先算出所有高次项，再用一组 share 直接恢复

$$
s \equiv y-\sum_{i\ge 1} a_i x^i \pmod p
$$

## 知识补充

- [Shamir's Secret Sharing - Wikipedia](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [Python random module documentation](https://docs.python.org/3/library/random.html)
- [MD5 - RFC 1321](https://www.rfc-editor.org/rfc/rfc1321)

## 解题思路

先拿题目给的 `a_1` 不断做 MD5，把后面所有高次项系数都复原出来。接着把这些已知项在给定的 `x` 上代进去，算出它们对 share 的贡献。真实的 `y` 减掉这部分，剩下来的就是 `secret`。

拿到 `secret` 后，后半段基本就是送分：题目用它去 `seed()` 了 Python 的随机数，再据此生成 AES key。那我们本地照着复现一遍随机流，AES key 自然就出来了，最后解密 `msg.enc` 就行。

```python
def derive_coeff_chain(a1, degree, p):
    coeffs = [a1]
    while len(coeffs) < degree:
        nxt = int(md5(str(coeffs[-1]).encode()).hexdigest(), 16) % p
        coeffs.append(nxt)
    return coeffs


def recover_secret(share, a1, degree, p):
    x, y = share
    coeffs = derive_coeff_chain(a1, degree, p)
    known_part = sum(coef * pow(x, idx + 1, p) for idx, coef in enumerate(coeffs)) % p
    return (y - known_part) % p
```

## 参考资料

- [Platypwnies writeup: Space Pirates](https://platypwnies.de/writeups/2021/htb-uni-quals/crypto/space-pirates/)
- [CTFtime writeup: Space Pirates](https://ctftime.org/writeup/31433)
- [Radboud Institute of Pwning writeup](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/spacepirates/)
