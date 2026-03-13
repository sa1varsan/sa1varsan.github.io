---
title: CryptoHack - Beatboxer 题解思路
description: 根据官方题面和题目所在的 Linear Cryptanalysis 分类，把 Beatboxer 识别成一题针对 AES 风格 SPN 的线性分析题。
timeLabel: 2023
timeOrder: 2023
topic: Classical Cryptanalysis
competition: CryptoHack
pubDate: 2026-03-08T17:06:00+08:00
---


`Welcome to my military grade encryption service! It's based on AES but with some tweaks to make it NSA-proof.` 题目位于 CryptoHack 的 `Linear Cryptanalysis` 小节，服务端提供一个“魔改 AES”式的加密服务，目标是恢复隐藏消息。

对 AES 风格 SPN 做线性分析时，核心仍然是寻找偏差最大的近似：

$$
\varepsilon_{\alpha,\beta}=\Pr[\alpha \cdot x = \beta \cdot S(x)]-\frac12
$$

然后把这个偏差沿着轮函数往后传播，最终把它变成对最后一轮子密钥的打分规则。

## 知识补充

- [CryptoHack official Symmetric Ciphers page](https://cryptohack.org/challenges/aes/)
- [Linear cryptanalysis - Wikipedia](https://en.wikipedia.org/wiki/Linear_cryptanalysis)

## 解题思路

根据轮函数和 S-box 建 `LAT`，看哪几组输入输出 mask 偏差最大。

样本够了以后，对最后一轮相关子密钥做部分逆运算，再按线性近似去打分。哪个猜测的偏差最稳，哪个就最可疑。后面无非就是继续往前剥，或者借 key schedule 把整把 key 拉出来。

```python
def best_masks(lat):
    pairs = []
    for alpha, row in enumerate(lat):
        for beta, score in enumerate(row):
            if alpha and beta:
                pairs.append((abs(score), alpha, beta))
    return sorted(pairs, reverse=True)[:8]


def rank_subkeys(samples, inv_last_round, masks):
    ranking = []
    for guess in range(256):
        score = sum(linear_test(pt, inv_last_round(ct, guess), masks) for pt, ct in samples)
        ranking.append((abs(score), guess))
    return sorted(ranking, reverse=True)
```

## 参考资料

- [CryptoHack official Symmetric Ciphers page (contains Beatboxer in Linear Cryptanalysis)](https://cryptohack.org/challenges/aes/)
