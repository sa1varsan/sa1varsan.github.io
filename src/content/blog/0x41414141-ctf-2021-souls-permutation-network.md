---
title: 0x41414141 CTF 2021 - Soul's Permutation Network 题解
description: 这是一道标准线性分析题：先做 LAT，再沿置换跟踪 mask，用大量明密文对统计最后一轮子密钥偏差。
timeLabel: 2021
timeOrder: 2021
topic: Classical Cryptanalysis
competition: 0x41414141 CTF
pubDate: 2026-03-08T17:18:00+08:00
---

题目只给出一句很短的说明：`wrap the answer with flag{} when you get it`，附件 `net.py` 则实现了一个 4 轮、8 字节分组的 substitution-permutation network。服务端会给出大量明密文对，key 由 flag 派生，目标是恢复答案并按 `flag{...}` 包起来提交。

## 源码

这题的 challenge 文件 `net.py` 在公开归档里能直接看到。下面这段就是原题里真正的 S-box、置换和加密流程片段：

```python
ROUNDS = 4
BLOCK_SIZE = 8
sbox = [237, 172, 175, 254, 173, 168, 187, 174, 53, 188, 165, 166, 161, 162, 131, 227, ...]
perm = [1, 57, 6, 31, 30, 7, 26, 45, 21, 19, 63, 48, 41, 2, 0, 3, ...]
key = open('flag.txt', 'rb').read().strip()


class Service(socketserver.BaseRequestHandler):
    def key_expansion(self, key):
        keys = [None] * 5
        keys[0] = key[0:4] + key[8:12]
        keys[1] = key[4:8] + key[12:16]
        keys[2] = key[0:4] + key[8:12]
        keys[3] = key[4:8] + key[12:16]
        keys[4] = key[0:4] + key[8:12]
        return keys

    def apply_sbox(self, pt):
        ct = b''
        for byte in pt:
            ct += bytes([sbox[byte]])
        return ct

    def apply_perm(self, pt):
        pt = bin(int.from_bytes(pt, 'big'))[2:].zfill(64)
        ct = [None] * 64
        for i, c in enumerate(pt):
            ct[perm[i]] = c
        return bytes([int(''.join(ct[i: i + 8]), 2) for i in range(0, len(ct), 8)])

    def apply_key(self, pt, key):
        ct = b''
        for a, b in zip(pt, key):
            ct += bytes([a ^ b])
        return ct
```

一眼 SPN。既然轮函数就是异或、S-box、置换反复叠，看线性分析能不能做。写出来的常规路线也确实如此：先做 LAT，再沿着置换把 mask 往后推。

它的 S-box 偏差给得很大，不需要搞特别夸张的多轮组合近似。只要 mask 选对、样本够多，最后一轮某个字节的子密钥就会非常显眼。

线性分析里最常看的量是偏差：

$$
\varepsilon_{\alpha,\beta}=\Pr[\alpha \cdot x = \beta \cdot S(x)]-\frac12
$$

等价地，也可以先计算线性近似表：

$$
LAT[\alpha,\beta]=\sum_x (-1)^{\alpha \cdot x \oplus \beta \cdot S(x)}
$$

偏差越大，对应的 mask 越适合作为最后一轮子密钥恢复的统计依据。

## 知识补充

- [Linear cryptanalysis - Wikipedia](https://en.wikipedia.org/wiki/Linear_cryptanalysis)
- [Matsui's Algorithm 2 overview](https://crypto.stackexchange.com/questions/12328/what-is-linear-cryptanalysis)

## 解题思路

先把 S-box 的 `LAT` 建出来，挑偏差最大的几组 mask。然后顺着题目的 bit permutation 一轮轮推，看看哪组近似能落到最后一轮前的某个字节上。

接着枚举最后一轮相关子密钥，部分逆掉最后一层，统计线性关系成立次数。正确猜测的偏差会明显更大，错误猜测则接近随机。把最后一轮子密钥拆出来以后，再往前推或者顺着 key schedule 回去就行。

```python
def build_lat(sbox):
    lat = [[0] * 256 for _ in range(256)]
    for alpha in range(256):
        for beta in range(256):
            score = 0
            for x in range(256):
                score += -1 if parity(alpha & x) ^ parity(beta & sbox[x]) else 1
            lat[alpha][beta] = score
    return lat


def score_last_round(samples, guess, in_mask, out_mask, inv_sbox):
    score = 0
    for pt, ct in samples:
        u = inv_sbox[ct[-1] ^ guess]
        score += 1 if parity(pt[0] & in_mask) == parity(u & out_mask) else -1
    return abs(score)
```

## 参考资料

- [CTFtime: Soul's Permutation Network](https://ctftime.org/writeup/25853)
- [Original writeup linked by CTFtime](https://github.com/yonlif/0x41414141-CTF-writeups/blob/main/SoulsPermutationNetwork.md)
- [Challenge file archive: net.py](https://github.com/sajjadium/ctf-archives/blob/main/ctfs/0x41414141/2021/crypto/Soul-Permutation-Network/net.py)
