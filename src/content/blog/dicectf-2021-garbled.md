---
title: DiceCTF 2021 - garbled 题解
description: 从 garbled table 里的 validation ciphertext 入手，对 24 bit label key 做 meet-in-the-middle 恢复电路标签。
timeLabel: 2021
timeOrder: 2021
topic: Garbled Circuits
competition: DiceCTF
pubDate: 2026-03-08T17:04:00+08:00
---


My friend gave me a weird circuit to evaluate, but I forgot to ask her for the input. I know the circuit is supposed to return true, but everything's been garbled and I can't make heads or tails of it.

题目给出了一套基于 Yao garbled circuit 的实现，目标函数本质上是一个 4 输入 AND。服务端把 garbled table 发给我们，但没有直接给出输入 label。题目里还实现了一个很小的 SPN 分组密码，而每个 label key 只有 24 bit。目标是恢复那些代表输入 bit 为 `1` 的 label，进而拿到 flag。

```python
# block_cipher.py
def encrypt(data, key1, key2):
    encrypted = encrypt_data(data, key1)
    encrypted = encrypt_data(encrypted, key2)
    return encrypted


# yao.py
def generate_random_label():
    return randrange(0, 2**24)


def garble_label(key0, key1, key2):
    """
    key0, key1 = two input labels
    key2 = output label
    """
    gl = encrypt(key2, key0, key1)
    validation = encrypt(0, key0, key1)
    return (gl, validation)
```

题目额外给了 validation ciphertext，其泄露了藏起来的 label 关系。

garbled gate 的评估可以抽象成双重解密：

$$
w_{out}=D_{k_b}(D_{k_a}(T_{a,b}))
$$

而题目额外给出的 validation 项相当于

$$
V_{a,b}=E_{k_a,k_b}(0)
$$

这使得我们能够围绕已知明文 $0$ 做 meet-in-the-middle，而不用直接枚举 $2^{48}$ 个 key 对。

## 知识补充

- [Yao's garbled circuit - Wikipedia](https://en.wikipedia.org/wiki/Garbled_circuit)
- [Meet-in-the-middle attack - Wikipedia](https://en.wikipedia.org/wiki/Meet-in-the-middle_attack)

## 解题思路

先把所有单把 key 对 0 的处理结果预处理出来，做一边的表；另一边拿 validation ciphertext 去逆，能对上的就是候选 key 对。这一步本身就已经把复杂度压下来了。

然后再回到 garbled table 本身去筛。因为 AND gate 的输出分布有固定结构，所以真正的 key 对会在解出来的 label 模式上很显眼。把这部分筛完，后面顺着电路往下走就能把输入标签和 flag 一路捋出来。

```python
def mitm_validation(ciphertext, key_space):
    left = {}
    for k1 in key_space:
        left[decrypt1(ciphertext, k1)] = k1
    for k2 in key_space:
        probe = encrypt1(b'\x00' * 16, k2)
        if probe in left:
            yield left[probe], k2


def keep_consistent_pairs(candidates, gate_table):
    good = []
    for k1, k2 in candidates:
        outputs = [decrypt2(entry, k1, k2) for entry in gate_table.values()]
        if len(set(outputs)) <= 2:
            good.append((k1, k2))
    return good
```

## 参考资料

- [josephsurin: DiceCTF 2021 - garbled](https://jsur.in/posts/2021-02-08-dicectf-2021-garbled/)
- [CTFtime: DiceCTF 2021 - garbled](https://ctftime.org/writeup/25974)
- [DiceGang official challenge repository](https://github.com/dicegang/dicectf-2021-challenges)
