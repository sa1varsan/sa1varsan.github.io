---
title: zer0pts CTF 2021 - 3-AES 题解
description: 利用可控解密 oracle 先拆掉最外层 CFB，再对剩余两层做 meet-in-the-middle 恢复三把低熵 AES key。
timeLabel: 2021
timeOrder: 2021
topic: Oracle Attack
competition: zer0pts CTF
pubDate: 2026-03-08T17:05:00+08:00
---


3-DES is more secure than DES. Then, 3-AES is more secure than AES of course!

题目实现了一个三层串联的 AES：先做 `AES-ECB`，再做 `AES-CBC`，最后做 `AES-CFB`。三把 key 都来自 `md5(os.urandom(3))`，也就是说每把 key 实际只有 24 bit 熵。服务端提供加密 oracle、解密 oracle，以及一次加密 flag 的接口，目标是恢复 flag。

下面这段是公开 writeup 里直接贴出的原题脚本核心部分，也就是服务端真正使用的三层 AES 逻辑：

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from binascii import hexlify, unhexlify
from hashlib import md5
import os
import signal
from flag import flag

keys = [md5(os.urandom(3)).digest() for _ in range(3)]


def get_ciphers(iv1, iv2):
    return [
        AES.new(keys[0], mode=AES.MODE_ECB),
        AES.new(keys[1], mode=AES.MODE_CBC, iv=iv1),
        AES.new(keys[2], mode=AES.MODE_CFB, iv=iv2, segment_size=8 * 16),
    ]


def encrypt(m: bytes, iv1: bytes, iv2: bytes) -> bytes:
    assert len(m) % 16 == 0
    ciphers = get_ciphers(iv1, iv2)
    c = m
    for cipher in ciphers:
        c = cipher.encrypt(c)
    return c


def decrypt(c: bytes, iv1: bytes, iv2: bytes) -> bytes:
    assert len(c) % 16 == 0
    ciphers = get_ciphers(iv1, iv2)
    m = c
    for cipher in ciphers[::-1]:
        m = cipher.decrypt(m)
    return m


signal.alarm(3600)
while True:
    print('==== MENU ====')
    print('1. Encrypt your plaintext')
    print('2. Decrypt your ciphertext')
    print('3. Get encrypted flag')
    choice = int(input('> '))

    if choice == 1:
        plaintext = unhexlify(input('your plaintext(hex): '))
        iv1, iv2 = get_random_bytes(16), get_random_bytes(16)
        ciphertext = encrypt(plaintext, iv1, iv2)
        ciphertext = b':'.join([hexlify(x) for x in [iv1, iv2, ciphertext]]).decode()
        print("here's the ciphertext: {}".format(ciphertext))

    elif choice == 2:
        ciphertext = input('your ciphertext: ')
        iv1, iv2, ciphertext = [unhexlify(x) for x in ciphertext.strip().split(':')]
        plaintext = decrypt(ciphertext, iv1, iv2)
        print("here's the plaintext(hex): {}".format(hexlify(plaintext).decode()))

    elif choice == 3:
        plaintext = flag
        iv1, iv2 = get_random_bytes(16), get_random_bytes(16)
        ciphertext = encrypt(plaintext, iv1, iv2)
        ciphertext = b':'.join([hexlify(x) for x in [iv1, iv2, ciphertext]]).decode()
        print("here's the encrypted flag: {}".format(ciphertext))
        exit()

    else:
        exit()
```


这题第一眼最容易先被“三层 AES”吓一下，然后又被“每把 key 只有 24 bit”勾着往暴力走。真要这么硬爆，复杂度还是很难看。真正的突破口不是 key 空间本身，而是题目把加密 oracle 和解密 oracle 一起给了，而且最外层还是 CFB。

这就意味着我们不用一层层盲猜，可以先想办法把最外层单独剥掉。只要这一步做成，里面的两层就会变成一个很标准的 meet-in-the-middle 结构。说到底，这题关键不是力气大，而是拆层拆得对。

最外层 CFB 被利用的关键等式是：如果把第二个 IV 从 $iv_2$ 改成 $iv_2'$，那么候选 $k_3$ 的修正密文可以写成

$$
c' = c \oplus E_{k_3}(iv_2') \oplus E_{k_3}(iv_2)
$$

当 $k_3$ 猜对时，解密 oracle 返回的就会重新对齐到原始明文。剥掉这一层后，内部两层就能做 meet-in-the-middle。

## 知识补充

- [Cipher feedback mode - Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB))
- [Meet-in-the-middle attack - Wikipedia](https://en.wikipedia.org/wiki/Meet-in-the-middle_attack)

## 解题思路

先拿一组自己可控的明文、密文和对应的两个 IV。然后固定一个新的 IV，对候选 `k3` 构造修正密文，让解密 oracle 在猜对时正好回到原来的明文。这样外层 CFB 就被单独拎出来了。

剩下的 `ECB -> CBC` 两层就很标准了：一边枚举第一层 key 记录中间值，另一边枚举第二层 key 反推中间值，做一次 meet-in-the-middle。三把 key 都出来以后，按逆序解密 flag 就结束。

```python
def peel_outer_cfb(ciphertext, iv2, iv2_new, k3):
    aes = AES.new(k3, AES.MODE_ECB)
    return bytes(c ^ a ^ b for c, a, b in zip(ciphertext, aes.encrypt(iv2), aes.encrypt(iv2_new)))


def mitm_inner_layers(known_plain, target_block):
    left = {}
    for seed1 in range(1 << 24):
        k1 = expand_seed(seed1)
        left[AES.new(k1, AES.MODE_ECB).encrypt(known_plain)] = seed1
    for seed2 in range(1 << 24):
        k2 = expand_seed(seed2)
        middle = AES.new(k2, AES.MODE_CBC, iv1).decrypt(target_block)
        if middle in left:
            return left[middle], seed2
```

## 参考资料

- [josephsurin: zer0pts CTF 2021 - 3-AES writeup](https://jsur.in/posts/2021-03-07-zer0pts-ctf-2021-crypto-writeups#three-aes)
- [CTFtime: zer0pts CTF 2021 - 3-AES](https://ctftime.org/writeup/26270)
- [Affine Group: zer0pts 2021 crypto writeups](https://affine.group/writeup/2021-01-Zer0pts)
