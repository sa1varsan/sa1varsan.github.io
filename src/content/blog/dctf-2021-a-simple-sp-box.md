---
title: DCTF 2021 - A Simple SP Box! 题解
description: 通过 chosen-plaintext 先恢复 substitution，再逆掉 odd/even 置换轮次，还原整条 flag。
timeLabel: 2021
timeOrder: 2021
topic: Classical Cryptanalysis
competition: DCTF
pubDate: 2026-03-08T17:16:00+08:00
---

It's just a simple SP-box, 150 tries should be enough for you.

服务端先输出一条被加密后的 flag，然后允许你在 150 轮内不断猜 flag；如果猜错，它就把你的输入按同样算法加密后返回。加密算法会先按一张固定但未知的字符映射做 substitution，再把奇数位字符移到前半、偶数位移到后半，重复若干轮。

```python
random = SystemRandom()
ALPHABET = ascii_letters + digits + "_!@#$%.'\"+:;<=}{"
shuffled = list(ALPHABET)

random.shuffle(shuffled)
S_box = {k: v for k, v in zip(ALPHABET, shuffled)}


def encrypt(message):
    if len(message) % 2:
        message += "_"

    message = list(message)
    rounds = int(2 * ceil(log(len(message), 2)))

    for round in range(rounds):
        message = [S_box[c] for c in message]
        if round < (rounds - 1):
            message = [message[i] for i in range(len(message)) if i % 2 == 1] + [message[i] for i in range(len(message)) if i % 2 == 0]
    return ''.join(message)


for _ in range(150):
    guess = input("> ").strip()
    assert 0 < len(guess) <= 10000

    if guess == flag:
        print("Well done. The flag is:")
        print(flag)
        break
    else:
        print("That doesn't look right, it encrypts to this:")
        print(encrypt(guess))
```

题目本质上是在重复一个 substitution-permutation 组合：

$$
E = \pi \circ \sigma
$$

其中 $\sigma$ 是逐字符代换，$\pi$ 是把奇数位和偶数位拆开的固定置换。由于全相同字符串在 $\pi$ 下保持不变，chosen-plaintext 就能先单独学到 $\sigma$。

## 知识补充

- [Chosen-plaintext attack - Wikipedia](https://en.wikipedia.org/wiki/Chosen-plaintext_attack)
- [Substitution-permutation network - Wikipedia](https://en.wikipedia.org/wiki/Substitution%E2%80%93permutation_network)

## 解题思路

先拿全相同字符去喂 oracle，一种字符一条，直接把整张 substitution 表摸出来。因为置换在这种输入下不起作用，所以返回值的首字符就已经够用了。

接下来把题目给的密文先做逆替换，再按 odd/even 规则把多轮置换一步步倒回去。顺序一回来，明文也就全出来了。

```python
def recover_substitution(oracle, alphabet, length):
    table = {}
    for ch in alphabet:
        probe = ch * length
        table[ch] = oracle(probe)[0]
    return table


def invert_shuffle(text, rounds):
    for _ in range(rounds - 1):
        half = (len(text) + 1) // 2
        odds, evens = text[:half], text[half:]
        text = ''.join(a + b for a, b in zip(odds, evens + ''))[: len(text)]
    return text
```

## 参考资料

- [HgbSec: dCTF 2021 - A Simple SP Box!](https://hgbsec.at/posts/2021/writeups/dctf/simple-sp-box/)
- [Onealmond writeup](https://onealmond.github.io/ctf/dctf-2021/a-simple-sp-box.html)
- [CTFtime: A Simple SP Box!](https://ctftime.org/writeup/28434)
