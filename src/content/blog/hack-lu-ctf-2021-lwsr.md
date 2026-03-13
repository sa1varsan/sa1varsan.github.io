---
title: Hack.lu CTF 2021 - lwsr 题解
description: 题目核心不是硬解整个 LWE，而是利用实现 bug 造成的 bit leak，先恢复 LFSR 状态再批量判定密文位。
timeLabel: 2021
timeOrder: 2021
topic: Lattice Cryptanalysis
competition: Hack.lu CTF
pubDate: 2026-03-08T17:12:00+08:00
---


Sometimes you learn with errors, but I recently decided to learn with shift registers.

附件里把一个 384 bit 的 `LFSR` 和一个 `LWE` 型加密过程混在了一起：LFSR 的 state 决定每次从哪些公钥项里取和，得到每一位 flag 的密文。服务端还允许你自己不断提交 bit，并告诉你这次加密/解密是否 `Success!`。

```python
def lfsr(state):
    # x^384 + x^8 + x^7 + x^6 + x^4 + x^3 + x^2 + x + 1
    mask = (1 << 384) - (1 << 377) + 1
    newbit = bin(state & mask).count('1') & 1
    return (state >> 1) | (newbit << 383)


n = 128
m = 384

lwe = Regev(n)
q = lwe.K.order()
pk = [list(lwe()) for _ in range(m)]
sk = lwe._LWE__s

for byte in flag:
    for bit in map(int, format(byte, '#010b')[2:]):
        msg = (q >> 1) * bit
        c = [vector([0 for _ in range(n)]), 0]
        for i in range(m):
            if (state >> i) & 1 == 1:
                c[0] += vector(pk[i][0])
                c[1] += pk[i][1]
        c[1] += msg
        print(c)
        state = lfsr(state)

while True:
    msg = int(sys.stdin.readline())
    pk[0][1] += (q >> 1) * msg
    c = [vector([0 for _ in range(n)]), 0]
    for i in range(m):
        if (state >> i) & 1 == 1:
            c[0] += vector(pk[i][0])
            c[1] += pk[i][1]
    pk[0][1] -= (q >> 1) * msg
```

服务端实现存在问题，在处理 bit=1 的时候把公钥某个位置临时改坏了，暴露了 LSFR 最低位。

一旦这个信息泄漏成立，题目就彻底换题了。因为 LFSR 每次都会移位，所以你不是只拿到一位，而是可以一路把整段状态全读出来。然后再反推回加密 flag 时的状态，最后去判断每一位密文到底是 0 还是 1。外表是 LWE，致命点却是状态泄漏。

题目底层仍然是 LWE 形态：

$$
c = \sum_{i \in I} pk_i + m\cdot \left\lfloor \frac q2 \right\rfloor \pmod q
$$

而真正被利用的是状态泄漏：当交互接口把某个公钥项改坏以后，返回结果直接暴露了当前 LFSR 的最低位，所以我们实际上是在恢复

$$
s_t, s_{t+1}, \dots, s_{t+383}
$$

## 知识补充

- [Linear-feedback shift register - Wikipedia](https://en.wikipedia.org/wiki/Linear-feedback_shift_register)
- [Learning with errors - Wikipedia](https://en.wikipedia.org/wiki/Learning_with_errors)

## 解题思路

做法就是固定发送 bit=1，不断记录服务端回包。把 384 次结果攒起来以后，LFSR 的整段状态基本就齐了。再根据 taps 写出逆向更新，把状态往回倒，回到真正加密 flag 的时刻。

之后每一位密文就都能解释了：看这一步状态会选中哪些公钥项，把它们加起来和真实密文比。接近 0 就判 0，接近 `q/2` 就判 1。这样一路扫完，flag 就出来了。

```python
def revlfsr(state):
    msb = feedback_inverse(state)
    return ((state >> 1) | (msb << 383))


def recover_state(bits):
    state = 0
    for idx, bit in enumerate(bits):
        state |= (bit & 1) << idx
    return state
```

## 参考资料

- [CTFtime: Hack.lu 2021 - lwsr](https://ctftime.org/writeup/31200)
- [roadicing: Hack.lu CTF 2021 writeup](https://roadicing.com/2021/11/02/hackluctf-writeup.html)
- [r3kapig writeup repository (contains lwsr section)](https://github.com/r3kapig/writeup/blob/writeup/20211102-hacklu/README.md)
