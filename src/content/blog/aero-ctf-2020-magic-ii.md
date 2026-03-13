---
title: Aero CTF 2020 - Magic II 题解
description: 前半段把 `A*s+e=b mod q` 还原成 CVP 来做，后半段再用 Z3 补出 RNG 初始状态并解出 flag。
timeLabel: 2020
timeOrder: 2020
topic: Lattice Cryptanalysis
competition: Aero CTF
pubDate: 2026-03-08T17:11:00+08:00
---

题目会不断给出 12 维 `amounts` 向量和一个 `effect` 值，而内部真实计算是 `effect = sum(ingredients[i] * amounts[i]) + side_effect mod magic_constant`。此外程序还把 `potions_count` 打印出来，而这个值又和 flag、内部 RNG 状态有关。附件给了 100 轮样本，目标是恢复最终 flag。

```python
def create_potion(ingredients: List[int], amounts: List[int]) -> int:
    magic_constant = 1046961993706256953070441
    effect = sum(starmap(mul, zip(ingredients, amounts)))
    side_effect = getrandbits(13) ^ getrandbits(37)
    return (effect + side_effect) % magic_constant


def main():
    from secret import FLAG
    security_level = 64
    ingredients_count = 12
    random = Random.create(security_level)
    potions_count = int.from_bytes(FLAG, 'big') ^ random.randint(512)
    print(f'There are {potions_count} famous potions in the world. We are trying to create something new!')
    ingredients = [random.randint(security_level) for _ in range(ingredients_count)]
    while True:
        amounts = [getrandbits(41) for _ in range(len(ingredients))]
        effect = create_potion(ingredients, amounts)
        print(f'A potion with {amounts} amounts of ingregients has {effect} value of effect.')
        choice = input('Would you like to create another potion? (y/n): ')
        if not choice.lower().startswith('y'):
            break
        return


def _getbit(self) -> int:
    buffer = 2 * self._state | self._state >> (self._size - 1) | self._state << (self._size + 1)
    self._state = reduce(ior, ((buffer >> i & 7 in [1, 2, 3, 4]) << i for i in range(self._size)))
    return self._state & 1
```

这题分成两段。前半截是个带小噪声的线性系统；后半截是把前面恢复出来的输出继续拿去打 RNG。

真正的突破口还是第一阶段。只要把 `amounts`、`ingredients`、`effect` 的关系认成弱 LWE / CVP，后面的路就顺了：先把 ingredients 抠出来，再拿这些输出位去把 RNG 初始状态补全。

题目的第一阶段可以整理成带噪线性关系

$$
A s + e \equiv b \pmod q
$$

其中 $e$ 很小，所以我们不是把它当成“任意模误差”，而是把它看成 CVP 里的一个短偏移量。也就是说，目标是找到最接近 $b$ 的格点。

## 知识补充

- [Closest vector problem - Wikipedia](https://en.wikipedia.org/wiki/Closest_vector_problem)
- [Babai's nearest plane algorithm - Wikipedia](https://en.wikipedia.org/wiki/Babai%27s_nearest_plane_algorithm)
- [Z3 Guide](https://microsoft.github.io/z3guide/)

## 解题思路

先把 100 轮样本改写成矩阵形式，把目标值当成点、把 `A` 和 `qI` 当成格基，然后用 LLL 加 Babai 近似求最近格点。只要噪声量级找对，`ingredients` 很快就能定位出来。

拿到这部分之后，后半段就转成状态恢复：把 `ingredients` 对应的输出位翻成约束，直接喂给 Z3 去跑初始 seed。seed 一出来，剩下的随机量全能复现，最终把和 flag 纠缠在一起的那部分也一起解开。

```python
def build_cvp_basis(A, q):
    n = len(A)
    dim = len(A[0])
    basis = matrix(ZZ, n + dim, n + dim)
    basis[:n, :dim] = matrix(ZZ, A)
    basis[n:, n:] = q * identity_matrix(ZZ, dim)
    return basis


def recover_rng_seed(bits):
    seed = BitVec('seed', 64)
    solver = Solver()
    state = seed
    for want in bits:
        state = step(state)
        solver.add((state & 1) == want)
    assert solver.check() == sat
    return solver.model()[seed].as_long()
```

## 参考资料

- [CTFtime: Aero CTF 2020 - Magic II](https://ctftime.org/writeup/18549)
- [HackMD writeup referenced by CTFtime](https://hackmd.io/@hakatashi/B1OM7HFVI)
- [Gist: solver for Magic II](https://gist.github.com/hakatashi/2266a5df35cc79de50b86d2419b33a6f)
