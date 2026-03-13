---
title: 'MiniL CTF 2023 - EZfactor'
description: '从高位泄露与 Coppersmith 调参入手，再转向二次剩余与丢番图方程求解。'
timeLabel: 2023
timeOrder: 2023
topic: 'RSA & Number Theory'
competition: 'MiniL CTF'
pubDate: 2026-03-11T16:45:00+08:00
---

## EZfactor

一眼 $p$ 高位泄露：管它怎么解，先 Coppersmith 爆了！

嗯？怎么爆不出来？？？这咋办？

wuuuu，论文保命。

嗯？论文咋也不对？不是，我这参数这么完美，你在跟我开玩笑吗？

调参？不是，这真能调吗？

不是，这真能调？

总结：格真是玄学。

这里大概总结一下调参。论文可以参考这个：[lll.pdf](https://www.crypto.ruhr-uni-bochum.de/imperia/md/content/may/paper/lll.pdf)。（虽然 Coppersmith 我翻了太多论文了，在这就不贴全了，大家自己搜搜应该差不多。）

由论文可知，Coppersmith 的应用场景如下：

现有一个 $e$ 阶多项式 f，那么可以：

- 给定 beta，快速求出模某个 $n$ 的因数 $b$ 意义下较小的根，其中 $b \ge n^{\beta}$（$0 < \beta \le 1$）。
- 在模 $n$ 意义下，快速求出 $n^{\frac{\beta^2}{e}}$ 以内的根。

而应用 Coppersmith 定理求解 p_{unknown}，前提条件是：

$$
p_{unknown} \le n^{\frac{\beta^2}{e}}
$$

这道题的高位攻击显然对应第二条性质。此时可构造多项式 $f = p_{high} + p_{unknown}$（构造方法不止一种，我用的是这个；其实都差不多）。显然阶数 $e=1$。

而 $\beta$ 的定义是：存在 $n$ 的某个因数 b，使得 $b \ge n^{\beta}$（$0 < \beta \le 1$）。

由于 $n = p \cdot q$，其中 $p, q$ 均为大素数。验算可知，当 $p,q$ 二进制位数相同时，最接近边界值的保守做法是取 0.4（实际上介于 $0.4$ 到 $0.5$ 之间）。如果 $p,q$ 位数不同，就按具体情况分析。

注意到题目中的 $p$ 和 $q$ bit 位一致，我们先保守取 $\beta = 0.4$，其他参数按论文进行初始化。

```
sage.rings.polynomial.polynomial_modn_dense_ntl.small_roots(self, X=None, beta=1.0, epsilon=None, **kwds)
```

```
dd = pol.degree()
beta = 0.4                            # we should have q >= N^beta
epsilon = beta / 7                    # <= beta/7
mm = ceil(beta**2 / (dd * epsilon))   # optimized
tt = floor(dd * mm * ((1/beta) - 1))  # optimized
XX = ceil(pow(n , ((beta**2/dd) - epsilon))) # we should have |diff| < X
```

我们在这个基础上调参即可。beta 以 0.01 为步长。epsilon 的建议是从 0 到 $\beta/7$ 遍历，步长取 0.01。

```
from sage.all import*
from Crypto.Util.number import*
n = 1612520630363003059353142253089981533043311564255746310310940263864745479492015266264329953981958844235674179099410756219312942121244956701500870363219075525408783798007163550423573845701695879459236385567459569561236623909034945892869546441146006017614916909993115637827270568507869830024659905586004136946481048074461682125996261736024637375095977789425181258537482384460658359276300923155102288360474915802803118320144780824862629986882661190674127696656788827
ph = 484571358830397929370234740984952703033447536470079158146615136255872598113610957918395761289775053764210538009624146851126
phh = ph*(2**360)
e = 107851261855564315073903829182423950546788346138259394246439657948476619948171
kbits = 360
PR = PolynomialRing(Zmod(n),names = ('x'));(x,) = PR._first_ngens(1)
f = x + phh
p = f.small_roots(X = 2**360,beta = 0.45,epsilon = 0.02)[0] + phh
print(p)
```

小科普到此结束，我们开始上面说的 Diophantine equation 的求解。大概思路可以参考某本书的 41 页；证明的话我看的是这篇论文：[pjaa.80.40](https://projecteuclid.org/journalArticle/Download?urlId=10.3792%2Fpjaa.80.40)。这里直接贴代码：

```

def find_sol(p, d):
    """
    input - a prime p, an absolute value of discriminant d
    output - a primitive solution (x, y) in integers to the equation
    x^2 + d*y^2 = p, if there exists one, otherwise return None.
    """
    t = find_sqrt(p, -d)
    bound = ZZ(int(sqrt(p)))
    n = p
    while True:
        n, t = t, n % t
        if t < bound:
            break
    if ZZ(gmpy2.iroot((p - t**2)/d ,2)) in ZZ:
        return t, ZZ(sqrt((p - t**2) / d))
    else:
        return None
x, y = find_sol(N, e)
```

现在要做的大概就是解决上面代码里提到的 `find_sqrt`。由上面的分解我们可以得到 $N$ 分解后的 p,q。这里利用二次剩余加 CRT 可以求出 `find_sqrt(n, -d)`，即 $-d$ 关于 $n$ 的二次剩余。（注意这里是 -d。实际上验证可知 $p \bmod 4 = 3$，根据欧拉判别法，不存在 $d$ 关于 $p$ 的二次剩余；当时在这卡了很久，自锤一下。）

根据小学知识，理论上会有四组解，验证排除一下即可。（~~我可能运气比较好，最开始试的两组就是对的~~）
