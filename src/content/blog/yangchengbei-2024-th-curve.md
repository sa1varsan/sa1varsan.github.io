---
title: '羊城杯 2024 - TH_Curve'
description: '把 Twisted Hessian 曲线转成椭圆曲线模型后，直接求离散对数恢复明文。'
timeLabel: 2024
timeOrder: 2024
topic: 'Elliptic Curve Cryptography'
competition: '羊城杯'
pubDate: 2026-03-11T16:45:00+08:00
---

题目内容：

TH_Curve

题目分值：

已答出6次，初始分值500.0，当前分值499.78，解出分值499.69

题目难度：

容易

```
from Crypto.Util.number import *
from secret import flag

def add_THcurve(P, Q):
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 - y1 ** 2 * x2 * y2) * pow(a * x1 * y1 * x2 ** 2 - y2, -1, p) % p
    y3 = (y1 * y2 ** 2 - a * x1 ** 2 * x2) * pow(a * x1 * y1 * x2 ** 2 - y2, -1, p) % p
    return x3, y3

def mul_THcurve(n, P):
    R = (0, 0)
    while n > 0:
        if n % 2 == 1:
            R = add_THcurve(R, P)
        P = add_THcurve(P, P)
        n = n // 2
    return R

p = 10297529403524403127640670200603184608844065065952536889
a = 2
G = (8879931045098533901543131944615620692971716807984752065, 4106024239449946134453673742202491320614591684229547464)

FLAG = flag.lstrip(b'DASCTF{').rstrip(b'}')
assert len(FLAG) == 15
m = bytes_to_long(FLAG)
assert m < p
Q = mul_THcurve(m, G)
print("Q =", Q)
# Q = (6784278627340957151283066249316785477882888190582875173, 6078603759966354224428976716568980670702790051879661797)
```

Twisted Hessian Curve

还是wikipedia查东西舒服

```
from sage.all import *
from Crypto.Util.number import *

p = 10297529403524403127640670200603184608844065065952536889
a = 2
G = (8879931045098533901543131944615620692971716807984752065, 4106024239449946134453673742202491320614591684229547464)
Q = (6784278627340957151283066249316785477882888190582875173, 6078603759966354224428976716568980670702790051879661797)

R = PolynomialRing(Zmod(p), 3, 'x,y,z')
x, y, z = R.gens()
P =  (8879931045098533901543131944615620692971716807984752065, 4106024239449946134453673742202491320614591684229547464,1)

d = (a*G[0]**3 + G[1]**3 + 1) * inverse(G[0]*G[1] , p)
cubic = a*x**3 + y**3 + z**3 - d*x*y*z
E = EllipticCurve_from_cubic(cubic, P, morphism= True)

QQ = E(Q)
GG = E(G)

print(long_to_bytes(GG.discrete_log(QQ)))
# 525729205728344257526560548008783649
# e@sy_cuRvL_c0o!
```
