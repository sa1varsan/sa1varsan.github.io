---
title: 'MiniL CTF 2023 - Mintrix'
description: '利用矩阵 rref 结构和特征多项式关系，从公开构造里直接拿到 sharekey。'
timeLabel: 2023
timeOrder: 2023
topic: 'Matrix Cryptography'
competition: 'MiniL CTF'
pubDate: 2026-03-11T16:45:00+08:00
---

## Mintrix

两种解法。

1. 第一种思路：把 `puk` 转化成 `rref` 形式，然后直接分解。因为矩阵转化成 `rref` 后 pivots 刚好是前 60 列，这是必然的（可以自行证明）

exp：

```
shA = []
matA, matB, flag = load(r'/root/ctf/mintrix/output.sobj')
for i in range(4):
    m1 = matA[i].rref()
    m2 = matB[i].rref()
    B1.append(m1[:66,:99])
    A1.append(m1[:99,:66])
    B2.append(m2[:66,:99])
    A2.append(m2[:99,:66])
shA = []
for i in range(4):
    shA.append(((A1[i].transpose())*A2[i]*B2[i]*(B1[i].transpose())).det())
print(shA)
```

1. dbt 学长的解法我觉得很棒。据说整活三行代码就搞定了，学不来（（（。但我觉得这才是正解。我这套思路很多时候是不奏效的，总是和 pk、sk 正面硬刚；并不是什么时候都能做出来，比如接下来的 Sums。应该去找一些更弱的性质（这是 dbt 学长原话）。
    
    我来补坑了：
    
    - 把题里出现的公开构造识别成 **AB（大方阵但低秩）** 和 **BA（小方阵）** 的关系。
    - 用结论 chi_{AB}(x)=x^{20}chi_{BA}(x)，从 $AB$ 的特征多项式（charpoly）推出 $BA$ 的特征多项式。
    - 取常数项得到 det(BA)，从而**直接得到 sharekey**（或其派生），无需分解求私钥。
    - 必要时用 $\det(S^{-1}MS)=\det(M)$ 等行列式性质，把 $\det$ 改写成只含公开矩阵（例如 C_0, C_1）的形式，便于落地实现。

感觉 dbt 学长最后应该会放 WP，所以就当预告，期待一下。
