---
title: '0ctf 2024 - ZKPQC_1'
description: '先把共享曲线和目标 2-isogeny kernel 算出来，再借 `j = 1728` 附近的特殊 2-isogeny 图构造 3 个等价 kernel 通过 PoK。'
timeLabel: 2024
timeOrder: 2024
topic: 'Post-Quantum Cryptography'
competition: '0ctf'
pubDate: 2026-03-14T10:35:00+08:00
---

```text
import signal
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from secret import FLAG

def _handle_timeout(signum, frame):
    raise TimeoutError('function timeout')

FAKE_NUM = 3

# Base field
a = 49
b = 36
p = 2**a * 3**b - 1


def get_canonical_basis(E, l, e):
    assert (p+1) % l^e == 0
    P = E(0)
    while (l^(e-1))*P == 0:
        P = ((p+1) // l^e) * E.random_point()
    Q = P
    while P.weil_pairing(Q, l^e)^(l^(e-1)) == 1:
        Q = ((p+1) // l^e) * E.random_point()
    return P, Q

def gen_torsion_points(E):
    Pa, Qa = get_canonical_basis(E, 2, a)
    Pb, Qb = get_canonical_basis(E, 3, b)
    return Pa, Qa, Pb, Qb


def hash_function(J):
    return (bytes_to_long(sha256(str(J[0]).encode()).digest()) // 2 * 2 + 1)  % 2^a, \
        (bytes_to_long(sha256(str(J[1]).encode()).digest()) // 2 * 2 + 1) % 2^a


def get_Fp2(i):
    return int(input()) + int(input())*i


def get_ECC_and_points():
    Ea4 = get_Fp2(i)
    Ea6 = get_Fp2(i)
    Ea = EllipticCurve(Fp2, [0, 6, 0, Ea4, Ea6])
    P = Ea(get_Fp2(i), get_Fp2(i))
    Q = Ea(get_Fp2(i), get_Fp2(i))
    return Ea, P, Q


class ZKP:

    def __init__(self, E, kernel):
        self.P0, self.Q0 = get_canonical_basis(E, 3, b)
        self.E0 = E
        self.chall_lst = []
        self.CHALL_NUM = 16
        self.kernel = kernel
        self.ker_phi = self.E0.isogeny(self.kernel, algorithm="factored")
        print(f"{self.P0 = }")
        print(f"{self.Q0 = }")


    def _commit(self):
        print("Give me E2:")
        E2a4 = get_Fp2(i)
        E2a6 = get_Fp2(i)
        self.E2 = EllipticCurve(Fp2, [0, 6, 0, E2a4, E2a6])

        self.P2, self.Q2 = get_canonical_basis(self.E2, 3, b)
        print(f"{self.P2 = }")
        print(f"{self.Q2 = }")

        self.E3, self.P3, self.Q3 = get_ECC_and_points()
        assert self.E3.is_supersingular()


    def _challenge(self, c=None):
        if c is None:
            self.chall = randint(0,1)
        else:
            self.chall = c
        print(f"chall = {self.chall}")


    def _verify(self):
        print("Your response:")

        if self.chall:
            Kphi_ = self.E2(get_Fp2(i), get_Fp2(i))
            assert 2^a * self.E2(Kphi_) == self.E2(0)
            phi_ = self.E2.isogeny(Kphi_, algorithm="factored")
            assert self.E3.j_invariant() == phi_.codomain().j_invariant()
            assert phi_(self.P2) == self.P3 and phi_(self.Q2) == self.Q3
        else:
            resp = input()
            sigma, delta = [int(_) for _ in resp.split(",")]
            Kbar_psi = sigma * self.P2 + delta * self.Q2
            Kbar_psi_ = sigma * self.P3 + delta * self.Q3
            assert 3^b * Kbar_psi == self.E2(0) and 3^b * Kbar_psi_ == self.E3(0)
            E0_ = self.E2.isogeny(Kbar_psi, algorithm="factored").codomain()
            E1_ = self.E3.isogeny(Kbar_psi_, algorithm="factored").codomain()
            assert E0.j_invariant() == E0_.j_invariant() and EA.j_invariant() == E1_.j_invariant()
            assert self.ker_phi.codomain().j_invariant() == E1_.j_invariant()
        return True


    def run(self):
        self.chall_lst = [randint(0,1) for _ in range(self.CHALL_NUM)]
        while sum(self.chall_lst) == 0 or sum(self.chall_lst) == self.CHALL_NUM:
            self.chall_lst = [randint(0, 1) for _ in range(self.CHALL_NUM)]

        for _ in range(self.CHALL_NUM):
            print(f"Now, for the {_} round of PoK:")
            self._commit()
            self._challenge(self.chall_lst[_])
            if not self._verify():
                return False
        return True

timeout = 90
signal.signal(signal.SIGALRM, _handle_timeout)
signal.alarm(timeout)

Fpx = PolynomialRing(GF(p), "x")
x = Fpx.gen()
Fp2.<i> = GF(p**2, modulus=[1,0,1])

E0 = EllipticCurve(Fp2, [0, 6, 0, 1, 0])
E0.set_order((p+1)**2)

Pa,Qa,Pb,Qb = gen_torsion_points(E0)
print(f"Pa = {Pa}")
print(f"Qa = {Qa}")
print(f"Pb = {Pb}")
print(f"Qb = {Qb}")

Ea, phiPb, phiQb = get_ECC_and_points()
assert Ea.is_supersingular()

Sb = randint(0, 3^b-1)
Tb = randint(0, 3^b-1)
R = Sb * Pb + Tb * Qb
psi = E0.isogeny(R, algorithm="factored")
Eb, psiPa, psiQa = psi.codomain(), psi(Pa), psi(Qa)
print(f"{Eb}")
print(f"psiPa = {psiPa}")
print(f"psiQa = {psiQa}")

J = Ea.isogeny(Sb * phiPb + Tb * phiQb, algorithm="factored").codomain().j_invariant()
Sa, Ta = hash_function(J)
EA = E0.isogeny(Sa * Pa + Ta * Qa, algorithm="factored").codomain()

s = set()
for _ in range(FAKE_NUM):
    print("Give me your share: ")

    kernel = E0(get_Fp2(i), get_Fp2(i))
    assert 2^a * kernel == E0(0) and 2^(a-2) * kernel != E0(0)
    zkp = ZKP(E0, kernel)

    if all(kernel.weil_pairing(PP, 2^a) != 1 for PP in s) and zkp.run():
        print("Good Job!")
        s.add(kernel)
    else:
        print("Out, you are cheating!")
        break

if len(s) == FAKE_NUM:
    print("You are a master of isogeny and ZKP.")
    print(FLAG)
```

## 题目解析

这题表面上是 ZKP，实质上是个 isogeny-based PoK。前半段其实就是一轮非常标准的 SIDH 风格密钥交换：你先给出自己的 supersingular 曲线和 Bob 的 3-torsion 基点像，服务端回你 Bob 侧的公钥像，然后双方各自再走一次对方给出的 kernel，最后得到共享曲线的 `j` 不变量 `J`。这个 `J` 再被哈希成 `(Sa, Ta)`，于是目标 2-isogeny kernel 也就固定成了 `R_A = Sa P_a + Ta Q_a`，终点曲线就是 `E_A`。

真正难的地方在后半段。题目要求你交 3 个不同的 2-power kernel，它们都要把起点 `E0` 送到同一个 `E_A`，阶还必须落在 `2^a` 或 `2^(a-1)`，并且两两 Weil pairing 不能是 1。关键观察是 `j = 1728` 附近的 2-isogeny 图有特殊自同构，尤其是曲线 `y^2 = x^3 + x` 上的自同构和一条度为 4 的自同态 `2i`。如果 `R_A` 对应的 2-isogeny 路径一开始穿过 `1728` 这一小块，就能把这条路径在不改终点的前提下重新走几次，于是同一个 `E_A` 会对应出多条等价 kernel。

## 解题思路

这里直接按路径去做。先按正常 SIDH 交换拿到 `J`，算出 `R_A` 和 `E_A`。然后把 `R_A` 的 2-isogeny 路径投到 `j = 1728` 那个邻域里，枚举能复用同一路径的自同构和 2-division points，把所有仍然满足

$$
E_0 / \langle K \rangle \cong E_A
$$

的候选 kernel 收集出来。实际筛掉阶不够和配对冲突的点之后，刚好能凑出 3 个能用的 kernel。

PoK 部分反而比较机械。`chall = 1` 时直接把当前 3-isogeny 下推过去的 2-kernel 发回去；`chall = 0` 时构造一个 3-power kernel，让 `E2` 和 `E3` 分别商掉它之后回到 `E0` 和 `EA`，再把这个 kernel 在 `(P2, Q2)` 基下写成 `(sigma, delta)` 交回去即可，流程照着 `eprint 2022/475` 实现就行。

## 解题脚本

下面放一份核心 Sage 脚本，思路就是“正常做 SIDH 交换拿到 `R_A`，再在 `j = 1728` 邻域找等价 kernel，然后机械过 PoK”。

```text
from sage.all import *
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from pwn import remote

a = 49
b = 36
p = 2^a * 3^b - 1
Fp2.<i> = GF(p^2, modulus=[1, 0, 1])
E0 = EllipticCurve(Fp2, [0, 6, 0, 1, 0])
E0.set_order((p + 1)^2)

def hash_function(J):
    return (
        (bytes_to_long(sha256(str(J[0]).encode()).digest()) // 2 * 2 + 1) % 2^a,
        (bytes_to_long(sha256(str(J[1]).encode()).digest()) // 2 * 2 + 1) % 2^a,
    )

def get_canonical_basis(E, l, e):
    P = E(0)
    while (l^(e - 1)) * P == 0:
        P = ((p + 1) // l^e) * E.random_point()
    Q = P
    while P.weil_pairing(Q, l^e)^(l^(e - 1)) == 1:
        Q = ((p + 1) // l^e) * E.random_point()
    return P, Q

def send_fp2(io, z):
    io.sendline(str(int(z[0])).encode())
    io.sendline(str(int(z[1])).encode())

def read_point(io, E, prefix):
    io.recvuntil(prefix)
    raw = io.recvline().strip().decode().replace(':', ',')
    return E(eval(raw))

def equivalent_kernels(RA, EA):
    Ej = EllipticCurve(Fp2, [0, 0, 0, 1, 0])
    phi = E0.isogeny(E0(0, 0), algorithm="factored")
    lift = phi.codomain().isomorphism_to(Ej) * phi
    cands = [RA]
    for aut in Ej.automorphisms()[3:]:
        back = lift.dual() * aut
        for T in lift(RA).division_points(2):
            for K in [back(T), back(T) + RA]:
                if K == E0(0) or K.order() < 2^(a - 1):
                    continue
                if E0.isogeny(K, algorithm="factored").codomain().j_invariant() == EA.j_invariant():
                    cands.append(K)
    good = []
    for K in cands:
        if all(K.weil_pairing(L, 2^a) != 1 for L in good):
            good.append(K)
    return good[:3]

def kernel_coords(K, P, Q, ord_):
    c = discrete_log(K.weil_pairing(Q, ord_), P.weil_pairing(Q, ord_), ord=ord_, operation='*')
    d = discrete_log(K.weil_pairing(P, ord_), Q.weil_pairing(P, ord_), ord=ord_, operation='*')
    return int(c), int(d)

def challenge0_kernel(psi, E2, P2, Q2):
    while True:
        T = (2^a) * E0.random_point()
        if T.order() != 3^b:
            continue
        K = psi(T)
        if K.order() != 3^b:
            continue
        if E2.isogeny(K, algorithm="factored").codomain().j_invariant() == E0.j_invariant():
            return kernel_coords(K, P2, Q2, 3^b)

def main():
    io = remote("instance.penguin.0ops.sjtu.cn", 18433)
    Pa = read_point(io, E0, b"Pa = ")
    Qa = read_point(io, E0, b"Qa = ")
    Pb = read_point(io, E0, b"Pb = ")
    Qb = read_point(io, E0, b"Qb = ")

    sa = randint(0, 2^a - 1)
    ta = randint(0, 2^a - 1)
    phi = E0.isogeny(sa * Pa + ta * Qa, algorithm="factored")
    Ea = phi.codomain()

    send_fp2(io, Ea.a4())
    send_fp2(io, Ea.a6())
    send_fp2(io, phi(Pb)[0])
    send_fp2(io, phi(Pb)[1])
    send_fp2(io, phi(Qb)[0])
    send_fp2(io, phi(Qb)[1])

    io.recvuntil(b"Elliptic Curve defined by y^2 = x^3 + 6*x^2 + ")
    eba4 = Fp2(io.recvuntil(b"*x + ")[:-5].decode())
    eba6 = Fp2(io.recvuntil(b" over Finite Field")[:-len(b" over Finite Field")].decode())
    Eb = EllipticCurve(Fp2, [0, 6, 0, eba4, eba6])
    psiPa = read_point(io, Eb, b"psiPa = ")
    psiQa = read_point(io, Eb, b"psiQa = ")

    J = Eb.isogeny(sa * psiPa + ta * psiQa, algorithm="factored").codomain().j_invariant()
    ha, hb = hash_function(J)
    RA = ha * Pa + hb * Qa
    EA = E0.isogeny(RA, algorithm="factored").codomain()
    kernels = equivalent_kernels(RA, EA)

    for ker in kernels:
        io.recvuntil(b"Give me your share: ")
        send_fp2(io, ker[0])
        send_fp2(io, ker[1])
        P0 = read_point(io, E0, b"self.P0 = ")
        Q0 = read_point(io, E0, b"self.Q0 = ")
        for _ in range(16):
            s = randint(0, 3^b - 1)
            t = randint(0, 3^b - 1)
            psi = E0.isogeny(s * P0 + t * Q0, algorithm="factored")
            E2 = psi.codomain()
            io.recvuntil(b"Give me E2:\n")
            send_fp2(io, E2.a4())
            send_fp2(io, E2.a6())
            P2 = read_point(io, E2, b"self.P2 = ")
            Q2 = read_point(io, E2, b"self.Q2 = ")
            Kphi = psi(ker)
            phi2 = E2.isogeny(Kphi, algorithm="factored")
            E3 = phi2.codomain()
            P3, Q3 = phi2(P2), phi2(Q2)
            send_fp2(io, E3.a4())
            send_fp2(io, E3.a6())
            send_fp2(io, P3[0])
            send_fp2(io, P3[1])
            send_fp2(io, Q3[0])
            send_fp2(io, Q3[1])
            io.recvuntil(b"chall = ")
            chall = int(io.recvline().strip())
            io.recvuntil(b"Your response:\n")
            if chall == 1:
                send_fp2(io, Kphi[0])
                send_fp2(io, Kphi[1])
            else:
                c, d = challenge0_kernel(psi, E2, P2, Q2)
                io.sendline(f"{c},{d}".encode())
    io.interactive()

if __name__ == "__main__":
    main()
```

## 参考资料

- [题目归档 ZKPQC_1](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/0CTF/2024/crypto/ZKPQC_1)
- [ZKPQC_1 Writeup](https://github.com/sh1k4ku/ctf-challenge/tree/main/0CTF2024/ZKPQC1)
- [2024-0CTF-wp-crypto](https://tangcuxiaojikuai.xyz/post/b137586.html)
