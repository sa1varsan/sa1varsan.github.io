---
title: '0ctf 2024 - ZKPQC_2'
description: '利用最长公共前缀泄露先猜 coins，再做 RIPEMD-160 状态续接，把 hats 变成 Kyber secret 的格提示恢复 seed。'
timeLabel: 2024
timeOrder: 2024
topic: 'Post-Quantum Cryptography'
competition: '0ctf'
pubDate: 2026-03-14T10:45:00+08:00
---

```python
import ctypes
import hashlib
import os
from Crypto.Util.number import bytes_to_long, long_to_bytes
from random import randint
import signal
from secret import FLAG


def _handle_timeout(signum, frame):
    raise TimeoutError('function timeout')

timeout = 150
signal.signal(signal.SIGALRM, _handle_timeout)
signal.alarm(timeout)

q = 3329
k = 2


kyber_lib = ctypes.CDLL("./libpqcrystals_kyber512_ref.so")

def poly_ntt(p):
    t = (ctypes.c_int16 * int(256))(*list(p))
    kyber_lib.pqcrystals_kyber512_ref_ntt(t)
    t = list(t)
    return t


def polyvec_ntt(p):
    return list([poly_ntt(p) for p in p])


class Kyber:
    def __init__(self, pk = None, sk = None):
        if pk and len(pk) == 800:
            self.pk_buf = ctypes.c_buffer(pk)
        else:
            self.pk_buf = ctypes.c_buffer(800)
            self.sk_buf = ctypes.c_buffer(1632)
            kyber_lib.pqcrystals_kyber512_ref_keypair(self.pk_buf, self.sk_buf)


    def parse_sk(self):
        s_bytes = bytes(self.sk_buf)[:768]
        s_buf = ctypes.c_buffer(s_bytes)
        s_veck = (ctypes.c_int16 * int(k * 256))()
        kyber_lib.pqcrystals_kyber512_ref_polyvec_frombytes(s_veck, s_buf)
        return list(s_veck), s_bytes
    

    def encrypt2(self, m):
        ct_buf = ctypes.c_buffer(768)
        m_buf = ctypes.c_buffer(m)
        r = ctypes.c_buffer(os.urandom(32))
        kyber_lib.pqcrystals_kyber512_ref_indcpa_enc(ct_buf, m_buf, self.pk_buf, r)
        return bytes(ct_buf)
    

    def decrypt2(self, c):
        assert len(c) == 768
        ct_buf = ctypes.c_buffer(c)
        m_buf = ctypes.c_buffer(32)
        kyber_lib.pqcrystals_kyber512_ref_indcpa_dec(m_buf, ct_buf, self.sk_buf)
        return bytes(m_buf)
    

class my_shake:
    def __init__(self, seed = None):
        self.idx = 0
        self.state = b""
        self.HashOr4cle = hashlib.new("ripemd160") # hash_hash
        if seed:
            self._absorb(seed)
        else:
            self._absorb()
        self._squeeze()

    
    def _absorb(self, data):
        self.HashOr4cle.update(data)


    def _squeeze(self):
        self.state += self.HashOr4cle.digest()
    

    def next(self, L = 1, data = None):
        if data:
            self._absorb(data)
        while len(self.state) - self.idx < L:
            self._absorb(self.state)
            self._squeeze()
        stream = self.state[self.idx: self.idx+L]
        self.idx += L
        return stream
            

class ZKP:
    def __init__(self, inner: Kyber, outer: Kyber, shake = None):
        if shake:
            self.shake = shake
        else:
            seed = os.urandom(32)
            self.shake = my_shake(seed)
            
        self.inner = inner
        self.outer = outer
        self.CHALL_NUM = 137
        self.L = 0
        self.slice = 10
        self.coins = bin(bytes_to_long(self.shake.next(10)))[2:].zfill(8*self.slice)


    def _commit(self):
        print("Give me ciphertext of your string in hex: ")
        cipher = bytes.fromhex(input())
        assert len(cipher) == 768
        L = self.L
        self.commit = self.inner.decrypt2(cipher)
        pre = bin(bytes_to_long(self.commit))[2:]
        while len(self.coins) < len(pre):
            self.coins += bin(bytes_to_long(self.shake.next(10)))[2:].zfill(8*self.slice)
        for i in range(self.L, len(pre)):
            if pre[i] != self.coins[i]:
                break
            L = i+1
        Lc = self.outer.encrypt2(str(L).encode())
        print(f'Your water: {Lc.hex()}')


    def _challenge(self, c = None):
        if c is None:
            self.chall = randint(0,1)
        else:
            self.chall = c
        print(f'chall = {self.chall}')


    def _verify(self):
        print('Your response: ')
        resp = bytes.fromhex(input())
        pre_ = bin(bytes_to_long(self.inner.decrypt2(resp)))[2:]
        if len(self.coins) < len(pre_):
            self.coins += bin(bytes_to_long(self.shake.next(10)))[2:].zfill(8*self.slice)
        while self.chall and len(pre_) - self.L != 1:
            return False
        for i in range(self.L, len(pre_)):
            if pre_[i] != self.coins[i]:
                return False
        self.L = len(pre_)
        return True


    def run(self):
        self.chall_lst = [randint(0,1) for _ in range(self.CHALL_NUM)]
        while sum(self.chall_lst) == 0 or sum(self.chall_lst) == self.CHALL_NUM:
            self.chall_lst = [randint(0, 1) for _ in range(self.CHALL_NUM)]

        for _ in range(self.CHALL_NUM):
            print(f'Now, for the {_} round of zkp:')
            self._commit()
            self._challenge(self.chall_lst[_])
            if not self._verify():
                print('You failed!')
                return False

        tickets = []
        weight = (self.slice + 4) / (2**(self.slice//2))
        for _ in range(int(weight * self.L)):
            rubbish = bytes.fromhex(input("give me some rubbish: "))
            ticket = [_ for _ in self.shake.next(20, rubbish)]
            tickets.extend(ticket)
        svec, _ = self.inner.parse_sk()
        s = [svec[i*256:(i+1)*256] for i in range(k)]
        hats = []
        for i in range(len(tickets) // 2):
            hats.append(s[0][tickets[i]] + s[1][tickets[-i]])
        print(f"wow, there are too many hats: {hats}")
        print('give me your fruit: ')
        fruit = bytes.fromhex(input())
        return fruit


print("Welcome to the ZKPQC challenge!")
print("Please provide your public key in hex: ")
pk = bytes.fromhex(input())
print(f"{len(pk) = }")
alice = Kyber(pk)
bob = Kyber()
print("This is my public key:", bob.pk_buf.raw.hex())
seed = os.urandom(32)
leaf = bob.encrypt2(seed)
print("This is your leaf:", leaf.hex())
shake = my_shake(seed)
print("Now, can you prove me you know the coins?")
zkp = ZKP(bob, alice, shake)
fruit = zkp.run()
if fruit == seed:
    print("Congratulations! Here is your flag:", FLAG)
else:
    print("You failed!")
```

## 题目解析

这题的外壳是个 ZKP，真正的漏洞点却分成三层。第一层是 `water`。服务端会把你提交的密文在 `inner.decrypt2()` 后转成二进制串，然后只把它和 `coins` 的最长公共前缀长度 `L` 回给你，而且这个 `L` 还是用你自己的 `outer` 公钥加密的。也就是说，你完全可以自己生成一对 Kyber 密钥，把公钥交给服务端，然后把每一轮的 `water` 解开，拿到精确的前缀长度。

第二层是 `my_shake`。它看起来像个自定义 XOF，实际上底层就是 RIPEMD-160 的 Merkle-Damgard 迭代：先吸收 `seed`，再不断把当前 `state` 自己喂回去。只要你在前 137 轮里把前 160 bit `coins` 猜出来，就能稳稳过完 PoK；更关键的是，后面 `rubbish` 会继续喂进同一个哈希状态，所以可以直接做长度扩展，把之后生成的 ticket 字节也一并预测出来。

最后一层是 `hats`。它输出的是 NTT 域里两个多项式某些位置上的和：

$$
\text{hat}_i = \hat s_0[a_i] + \hat s_1[b_i].
$$

这里可以直接改写成线性问题。Kyber 的 `q = 3329` 有 256 次单位根 `17`，NTT 可以视为一个特殊的 Vandermonde 变换，所以 `hats` 可以重写成模 `q` 的线性方程。虽然这些方程本身不满秩，但再结合公开钥里泄露的

$$
t = A s + e \pmod q
$$

就足够做格攻击，把 `s` 恢复出来，再去解 `leaf` 得到最终 `seed`。

## 解题思路

整题就是三步。先利用最长公共前缀 oracle，把第一个 RIPEMD-160 digest 对应的 160 bit `coins` 全猜出来；这一步 137 轮足够，而且不能继续贪心猜太长，不然后面的状态就不再可控。然后根据 RIPEMD-160 的 padding 和长度扩展规则，自己离线推演 `rubbish` 之后的哈希状态，把所有 ticket 下标都还原出来。最后把 `hats` 展开成关于 `\hat s` 的线性提示，再结合 `t = As + e` 调 solve 目录里的格工具恢复 `s`，用它解开 `leaf` 就结束了。

## 解题脚本

下面这份 `exp.py` 就是 solve 目录里的主脚本。主脚本本身就够看清整条利用链，辅助模块按同目录里的 `kyber_util.py` 和 `lwe_lattice.py` 放一起即可。

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
import ctypes
import hashlib
import os
import struct
import hashlib
from random import randint
from tqdm import trange
from kyber_util import *
import numpy as np
from lwe_lattice import *
from sage.all import matrix, Zmod, vector
import time

is_term = True
for key, value in os.environ.items():
    if key == "TERM":
        is_term = False
if is_term:
    os.environ["TERM"] = "xterm"
from pwn import remote, process, context


q = 3329
k = 2


def u32(n):
    return n & 0xFFFFffff

rho = [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]
pi = [(9*i + 5) & 15 for i in range(16)]
rl = [range(16)]
rl += [[rho[j] for j in rl[-1]]]
rl += [[rho[j] for j in rl[-1]]]
rl += [[rho[j] for j in rl[-1]]]
rl += [[rho[j] for j in rl[-1]]]
rr = [list(pi)]
rr += [[rho[j] for j in rr[-1]]]
rr += [[rho[j] for j in rr[-1]]]
rr += [[rho[j] for j in rr[-1]]]
rr += [[rho[j] for j in rr[-1]]]

f1 = lambda x, y, z: x ^ y ^ z
f2 = lambda x, y, z: (x & y) | (~x & z)
f3 = lambda x, y, z: (x | ~y) ^ z
f4 = lambda x, y, z: (x & z) | (y & ~z)
f5 = lambda x, y, z: x ^ (y | ~z)
fl = [f1, f2, f3, f4, f5]
fr = [f5, f4, f3, f2, f1]

_shift1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8]
_shift2 = [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7]
_shift3 = [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9]
_shift4 = [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6]
_shift5 = [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]
sl = [[_shift1[rl[0][i]] for i in range(16)]]
sl.append([_shift2[rl[1][i]] for i in range(16)])
sl.append([_shift3[rl[2][i]] for i in range(16)])
sl.append([_shift4[rl[3][i]] for i in range(16)])
sl.append([_shift5[rl[4][i]] for i in range(16)])
sr = [[_shift1[rr[0][i]] for i in range(16)]]
sr.append([_shift2[rr[1][i]] for i in range(16)])
sr.append([_shift3[rr[2][i]] for i in range(16)])
sr.append([_shift4[rr[3][i]] for i in range(16)])
sr.append([_shift5[rr[4][i]] for i in range(16)])

_kg = lambda x, y: int(2**30 * (y ** (1.0 / x)))
KL = [0, _kg(2, 2), _kg(2, 3), _kg(2, 5), _kg(2, 7)]
KR = [_kg(3, 2), _kg(3, 3), _kg(3, 5), _kg(3, 7), 0]

def rol(s, n):
    return u32((n << s) | (n >> (32-s)))

def box(h, f, k, x, r, s):
    (a, b, c, d, e) = h
    for word in range(16):
        T = u32(a + f(b, c, d) + x[r[word]] + k)
        T = u32(rol(s[word], T) + e)
        (b, c, d, e, a) = (T, b, rol(10, c), d, e)
    return (a, b, c, d, e)

def _compress(h, x):
    hl = hr = h
    for round in range(5):
        hl = box(hl, fl[round], KL[round], x, rl[round], sl[round])
        hr = box(hr, fr[round], KR[round], x, rr[round], sr[round])
    h = (
        u32(h[1] + hl[2] + hr[3]),
        u32(h[2] + hl[3] + hr[4]),
        u32(h[3] + hl[4] + hr[0]),
        u32(h[4] + hl[0] + hr[1]),
        u32(h[0] + hl[1] + hr[2]),
    )
    return h

def compress(h, s):
    p = 0
    while p < len(s):
        h = _compress(h, struct.unpack("<16L", s[p:p+64]))
        p += 64
    return h

def update(data, ripe_h, ripe_bytes, ripe_buf):
    ripe_buf += data
    ripe_bytes += len(data)
    p = len(ripe_buf) & ~63
    if p > 0:
        ripe_h = compress(ripe_h, ripe_buf[:p])
        ripe_buf = ripe_buf[p:]
    return (ripe_h, ripe_bytes, ripe_buf)

def digest(ripe_h, ripe_bytes, ripe_buf, initial_length=64):
    length = ((ripe_bytes + initial_length) << 3) & (2**64-1)
    data = ripe_buf + b"\x80"
    if len(data) <= 56:
        data = struct.pack("<56sQ", data, length)
    else:
        data = struct.pack("<120sQ", data, length)
    h = compress(ripe_h, data)
    return struct.pack("<5L", *h)

def make_padding(length):
    tmp = [0x80] + [0x00] * 63
    if length % 64 < 56:
        padding = tmp[0:(56-length % 64)]
    else:
        padding = tmp[0:(64+56-length % 64)]
    length = (length << 3)
    for i in range(8):
        padding.append((length >> (8*i)) % 256)
    return padding

def gen_initial_length(L):
    buf_length = L % 64 + 1
    if buf_length <= 56:
        return L - (L % 64) + 64
    return L - (L % 64) + 128

kyber_lib = ctypes.CDLL("./libpqcrystals_kyber512_ref.so")

class Kyber:
    def __init__(self, pk=None, sk=None):
        if pk and len(pk) == 800:
            self.pk_buf = ctypes.c_buffer(pk)
            if sk:
                self.sk_buf = ctypes.c_buffer(sk)
        else:
            self.pk_buf = ctypes.c_buffer(800)
            self.sk_buf = ctypes.c_buffer(1632)
            kyber_lib.pqcrystals_kyber512_ref_keypair(self.pk_buf, self.sk_buf)

    def parse_sk(self):
        s_bytes = bytes(self.sk_buf)[:768]
        s_buf = ctypes.c_buffer(s_bytes)
        s_veck = (ctypes.c_int16 * int(k * 256))()
        kyber_lib.pqcrystals_kyber512_ref_polyvec_frombytes(s_veck, s_buf)
        return list(s_veck), s_bytes

    def encrypt2(self, m):
        ct_buf = ctypes.c_buffer(768)
        m_buf = ctypes.c_buffer(m)
        r = ctypes.c_buffer(os.urandom(32))
        kyber_lib.pqcrystals_kyber512_ref_indcpa_enc(ct_buf, m_buf, self.pk_buf, r)
        return bytes(ct_buf)

    def decrypt2(self, c):
        ct_buf = ctypes.c_buffer(c)
        m_buf = ctypes.c_buffer(32)
        kyber_lib.pqcrystals_kyber512_ref_indcpa_dec(m_buf, ct_buf, self.sk_buf)
        return bytes(m_buf)

def pad_msg(guess):
    guess = long_to_bytes(guess)
    return b'\x00' * (32 - len(guess)) + guess

def commit_round(guess, conn, alice, bob):
    def parse_gift(gift):
        idx = 1
        while gift[idx:idx+1] != b"\x00":
            idx += 1
        return int(gift[:idx].decode())

    conn.recvuntil(b"Give me ciphertext of your string in hex: \n")
    conn.sendline(bob.encrypt2(pad_msg(guess)).hex().encode())
    tmp = conn.recvline()
    if b"water" not in tmp:
        return None
    return parse_gift(alice.decrypt2(bytes.fromhex(tmp.strip().decode().split(": ")[1])))

def run(conn, alice, bob):
    CHALL_NUM = 137
    stream = ''
    resp = ''
    sli = 10
    passed = False
    for i in trange(CHALL_NUM):
        streamL = len(stream)
        respL = len(resp)
        if 160 - respL < CHALL_NUM - i:
            return False
        elif 160 - respL == CHALL_NUM - i and not passed:
            passed = True
            sli = 1
        guess = int(stream + '1' * sli, 2)
        commitL = commit_round(guess, conn, alice, bob)
        if i == 0 and commitL == 0:
            return False
        if commitL == sli + streamL:
            stream += '1' * sli
        elif commitL > streamL:
            stream += '1' * (commitL - streamL)
            stream += '0'
        else:
            stream += '0'
        chall = int(conn.recvline().strip().decode().split(" = ")[1])
        resp = stream[:respL+1] if chall else stream
        conn.recvuntil(b'Your response: ')
        conn.sendline(bob.encrypt2(pad_msg(int(resp, 2))).hex().encode())
    return long_to_bytes(int(resp, 2)) if len(resp) == 160 and passed else False

def lwe_with_hint(idxs, shats, pk):
    def rotMatrix(poly):
        n = len(poly)
        A = np.array([[0] * n for _ in range(n)])
        for i in range(n):
            for j in range(n):
                A[i][j] = (1 if j >= i else -1) * poly[(j - i) % n]
        return A

    def format_A(A):
        return np.block([[rotMatrix(list(A[i][j])) for j in range(k)] for i in range(k)])

    def transpose(A):
        A[0][1], A[1][0] = A[1][0], A[0][1]
        return A

    def bit_reverse(i, N=256):
        return int('{:0{w}b}'.format(i, w=N.bit_length() - 1)[::-1], 2)

    def modq_hints():
        zeta = 17
        elems = [pow(zeta, bit_reverse(i) + 1, q) for i in range(N // 2)]
        Z = [[0] * N for _ in range(N)]
        for i in range(N):
            for j in range(N):
                if (i + j) % 2 == 0:
                    Z[i][j] = pow(elems[i // 2], j // 2, q)
        V, l = [], []
        for i in range(len(idxs) // 2):
            tmp = Z[idxs[i]][:]
            tmp.extend(Z[idxs[-i]][:])
            V.append(tmp)
            l.append(shats[i])
        Vm = matrix(Zmod(q), V)
        rank_V = Vm.rank()
        Vp = Vm.rref()[0:rank_V, :]
        U = Vm.solve_left(Vp)
        lp = U * vector(Zmod(q), l)
        return [[int(_) for _ in row] for row in Vp], [int(_) for _ in lp]

    t, A_seed = unpack_pk(pk)
    A = gen_matrix(A_seed)
    t = polyvec_invntt(t)
    A = [polyvec_invntt(a) for a in A]
    t = np.array(list(t[0]) + list(t[1]))
    A = format_A(transpose(A))
    V, l = modq_hints()
    if len(V) < 475:
        return None
    lattice = LWELattice(A, t, q, verbose=True)
    for i in range(len(V)):
        lattice.integrateModularHint(V[i], l[i] % q, q)
    lattice.reduce(maxBlocksize=40)
    return list(lattice.s)

alice = Kyber()
while True:
    conn = remote("instance.penguin.0ops.sjtu.cn", 18435)
    conn.recvuntil(b'Please provide your public key in hex: \n')
    conn.sendline(alice.pk_buf.raw.hex().encode())
    conn.recvuntil(b"This is ")
    bob_pk = bytes.fromhex(conn.recvline().strip().decode().split(": ")[1])
    leaf = bytes.fromhex(conn.recvline().strip().decode().split(": ")[1])
    bob = Kyber(pk=bob_pk)
    coins = run(conn, alice, bob)
    if not coins:
        conn.close()
        continue

    L = 32
    dst = coins
    msg = b''
    idxs = []
    for _ in trange(70):
        conn.recvuntil(b"give me some rubbish: ")
        pad_ = make_padding(L)
        initial_length = gen_initial_length(L)
        rubbish = bytes.fromhex(''.join(f'{x:02x}' for x in pad_))
        L += len(rubbish)
        conn.sendline(rubbish.hex().encode())
        initial_h = tuple(struct.unpack("<5L", dst))
        msg += dst
        ripe_h, ripe_bytes, ripe_buf = update(msg, initial_h, 0, b"")
        dst = digest(ripe_h, ripe_bytes, ripe_buf, initial_length)
        idxs.extend([_ for _ in dst])
        L += len(msg)

    shats = eval(conn.recvline().strip().decode().split(": ")[1])
    ss = lwe_with_hint(idxs, shats, bob_pk)
    if ss is None:
        conn.close()
        continue

    ss = [ss[i*256:(i+1)*256] for i in range(k)]
    shat = polyvec_ntt(ss)
    s_bytes = polyvec_to_bytes(shat)
    seed = Kyber(pk=bob_pk, sk=s_bytes).decrypt2(leaf)
    conn.recvuntil(b"give me your fruit: \n")
    conn.sendline(seed.hex().encode())
    res = conn.recvall()
    if b"flag" in res:
        print(res.decode(errors="ignore"))
        break
```

## 参考资料

- [题目归档 ZKPQC_2](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/0CTF/2024/crypto/ZKPQC_2)
- [Writeup ZKPQC_2](https://github.com/sh1k4ku/ctf-challenge/tree/main/0CTF2024/ZKPQC2)
- [Kyber 规范](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf)
- [格攻击参考](https://eprint.iacr.org/2023/777)
