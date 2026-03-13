---
title: 'RCTF 2025 - yet another shuffled MT game'
description: '先恢复 Python shuffle 的 128-bit seed，再反推出底层 MT 状态并完成后续求解。'
timeLabel: 2025
timeOrder: 2025
topic: 'RNG Attack'
competition: 'RCTF'
pubDate: 2026-03-11T16:45:00+08:00
---

题目代码：

```python
import os
from sage.all import set_random_seed, random_matrix, Zmod, ZZ, shuffle
import signal
FLAG = os.environ.get("FLAG", "RCTF{fake_flag}")
secret = os.urandom(64)
set_random_seed(int.from_bytes(secret, 'big'))

N_RUNS = 3
MACHINE_LIMIT = 16400
IS_BROKEN = False

def shuffle_int(num: int, nbits: int):
    bits = ZZ(num).digits(base = 2, padto = nbits)
    shuffle(bits)
    return ZZ(bits, 2)

def random_machine(mod: int, nrow: int, ncol: int) -> bytes:
    global IS_BROKEN
    nbits = (mod - 1).bit_length()
    outs = random_matrix(Zmod(mod), nrow, ncol).list()
    if IS_BROKEN:
        outs = [shuffle_int(x, nbits) for x in outs]
        shuffle(outs)
    print("🤖 Machine output:", outs)

print("✨ Yet Another Mersenne Twister Game ✨")
print("🤔 However, the random machine will break down if you extract too much randomness from it.")

leaked = 0
signal.alarm(60)
for i in range(N_RUNS):
    mod, nrow, ncol = map(int, input("✨ Enter mod and dimensions (space separated): ").split())
    if not(mod > 1 and nrow > 0 and ncol > 0):
        break
    nbits = (mod - 1).bit_length()
    leaked += nbits * nrow * ncol
    print(f"🔓 Total leaked randomness: {leaked} bits")
    if leaked > MACHINE_LIMIT and IS_BROKEN == False:
        IS_BROKEN = True
        print("💥 The machine has broken down due to too much randomness being extracted!")
    # print(IS_BROKEN)
    random_machine(mod, nrow, ncol)

guess = bytes.fromhex(input("🤔 secret (hex): ").strip())
if guess == secret:
    print(f"🎉 Correct! Here is your flag: {FLAG}")
```

跟上面的题目联系一下之后可以发现这个题目的MACHINE_LIMIT = 16400，小于19937，所以我们不能一次性按照上一题的流程解决这个问题。

但是我们注意到shuffle是使用 Sage 的随机状态（由 set_random_seed(int.from_bytes(secret, 'big')) 控制），通过 Python random.Random.shuffle 的 Fisher–Yates 算法，对列表就地均匀打乱，所以是由python的seed控制的。

回忆上一题我们在找random_matrix的代码逻辑的时候我们就注意到当n足够大的时候random_matrix调用的实际是python的randint，种子使用的是在python_random初始化时生成的一个128位的数字。他调用的是randint(0, mod-1)，整体逻辑就是getrandbits(ceil(mod-1.bit_length()))，然后取到大于这个数的就直接去掉。（这里不选2^32是因为他会向上取整到33）

那我们在想是否可以通过在选择模数的时候令这个mod等于2^32 -1，然后调用这个randint(0 , 2^32 -1)，来模拟getrandbits(32)的输出，然后还原出python的种子，那显然是可以的，当然可以无脑选择把所有的16400//32都用上，但是我们可以明确这个的下界在哪里。

我们先看到底怎么从？？个getrandbits(32)反推出种子，呃非常显然因为标准mt全是线性的，就是先加twist然后temper全部都是可逆的（这个会在下一篇讲，这一篇我先放个啥喵喵小工具，[random_breaker]:[CTF_Library/CTF_Library/Cryptography/MersenneTwister/python_random_breaker.py at master · Aeren1564/CTF_Library](https://github.com/Aeren1564/CTF_Library/blob/master/CTF_Library/Cryptography/MersenneTwister/python_random_breaker.py)，总之翻一翻源码就可以发现下界是234

还原出来验证之后我们就可以直接使用这个seed来模拟shuffle的操作，之后就和上面那个题目进行一样的操作就好了。

```python
from pwn import process, remote
from ast import literal_eval
from CTF_Library.Cryptography.MersenneTwister.python_random_breaker import python_random_breaker
import random
import gmpy2

def crackme(outputs):
    breaker = python_random_breaker()
    bit_len = 128
    is_exact = 1
    indices = [i for i in breaker.get_required_output_indices_for_integer_seed_recovery(bit_len, is_exact)]
    cur_outputs = [outputs[i] for i in indices]
    # print(indices)
    return (breaker.recover_all_integer_seeds_from_few_outputs(bit_len, cur_outputs, True)

io = process(["sage", "/root/rctf/yet-another-mt-game-v2.py"])

io.sendline(str(2**32 -1).encode() + b" 1 234")
io.recvuntil(b"output:")
output = literal_eval(io.recvline().decode())
seed = crackme(output)[0]
r = random.Random(seed)

for i in range(234):
    assert r.getrandbits(32) == output[i]
print(f"[+] {seed = }")

io.sendline(str(2).encode() + b" 1 2000")
io.recvuntil(b"output:")
output = literal_eval(io.recvline().decode())

n = 20000
indices = list(range(n))
r.shuffle(indices)
real_output = [None for i in range(n)]
for i in range(n):
    real_output[indices[i]] = output[i]
output = real_output
io.sendline(str(2).encode() + b" 1 1")

from gf2bv import LinearSystem
from gf2bv.crypto.mt import MT19937
from tqdm import tqdm
lin = LinearSystem([32] * 624)
mt = lin.gens()
rng = MT19937(mt)
zeros = [mt[0] & 0x7FFFFFFF]
for i in range(2000 - 624):
    rng.getrandbits(32)
rng.getrandbits(128)
rng.getrandbits(32)
for i in tqdm(range(len(output))):
    zeros.append((rng.getrandbits(32) & 1) ^ output[i])
print("COMPUTING INVERSE ")
P = 2**19937 - 20023
I = pow(1074888996 //12, -1, (P - 1)//12)
print("COMPUTED INVERSE ")
for sol in lin.solve_all(zeros):
    seed = 0
    for i in sol[1:][::-1]:
        seed = (seed << 32) | i
    if sol[0] == 0x80000000:
         seed |= 1<<19936
    print("COMPUTING POWER ")
    seed = gmpy2.powmod(seed, I, P)
    print("COMPUTED POWER ")
    seed, ok = gmpy2.iroot(seed, 12)

    if ok:
        seed -= 2
        print(hex(seed))
        io.sendlineafter(b"secret", int(seed).to_bytes(64, "big").hex().encode())
        io.interactive()
```
