---
title: 'RCTF 2025 - yet-another-mt-game'
description: '从 Sage randstate 和 GMP/MT19937 的实现细节出发，搭线性方程恢复内部种子。'
timeLabel: 2025
timeOrder: 2025
topic: 'RNG Attack'
competition: 'RCTF'
pubDate: 2026-03-11T16:45:00+08:00
---

sage: set_random_seed??

```bash
sage: set_random_seed??
sage: Signature:      set_random_seed(seed=None)
Call signature: set_random_seed(*args, **kwds)
Type:           cython_function_or_method
String form:    <cyfunction set_random_seed at 0x75f28fdab850>
File:           ~/miniforge3/envs/sage107/lib/python3.11/site-packages/sage/misc/randstate.pyx
Source:
cpdef set_random_seed(seed=None):
    r"""
    Set the current random number seed from the given ``seed``
    (which must be coercible to a Python long).

    If no seed is given, then a seed is automatically selected
    using :func:`os.urandom` if it is available, or the current
    time otherwise.

    Type ``sage.misc.randstate?`` for much more
    information on random numbers in Sage.

    This function is only intended for command line use.  Never call
    this from library code; instead, use ``with seed(s):``.

    Note that setting the random number seed to 0 is much faster than
    using any other number.

    EXAMPLES::

        sage: set_random_seed(5)
        sage: initial_seed()
        5
    """
    global _current_randstate
    _current_randstate = randstate(seed)
Init docstring: Initialize self.  See help(type(self)) for accurate signature.
Call docstring: Call self as a function.
(END)
```

在路径miniforge3/envs/sage107/lib/python3.11/site-packages/sage/misc/randstate.pyx下找到了randstate的定义：

```python
cdef class randstate:
    r"""
    The :class:`randstate` class.  This class keeps track of random number
    states and seeds.  Type ``sage.misc.randstate?`` for much more
    information on random numbers in Sage.
    """
    def __cinit__(self, *args, **opts):
        """
        Initialise c-data for randstate, in a fail-safe way.

        TESTS:

        The following used to segfault (see :issue:`10113`). Now,
        there is a proper type error::

            sage: seed(1,2)   # indirect doctest
            Traceback (most recent call last):
            ...
            TypeError: ...__init__() takes at most 1 positional argument (2 given)

        AUTHOR:

        - Simon King <simon.king@uni-jena.de>
        """
        gmp_randinit_default(self.gmp_state)

    def __init__(self, seed=None):
        r"""
        Initialize a new :class:`randstate` object with the given seed
        (which must be coercible to a Python long).

        If no seed is given, then a seed is automatically selected
        using :func:`os.urandom` if it is available, or the current
        time otherwise.

        EXAMPLES::

            sage: from sage.misc.randstate import randstate
            sage: r = randstate(54321); r
            <sage.misc.randstate.randstate object at 0x...>
            sage: r.seed()
            54321
            sage: r = randstate(); r
            <sage.misc.randstate.randstate object at 0x...>
            sage: r.seed()     # random
            305866218880103397618377824640007711767

        Note that creating a :class:`randstate` with a seed of 0
        is vastly faster than any other seed (over a thousand times
        faster in my test). ::

            sage: timeit('randstate(0)') # random
            625 loops, best of 3: 1.38 us per loop
            sage: timeit('randstate(1)') # random
            125 loops, best of 3: 3.59 ms per loop
        """
        cdef mpz_t mpz_seed

        if seed is None:
            if use_urandom:
                seed = int(binascii.hexlify(os.urandom(16)), 16)
            else:
                seed = int(time.time() * 256)
        else:
            seed = int(seed)

        # If seed==0, leave it at the default seed used by
        # gmp_randinit_default()
        if seed:
            mpz_init(mpz_seed)
            mpz_set_pylong(mpz_seed, seed)
            gmp_randseed(self.gmp_state, mpz_seed)
            mpz_clear(mpz_seed)

        self._seed = seed

    def seed(self):
        r"""
        Return the initial seed of a :class:`randstate` object.  (This is not
        the current state; it does not change when you get random
        numbers.)

        EXAMPLES::

            sage: set_random_seed(0)
            sage: from sage.misc.randstate import randstate
            sage: r = randstate(314159)
            sage: r.seed()
            314159
            sage: r.python_random().random()
            0.111439293741037
            sage: r.seed()
            314159
        """
        return self._seed

    def python_random(self, cls=None, seed=None):
        r"""
        Return a :class:`random.Random` object.  The first time it is
        called on a given :class:`randstate`, a new :class:`random.Random`
        is created (seeded from the *current* :class:`randstate`);
        the same object is returned on subsequent calls.

        It is expected that ``python_random`` will only be
        called on the current :class:`randstate`.

        INPUT:

        - ``cls`` -- (optional) a class with the same interface as
          :class:`random.Random` (e.g. a subclass thereof) to use as the
          Python RNG interface.  Otherwise the standard :class:`random.Random`
          is used.

        - ``seed`` -- (optional) an integer to seed the :class:`random.Random`
          instance with upon creation; if not specified it is seeded using
          ``ZZ.random_element(1 << 128)``.

        EXAMPLES::

            sage: set_random_seed(5)
            sage: rnd = current_randstate().python_random()
            sage: rnd.random()
            0.013558022446944151
            sage: rnd.randrange(1000)
            544
        """

        if cls is None:
            cls = DEFAULT_PYTHON_RANDOM

        if type(self._python_random) is cls:
            return self._python_random

        from sage.rings.integer_ring import ZZ
        rand = cls()
        if seed is None:
            rand.seed(int(ZZ.random_element(1<<128)))
        else:
            rand.seed(int(seed))
        self._python_random = rand
        return rand

    cpdef ZZ_seed(self):
        r"""
        When called on the current :class:`randstate`, returns a 128-bit
        :mod:`Integer <sage.rings.integer_ring>` suitable for seeding another
        random number generator.

        EXAMPLES::

            sage: set_random_seed(1414)
            sage: current_randstate().ZZ_seed()
            48314508034782595865062786044921182484
        """
        from sage.rings.integer_ring import ZZ
        return ZZ.random_element(1<<128)

    cpdef long_seed(self):
        r"""
        When called on the current :class:`randstate`, returns a 128-bit
        Python long suitable for seeding another random number generator.

        EXAMPLES::

            sage: set_random_seed(1618)
            sage: current_randstate().long_seed()
            256056279774514099508607350947089272595
        """
        from sage.rings.integer_ring import ZZ
        return int(ZZ.random_element(1<<128))

    cpdef set_seed_libc(self, bint force):
        r"""
        Check to see if ``self`` was the most recent :class:`randstate`
        to seed the libc random number generator.  If not, seeds the
        libc random number generator.  (Do not use the libc random
        number generator if you have a choice; its randomness is poor,
        and the random number sequences it produces are not portable
        across operating systems.)

        If the argument ``force`` is ``True``, seeds the generator
        unconditionally.

        EXAMPLES::

            sage: from sage.misc.randstate import _doctest_libc_random
            sage: set_random_seed(0xBAD)
            sage: current_randstate().set_seed_libc(False)
            sage: _doctest_libc_random()   # random
            1070075918
        """
        global _libc_seed_randstate
        if force or _libc_seed_randstate is not self:
            c_libc_srandom(gmp_urandomb_ui(self.gmp_state, sizeof(int)*8))
            _libc_seed_randstate = self

    cpdef set_seed_ntl(self, bint force):
        r"""
        Check to see if ``self`` was the most recent :class:`randstate`
        to seed the NTL random number generator.  If not, seeds
        the generator.  If the argument ``force`` is ``True``,
        seeds the generator unconditionally.

        EXAMPLES::

            sage: set_random_seed(2008)

        This call is actually redundant; :func:`ntl.ZZ_random` will
        seed the generator itself.  However, we put the call in
        to make the coverage tester happy. ::

            sage: current_randstate().set_seed_ntl(False)
            sage: ntl.ZZ_random(10^40)
            1495283511775355459459209288047895196007
        """
        global _ntl_seed_randstate
        if force or _ntl_seed_randstate is not self:
            import sage.libs.ntl.ntl_ZZ as ntl_ZZ
            from sage.rings.integer_ring import ZZ
            ntl_ZZ.ntl_setSeed(ZZ.random_element(1<<128))
            _ntl_seed_randstate = self

    def set_seed_gap(self):
        r"""
        Check to see if ``self`` was the most recent :class:`randstate`
        to seed the GAP random number generator.  If not, seeds
        the generator.

        EXAMPLES::

            sage: set_random_seed(99900000999)
            sage: current_randstate().set_seed_gap()
            sage: gap.Random(1, 10^50)
            1496738263332555434474532297768680634540939580077
            sage: gap(35).SCRRandomString()
            [ 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1,
              1, 0, 0, 1, 1, 1, 1, 1, 0, 1 ]
        """
        global _gap_seed_randstate
        if _gap_seed_randstate is not self:
            from sage.interfaces.gap import gap

            if self._gap_saved_seed is not None:
                mersenne_seed, classic_seed = self._gap_saved_seed
            else:
                from sage.rings.integer_ring import ZZ
                seed = ZZ.random_element(1<<128)
                classic_seed = seed
                mersenne_seed = seed

            prev_mersenne_seed = gap.Reset(gap.GlobalMersenneTwister, mersenne_seed)
            prev_classic_seed = gap.Reset(gap.GlobalRandomSource, classic_seed)

            if _gap_seed_randstate is not None:
                _gap_seed_randstate._gap_saved_seed = \\
                    prev_mersenne_seed, prev_classic_seed

            _gap_seed_randstate = self

    def set_seed_gp(self, gp=None):
        r"""
        Check to see if ``self`` was the most recent :class:`randstate`
        to seed the random number generator in the given instance
        of gp.  (If no instance is given, uses the one in
        :class:`gp <sage.interfaces.gp.Gp>`.)  If not, seeds the generator.

        EXAMPLES::

            sage: set_random_seed(987654321)
            sage: current_randstate().set_seed_gp()
            sage: gp.random()
            23289294
        """
        if gp is None:
            import sage.interfaces.gp
            gp = sage.interfaces.gp.gp

        cdef randstate prev

        try:
            prev = _gp_seed_randstates[gp]
        except KeyError:
            prev = None

        if prev is not self:
            if self._gp_saved_seeds is not None and gp in self._gp_saved_seeds:
                seed = self._gp_saved_seeds[gp]
            else:
                seed = self.c_random()

            prev_seed = gp.getrand()
            gp.setrand(seed)

            if prev is not None:
                if prev._gp_saved_seeds is None:
                    prev._gp_saved_seeds = weakref.WeakKeyDictionary()
                prev._gp_saved_seeds[gp] = prev_seed

            _gp_seed_randstates[gp] = self

    def set_seed_pari(self):
        r"""
        Check to see if ``self`` was the most recent :class:`randstate` to
        seed the Pari random number generator.  If not, seeds the
        generator.

        .. NOTE::

           Since pari 2.4.3, pari's random number generator has
           changed a lot.  the seed output by getrand() is now a
           vector of integers.

        EXAMPLES::

            sage: set_random_seed(5551212)
            sage: current_randstate().set_seed_pari()
            sage: pari.getrand().type()
            't_INT'
        """
        global _pari_seed_randstate
        if _pari_seed_randstate is not self:
            from sage.libs.pari import pari

            if self._pari_saved_seed is not None:
                seed = self._pari_saved_seed
            else:
                seed = self.c_random()

            prev_seed = pari.getrand()
            pari.setrand(seed)

            if _pari_seed_randstate is not None:
                _pari_seed_randstate._pari_saved_seed = prev_seed

            _pari_seed_randstate = self

    cpdef int c_random(self) noexcept:
        r"""
        Return a 31-bit random number.  Intended for internal
        use only; instead of calling ``current_randstate().c_random()``,
        it is equivalent (but probably faster) to call the
        :meth:`random <sage.misc.randstate.random>` method of this
        :class:`randstate` class.

        EXAMPLES::

            sage: set_random_seed(1207)
            sage: current_randstate().c_random()
            2008037228

        We verify the equivalence mentioned above. ::

            sage: from sage.misc.randstate import random
            sage: set_random_seed(1207)
            sage: random()
            2008037228
        """
        return gmp_urandomb_ui(self.gmp_state, 31)

    cpdef double c_rand_double(self) noexcept:
        r"""
        Return a random floating-point number between 0 and 1.

        EXAMPLES::

            sage: set_random_seed(2718281828)
            sage: current_randstate().c_rand_double()
            0.22437207488974298
        """
        cdef double a = gmp_urandomb_ui(self.gmp_state, 25) * (1.0 / 33554432.0)  # divide by 2^25
        cdef double b = gmp_urandomb_ui(self.gmp_state, 28) * (1.0 / 9007199254740992.0)  # divide by 2^53
        return a+b

    def __dealloc__(self):
        r"""
        Free up the memory from the ``gmp_randstate_t`` in a
        :class:`randstate`.

        EXAMPLES::

            sage: from sage.misc.randstate import randstate
            sage: foo = randstate()
            sage: foo = None
        """
        gmp_randclear(self.gmp_state)

    def __enter__(self):
        r"""
        Use a :class:`randstate` object as a ``with`` statement context
        manager; switches this :class:`randstate` to be the current
        :class:`randstate`, to be switched back on exit from the ``with``
        statement.

        For this purpose, we usually use the ``seed`` alias for
        :class:`randstate`.

        EXAMPLES::

            sage: from sage.misc.randstate import randstate
            sage: seed is randstate
            True
            sage: set_random_seed(-12345)
            sage: ZZ.random_element(10^30)
            197130468050826967386035500824
            sage: ZZ.random_element(10^30)
            601704412330400807050962541983
            sage: set_random_seed(-12345)
            sage: ZZ.random_element(10^30)
            197130468050826967386035500824
            sage: with seed(12345):
            ....:     ZZ.random_element(10^30)
            197130468050826967386035500824
            sage: ZZ.random_element(10^30)
            601704412330400807050962541983
        """
        global _current_randstate
        randstate_stack.append(_current_randstate)
        _current_randstate = self
        return self

    def __exit__(self, ty, value, traceback):
        r"""
        Use a :class:`randstate` object as a ``with`` statement context
        manager; restores the previous :class:`randstate` as the current
        :class:`randstate`.

        For this purpose, we usually use the ``seed`` alias for
        :class:`randstate`.

        EXAMPLES::

            sage: from sage.misc.randstate import randstate
            sage: seed is randstate
            True
            sage: set_random_seed(-12345)
            sage: ZZ.random_element(10^30)
            197130468050826967386035500824
            sage: ZZ.random_element(10^30)
            601704412330400807050962541983
            sage: set_random_seed(-12345)
            sage: ZZ.random_element(10^30)
            197130468050826967386035500824
            sage: with seed(12345):
            ....:     ZZ.random_element(10^30)
            197130468050826967386035500824
            sage: ZZ.random_element(10^30)
            601704412330400807050962541983
        """
        global _current_randstate
        _current_randstate = randstate_stack.pop()
        return False
```

由于set_random_seed没有对实例化的randstate对象进行其他操作，所以我们只需要关注他的init函数，

```python
def __init__(self, seed=None):
    cdef mpz_t mpz_seed

    if seed is None:
        if use_urandom:
            seed = int(binascii.hexlify(os.urandom(16)), 16)
        else:
            seed = int(time.time() * 256)
    else:
        seed = int(seed)

    # If seed==0, leave it at the default seed used by
    # gmp_randinit_default()
    if seed:
        mpz_init(mpz_seed)
        mpz_set_pylong(mpz_seed, seed)
        gmp_randseed(self.gmp_state, mpz_seed)
        mpz_clear(mpz_seed)

    self._seed = seed
```

阅读整个函数发现实际对seed进行操作的是gmp_randseed函数，这里里的 gmp_randseed 不是在这个文件里定义的，而是通过 Cython cimport 从 GMP 库里来的。

在 randstate.pyx 里有：from sage.libs.gmp.all cimport *,这个 all.pxd 再导入 sage.libs.gmp.random，其中文件
sage/libs/gmp/random.pxd（路径：
/root/miniforge3/envs/sage107/lib/python3.11/site-packages/sage/libs/gmp/random.pxd）里有声明：`cdef extern from "gmp.h":    void gmp_randseed (gmp_randstate_t state, mpz_t seed)` ，真正的实现在系统的 GMP C 库中，对应头文件例如 /usr/include/x86_64-linux-gnu/gmp.h，函数体在 libgmp 的源码里。

然后我下了 GMP 6.3.0的源码，函数体在：
gmp-6.3.0/rand/randsd.c (line 24)

核心代码是：

```c
void
gmp_randseed (gmp_randstate_ptr rstate,
              mpz_srcptr seed)
{
  (*((gmp_randfnptr_t *) RNG_FNPTR (rstate))->randseed_fn) (rstate, seed);
}
```

也就是说它只是把调用转发给当前随机算法的 randseed_fn 函数指针，它只是通过 RNG_FNPTR(rstate)->randseed_fn 间接调用真正的 seeding 函数。

gmp_randfnptr_t 在 gmp-6.3.0/gmp-impl.h (line 1353) 定义：

```c
typedef struct {
  void (*randseed_fn) (gmp_randstate_ptr, mpz_srcptr);
  void (*randget_fn) (gmp_randstate_ptr, mp_ptr, unsigned long int);
  void (*randclear_fn) (gmp_randstate_ptr);
  void (*randiset_fn) (gmp_randstate_ptr, gmp_randstate_srcptr);
} gmp_randfnptr_t;

#define RNG_FNPTR(rstate) ((rstate)->_mp_algdata._mp_lc)
```

对默认的 Mersenne Twister 生成器，函数指针表在gmp-6.3.0/rand/randmts.c (line 90)：

```c
static const gmp_randfnptr_t Mersenne_Twister_Generator = {
  randseed_mt,
  __gmp_randget_mt,
  __gmp_randclear_mt,
  __gmp_randiset_mt
};

void
gmp_randinit_mt (gmp_randstate_ptr rstate)
{
  __gmp_randinit_mt_noseed (rstate);
  RNG_FNPTR (rstate) = (void *) &Mersenne_Twister_Generator;
}
```

这里 randseed_fn 字段就是 randseed_mt。真正的算法实现函数 randseed_mt 在同一文件gmp-6.3.0/rand/randmts.c (line 56) 起始：

```c
static void
randseed_mt (gmp_randstate_ptr rstate, mpz_srcptr seed)
{
  int i;
  size_t cnt;

  gmp_rand_mt_struct *p;
  mpz_t mod;    /* Modulus.  */
  mpz_t seed1;  /* Intermediate result.  */

  p = (gmp_rand_mt_struct *) RNG_STATE (rstate);

  mpz_init2 (mod, 19938L);
  mpz_init2 (seed1, 19937L);

  mpz_setbit (mod, 19937L);
  mpz_sub_ui (mod, mod, 20027L);
  mpz_mod (seed1, seed, mod);	/* Reduce `seed' modulo `mod'.  */
  mpz_clear (mod);
  mpz_add_ui (seed1, seed1, 2L);	/* seed1 is now ready.  */
  mangle_seed (seed1);	/* Perform the mangling by powering.  */

  /* Copy the last bit into bit 31 of mt[0] and clear it.  */
  p->mt[0] = (mpz_tstbit (seed1, 19936L) != 0) ? 0x80000000 : 0;
  mpz_clrbit (seed1, 19936L);

  /* Split seed1 into N-1 32-bit chunks.  */
  mpz_export (&p->mt[1], &cnt, -1, sizeof (p->mt[1]), 0,
              8 * sizeof (p->mt[1]) - 32, seed1);
  mpz_clear (seed1);
  cnt++;
  ASSERT (cnt <= N);
  while (cnt < N)
    p->mt[cnt++] = 0;

  /* Warm the generator up if necessary.  */
  if (WARM_UP != 0)
    for (i = 0; i < WARM_UP / N; i++)
      __gmp_mt_recalc_buffer (p->mt);

  p->mti = WARM_UP % N;
}
```

阅读起来大概是这个意思：
先定义一个大的模数M1 = 2^19937 - 20027。然后做：`seed1 = seed mod M1 + 2` ，再用另一个模数，`M2 = 2^19937 - 20023  e  = 1074888996`做：`seed2 = (seed1^e) mod M2` 。

seed2 被拆成许多 32 位块，填进 gmp_rand_mt_struct 里的 mt[] 数组，作为 MT 的初始状态，拆解函数如下:

```
/* Copy the last bit into bit 31 of mt[0] and clear it.  */
p->mt[0] = (mpz_tstbit (seed1, 19936L) != 0) ? 0x80000000 : 0;
mpz_clrbit (seed1, 19936L);

/* Split seed1 into N-1 32-bit chunks.  */
mpz_export (&p->mt[1], &cnt, -1, sizeof (p->mt[1]), 0,
            8 * sizeof (p->mt[1]) - 32, seed1);
```

逐行拆解的话就是：mpz_tstbit(seed1, 19936L)：seed1 有 19937 比特，bit 索引是 0…19936，取第 19936 位，如果这一位是 1，就令 mt[0] = 0x80000000（最高位 1，其余 0）；否则 mt[0] = 0。mpz_clrbit (seed1, 19936L)：把 seed1 的最高位清零，避免后面拆 32 位块时重复用到这一位，清完后，seed1 剩下 19936 比特（bit 0…19935）。

mpz_export (&p->mt[1], &cnt, -1, sizeof (p->mt[1]), 0, 8 * sizeof (p->mt[1]) - 32, seed1)这个函数字接着把剩下的 19936 比特被拆成若干个 32-bit 块，顺次填入 mt[1], mt[2], …，一共 N（624） 个元素。

最后一段：

```
/* Warm the generator up if necessary.  */
if (WARM_UP != 0)
  for (i = 0; i < WARM_UP / N; i++)
    __gmp_mt_recalc_buffer (p->mt);

p->mti = WARM_UP % N;
```

头文件定义warm_up为2000，对mt进行三次_gmp_mt_recalc_buffer(p->mt)操作（相当于MT 的核心“twist”操作），根据当前 mt[]，用那套线性递推（y = (mt[k] & 0x80000000) | … 等）计算出新的 mt[]，相当于生成完一整轮 N 个输出后的下一轮状态。

完成循环后令p->mti = WARM_UP % N，mti 是当前要从 mt[] 取输出的下标，把 mti 设成 WARM_UP % N，相当于：再往前走 WARM_UP % N 个单步输出（不重算 buffer，只是把 mti 从 0 移到这个位置），组合起来，等价于从这个初始状态出发，先丢掉前 WARM_UP 个 32-bit 输出，把生成器推进 WARM_UP 步，再开始真正对外输出。

到这里set_random_seed函数的分析结束了。

其实有注释可以看（笑得很苦）:

```bash
/* Seeding function.  Uses powering modulo a non-Mersenne prime to obtain
   a permutation of the input seed space.  The modulus is 2^19937-20023,
   which is probably prime.  The power is 1074888996.  In order to avoid
   seeds 0 and 1 generating invalid or strange output, the input seed is
   first manipulated as follows:

     seed1 = seed mod (2^19937-20027) + 2

   so that seed1 lies between 2 and 2^19937-20026 inclusive. Then the
   powering is performed as follows:

     seed2 = (seed1^1074888996) mod (2^19937-20023)

   and then seed2 is used to bootstrap the buffer.

   This method aims to give guarantees that:
     a) seed2 will never be zero,
     b) seed2 will very seldom have a very low population of ones in its
	binary representation, and
     c) every seed between 0 and 2^19937-20028 (inclusive) will yield a
	different sequence.

   CAVEATS:

   The period of the seeding function is 2^19937-20027.  This means that
   with seeds 2^19937-20027, 2^19937-20026, ... the exact same sequences
   are obtained as with seeds 0, 1, etc.; it also means that seed -1
   produces the same sequence as seed 2^19937-20028, etc.

   Moreover, c) is not guaranted, there are many seeds yielding to the
   same sequence, because gcd (1074888996, 2^19937 - 20023 - 1) = 12.
   E.g. x and x'=x*19^((2^19937-20023-1) / 12) mod (2^19937-20023), if
   chosen as seed1, generate the same seed2, for every x.
   Similarly x" can be obtained from x', obtaining 12 different
   values.
```

注释里写得很有意思的moreover说：模 M2 的乘法群大小是 M2 - 1 = 2^19937 - 20023 - 1。指数 e和M2 - 1的最大公约数是

`gcd(1074888996, 2^19937 - 20023 - 1) = 12` ，在这样的群里，幂映射 x ↦ x^e 不是一个单射，而是一个 12 对 1 的映射：每 12 个不同的 x 会映射到同一个 x^e。注释里举了例子：如果x是某个合法seed1，那么：

```
x'  = x * 19^((M2-1)/12) mod M2
x'' = x' * 19^((M2-1)/12) mod M2 ...
```

这样能构造出一共 12 个不同的值，但它们在做^e mod M2后得到相同的seed2，所以随机序列也一样。

接下来看：random_matrix

```python
sage: random_matrix??
sage: ...
if ncols is None:
        ncols = nrows
    sparse = kwds.pop('sparse', False)
    # Construct the parent of the desired matrix
    parent = matrix_space.MatrixSpace(ring, nrows, ncols, sparse=sparse, implementation=implementation)
    if algorithm == 'randomize':
        density = kwds.pop('density', None)
        # zero matrix is immutable, copy is mutable
        A = copy(parent.zero_matrix())
        if density is None:
            A.randomize(density=float(1), nonzero=False, *args, **kwds)
        else:
            A.randomize(density=density, nonzero=True, *args, **kwds)
        return A
    elif algorithm == 'echelon_form':
        return random_rref_matrix(parent, *args, **kwds)
    elif algorithm == 'echelonizable':
        return random_echelonizable_matrix(parent, *args, **kwds)
    elif algorithm == 'diagonalizable':
        return random_diagonalizable_matrix(parent, *args, **kwds)
    elif algorithm == 'subspaces':
        return random_subspaces_matrix(parent, *args, **kwds)
    elif algorithm == 'unimodular':
        return random_unimodular_matrix(parent, *args, **kwds)
    elif algorithm == 'unitary':
        return random_unitary_matrix(parent, *args, **kwds)
    else:
        raise ValueError('random matrix algorithm "%s" is not recognized' % algorithm)
File:
Type:      function
```

默认算法是randomize：

```python
if algorithm == 'randomize':
    density = kwds.pop('density', None)
    # Construct the parent of the desired matrix
    parent = matrix_space.MatrixSpace(ring, nrows, ncols, sparse=sparse, implementation=implementation)
    # zero matrix is immutable, copy is mutable
    A = copy(parent.zero_matrix())
    if density is None:
        A.randomize(density=float(1), nonzero=False, *args, **kwds)
    else:
        A.randomize(density=density, nonzero=True, *args, **kwds)
    return A
```

整体逻辑是，先建一个 MatrixSpace(ring, nrows, ncols, ...)，然后取一个零矩阵 parent.zero_matrix()，再 copy 一份可变矩阵 A，如果没有传density调用 A.randomize(density=1.0, nonzero=False, *args, **kwds)，对矩阵的每个位置用 ring.random_element(...) 重置，允许为 0；

如果传了density调用 A.randomize(density=density, nonzero=True, *args, **kwds)，只随机修改一部分位置，比例为 density，并且新元素要求非零，没选中的位置保持为 0。

接下里看A.randomize 算法，对于比较小的mod<94906266（对于该题是够的），执行的是（matrix_modn_dense_template.pxi (lines 2622-2627)）：

```python
def randomize(self, density=1, nonzero=False):
        density = float(density)
        if density <= 0:
            return
        if density > 1:
            density = float(1)

        self.check_mutability()
        self.clear_cache()

        cdef randstate rstate = current_randstate()

        cdef int nc, p = <int>self.p
        cdef long pm1

        if not nonzero:
            # Original code, before adding the ``nonzero`` option.
            if density == 1:
                for i from 0 <= i < self._nrows*self._ncols:
                    self._entries[i] = rstate.c_random() % p
            else:
                nc = self._ncols
                num_per_row = int(density * nc)
                sig_on()
                for i from 0 <= i < self._nrows:
                    for j from 0 <= j < num_per_row:
                        k = rstate.c_random() % nc
                        self._matrix[i][k] = rstate.c_random() % p
                sig_off()
        else:
            # New code, to implement the ``nonzero`` option.
            pm1 = p - 1
            if density == 1:
                for i from 0 <= i < self._nrows*self._ncols:
                    self._entries[i] = (rstate.c_random() % pm1) + 1
            else:
                nc = self._ncols
                num_per_row = int(density * nc)
                sig_on()
                for i from 0 <= i < self._nrows:
                    for j from 0 <= j < num_per_row:
                        k = rstate.c_random() % nc
                        self._matrix[i][k] = (rstate.c_random() % pm1) + 1
                sig_off()
```

在 Matrix_modn_dense_template 的 **cinit** 里（matrix_modn_dense_template.pxi:420+）：

```python
cdef class Matrix_modn_dense_template(Matrix_dense):
    def __cinit__(self, *args, bint zeroed_alloc=True, **kwds):
        cdef long p = self._base_ring.characteristic()
        self.p = p
        if p >= MAX_MODULUS:
            raise OverflowError("p (=%s) must be < %s." % (p, MAX_MODULUS))
        ...
        self._entries = <celement *> check_calloc(self._nrows * self._ncols, sizeof(celement))
```

在 density == 1、nonzero == False 的分支（matrix_modn_dense_template.pxi (lines 2622-2627)）：

```python
cdef randstate rstate = current_randstate()
cdef int nc, p = <int>self.p
...
if not nonzero:
    if density == 1:
        for i from 0 <= i < self._nrows*self._ncols:
            self._entries[i] = rstate.c_random() % p
```

rstate = current_randstate()获取当前全局随机状态对象（由 set_random_seed 决定）。之后rstate.c_random() % p调用 GMP 的 Mersenne Twister 随机数发生器 gmp_urandomb_ui 生成一个 31 位均匀随机整数 u ∈ [0, 2^31-1]，但本质都是线性计算；

补充：当n较大或某些情况，会使用 matrix2.randomize ，通用实现的 randomize 在 sage/matrix/matrix2.pyx (line 10092) 起。

```python
randint = current_randstate().python_random().randint

density = float(density)
if density <= 0:
    return
if density > 1:
    density = 1

self.check_mutability()
self.clear_cache()

R = self.base_ring()

cdef Py_ssize_t i, j, num

if nonzero:
    if density >= 1:
        for i from 0 <= i < self._nrows:
            for j from 0 <= j < self._ncols:
                self.set_unsafe(i, j, R._random_nonzero_element(*args, **kwds))
    else:
        num = int(self._nrows * self._ncols * density)
        for i from 0 <= i < num:
            self.set_unsafe(randint(0, self._nrows - 1),
                            randint(0, self._ncols - 1),
                            R._random_nonzero_element(*args, **kwds))
```

对 density=1 且 nonzero=False 的情况，首先取 randint = current_randstate().python_random().randint，然后：

```python
for i from 0 <= i < self._nrows:
    for j from 0 <= j < self._ncols:
        self.set_unsafe(i, j, R.random_element(*args, **kwds))
```

这里 R 是 Zmod(mod)，它的 random_element 在sage/rings/finite_rings/integer_mod_ring.py (line 1519)：

```python
if bound is not None:
	a = random.randint(-bound, bound)
else:
	a = random.randint(0, self.order() - 1) return self(a)
```

我们再回到这个题目，核心代码为

```python
FLAG = os.environ.get("FLAG", "RCTF{fake_flag}")
MACHINE_LIMIT = 19937

secret = os.urandom(64)
set_random_seed(int.from_bytes(secret, 'big'))

def random_machine(mod: int, nrow: int, ncol: int) -> bytes:
    outs = (random_matrix(Zmod(mod), nrow, ncol).list())
    print("🤖 Machine output:", outs)

guess = bytes.fromhex(input("🤔 secret (hex): ").strip())
if guess == secret:
    print(f"🎉 Correct! Here is your flag: {FLAG}")
```

总结一下整理这个题目的含义：我们需要构造最大的bit泄露，显然可以想到mod 2 ，nrow 1 ， ncol 19937，刚好请求 19937 个 bit，解线性方程组恢复 gmp random 的初始状态（也就是  seed2，可以使用gf2bv库  ），再从  seed2 反推  seed 。

MT 的内部状态与输出之间是线性的（在 $\mathbb{F}_2$ 上）：twist 本质上是线性递推，temper 由移位与按位与/异或构成，取 LSB 就是取最低一位。

同时，`randseed_mt` 中 `seed2 -> mt[0..623]` 的映射也是线性的。记

$$
\texttt{seed2} = \sum_{k=0}^{19936} s_k 2^k,\qquad s_k \in \{0,1\}
$$

则

$$
mt[0] = s_{19936} \cdot 2^{31},\qquad
mt[1] = \sum_{k=0}^{31} s_k 2^k,\qquad
mt[2] = \sum_{k=32}^{63} s_k 2^{k-32},\qquad \dots
$$

因此，可以直接把 19937 个比特的 `seed2` 当作 $\mathbb{F}_2$ 上的变量，写出

$$
M \cdot s = b
$$

其中 $s \in \mathbb{F}_2^{19937}$ 为 `seed2` 的 bit 变量，$b \in \mathbb{F}_2^{19937}$ 为观测到的 LSB 序列，$M$ 是由 `seed2 -> mt[] -> twist/temper -> LSB` 组成的线性变换矩阵。

接下来构造这个线性方程：
首先创建一个 GF(2) 上的线性系统，总共有 624 * 32 = 19968 个比特未知量，逻辑上对应 GMP 的 MT19937 状态数组 mt[0..623] 的每一位。mt = lin.gens()返回 624 个 BitVec，每个长度 32，比特全是“符号变量”，不是具体的 0/1。后面所有按位运算（移位、异或、与掩码）都是线性操作，gf2bv 会把它们记录成线性组合，然后把符号状态塞进 MT：rng = MT19937(mt)

接下来，加入已知的状态约束：mt[0] & 0x7FFFFFFF，用掩码只保留这 31 个低位，对应 31 个 BitVec 中的线性表达式；放到 zeros 里就表示这 31 个表达式都必须等于 0。LinearSystem.get_eqs(zeros) 会把这些 BitVec 展开成 31 条线性方程，约束“低 31 位 = 0”。这样从 19968 个未知比特中，先用 31 个恒等式去掉多余自由度，理论上就剩 19937 个真正自由的 seed 比特。

之后进行2000字的预热，由于gf2bv源码里mti是624，所以只需要2000 - 624 次预热

```
for i in range(2000 - 624):
	rng.getrandbi
```

a按照之前的选择（mod = 2，nrow = 1，ncol = 19937），output 里拿到的矩阵元素列表，每个都是 0 或 1。它本质上是 GMP 的 c_random() % 2，也就是 MT 输出的 最低一位。每次循环rng.getrandbits(32)得到下一次 MT 输出的 32 位“符号比特”，& 1：用掩码保留 LSB。对于 BitVec 来说，相当于只留下一个比特的线性表达式，通过^ output[i]和已知的 0/1 做异或，如果 output[i] == 0，这个表达式 = “LSB ⊕ 0”，如果 output[i] == 1，表达式 = “LSB ⊕ 1”，相当于在方程的常数项加了 1，把这个 BitVec 放进 zeros，在 LinearSystem 看来就是一条方程：

$$
\operatorname{LSB} \oplus \operatorname{output}_i = 0
$$

也就是“当前这一步 MT 的 LSB 必须等于我们output看到的那一位”。

最后枚举LinearSystem.solve_all解出来的所有情况，seed 的低 32 位 等于sol[1]，seed 的第 32~63 位 等于 sol[2]，...
seed 的第 19904~19935 = sol[623]以此类推，正好还原了 s_0..s_19935 这 19936 个比特，如果 mt[0] 恰好是 0x80000000，说明它的最高位为 1，即 s_19936 = 1，把 seed 的第 19936 位（从 0 开始数）设为 1，就把最高那一位也补上了。

这里LinearSystem.solve_all做的事大致是：把 zeros 里的所有 BitVec / int 展开成一个 GF(2) 上的矩阵 A 和常量向量 b（底层用 get_eqs + eqs_to_sage_mat_helper），相当于 A x = b。用 m4ri_solve（m4ri 库）做高效的 GF(2) 高斯消元，求出整个解空间（仿射空间）。solve_all 会枚举解空间里的所有解（这里维度为 0，所以只有一个解），并用 convert_sol 把单个大整数解拆成 624 个 32 位整数：`sol = (mt[0], mt[1], ..., mt[623])  # 具体的 int`

这一步"把 zeros 里的所有 BitVec / int 展开成一个 GF(2) 上的矩阵 A 和常量向量 b"是怎么工作的，我翻了一下源码，我的理解大概就是，省流版：

每个整数 E 对应一条仿射线性方程

$$
c_0 + \sum_{j=1}^n c_j x_j = 0,\qquad c_j \in \{0,1\}
$$

其中 c_j 是 E 的二进制展开的各个位。
zeros 里的所有 BitVec 被展开成一串整数 E_1,\dots,E_m，于是得到一个方程组

$$
A x = b \pmod 2
$$

再在 $\mathbb{F}_2$ 上用高斯消元求解。

最后一步只需要解一个 RSA，并且模数 `MOD2` 是一个素数。注意到 $e$ 和 $\varphi = p - 1$ 不互质，满足

$$
\gcd(1074888996, 2^{19937} - 20024) = 12
$$

比较暴力的解法就是列出方程，用 Coppersmith 解出 `seed1`。

由上面的式子可以推出：

$$
g = \gcd(e, \varphi)
\;\Rightarrow\;
d_1 = (e // g)^{-1} \pmod{\varphi // g}
$$

$$
\texttt{seed1}^e = \texttt{seed2} \pmod{\texttt{MOD2}}
\Rightarrow
\texttt{seed1}^g = C = \texttt{seed2}^{d'} \pmod{\texttt{MOD2}}
$$

取左半边，可构造方程：

$$
f(x) = x^{12} - C \equiv 0 \pmod{\texttt{MOD2}}
$$

计算上界 $X \approx 2^{513}$，远小于 $N^{1/d} \approx 2^{1661}$，可以进行 Coppersmith 攻击。

但是由于MOD2模数比较大，使用Zmod(MOD2)时会进行一次素性检测，我这电脑内存不太够，看到Arr3stY0u那边代码用的[crypto-attack]:[jvdsn/crypto-attacks: Python implementations of cryptographic attacks and utilities.](https://github.com/jvdsn/crypto-attacks)

里的small_roots。

还有一种的话，就是对seed2^{d1} =seed1^{12}  直接用gmpy.iroot开12次方。。喵喵。。

完整代码如下：

```python
from pwn import process, remote
from ast import literal_eval
import gmpy2
from sage.all import ZZ, gcd, Zmod, PolynomialRing
from Crypto.Util.number import isPrime

from gf2bv import LinearSystem
from gf2bv.crypto.mt import MT19937
from tqdm import *

io = process(["sage", "/root/rctf/mt19937.py"])
# io = remote("1.14.196.78", 42101)
io.sendline(b"2 1 19937")
io.recvuntil(b"output:")
output = literal_eval(io.recvline().decode())

lin = LinearSystem([32] * 624)
mt = lin.gens()
print(mt[0] & 0x7FFFFFFF)

rng = MT19937(mt)
print("WARMING UP ")
zeros = [mt[0] & 0x7FFFFFFF]
for i in range(2000 - 624):
    rng.getrandbits(32)
for i in tqdm(range(len(output))):
    zeros.append((rng.getrandbits(32) & 1) ^ output[i])

for sol in lin.solve_all(zeros):
    seed = 0
    for i in sol[1:][::-1]:
        seed = (seed << 32) | i
    if sol[0] == 0x80000000:
        seed |= 1 << 19936

    MOD2 = (ZZ(1) << 19937) - 20023
    E = ZZ(0x40118124)
    phi = MOD2 - 1
    g = gcd(E, phi)  # 12
    E1 = E // g
    phi1 = phi // g
    D1 = E1.inverse_mod(phi1)

    # Use Sage's built-in small_roots on a polynomial over Zmod(MOD2)
    from shared.small_roots.howgrave_graham import modular_univariate
    target = pow(seed, D1, MOD2)
    PR = PolynomialRing(ZZ, "x")
    x = PR.gen()
    f = x ** 12 - target
    X = 2 ** 513

    # ok = False
    # for m in range(2, 7):
    #     for t in range(1, 6):
    #         for roots in modular_univariate(f, MOD2, m, t, X):
    #             r = roots[0]
    #             if abs(r) < X and pow(r, 12, MOD2) == target and pow(r , E , MOD2) == seed:
    #                 root = r
    #                 seed = root - 2
    #                 io.sendlineafter(b"secret", int(seed).to_bytes(64, "big").hex().encode())
    #                 io.interactive()
    #                 ok = True
    #                 break
    #         if ok == True:
    #             break
    #     if ok == True:
    #         break

    seed = gmpy2.powmod(seed, D1, MOD2)
    seed, ok = gmpy2.iroot(seed, 12)

    if ok:
        seed -= 2
        print(hex(seed))
        io.sendlineafter(b"secret", int(seed).to_bytes(64, "big").hex().encode())
        io.interactive()
```
