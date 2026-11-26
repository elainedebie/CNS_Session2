#!/usr/bin/env python3
"""
rsa_solve.py  —  master RSA CTF solver / dispatcher.

Point it at whatever the challenge gives you; it detects the weakness and runs
the right attack. If detection is ambiguous it just CASCADES through every
applicable attack until one produces a sensible plaintext.

    python3 -I rsa_solve.py challenge.json
    python3 -I rsa_solve.py public_keys.txt ciphertexts.txt
    python3 -I rsa_solve.py challenge.json --flag cns          # hint the prefix

Accepts any mix of .json and .txt files. It harvests every n, e, c (also
'ciphertext' lists, block_size, original_length, and given d / p / q) and
normalises them, so the exam's two layouts both "just work".

ATTACKS COVERED (and the fingerprint that selects each):
  given d                      -> decrypt directly
  given p, q                   -> d = e^-1 mod phi, decrypt
  common factor gcd(ni,nj)>1   -> factor both keys, decrypt
  small e, m^e < n             -> direct e-th root (cube root)          [Håstad A]
  small e, e keys, same msg    -> CRT broadcast, then e-th root         [Håstad B]
  one n, two e, two c          -> common-modulus (extended Euclid)
  huge e (~size of n)          -> Wiener (small d, continued fractions)
  small / weak n               -> factor (trial / Fermat / rho / p-1), decrypt

DECODING: m = bytes_to_long(FLAG)  <->  FLAG = long_to_bytes(m) (big-endian),
or block mode (ciphertext list + block_size + original_length) like decryptor.py.
"""
import sys, json, re, random
from math import gcd, isqrt


# ======================================================================
#  number-theory helpers
# ======================================================================
def iroot(x, e):
    """(floor(x**(1/e)), exact?)."""
    if x < 0:
        raise ValueError
    if x == 0:
        return 0, True
    lo, hi = 1, 1 << ((x.bit_length() // e) + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** e <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo ** e == x


def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def egcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def crt(residues, moduli):
    N = 1
    for m in moduli:
        N *= m
    x = 0
    for r, n in zip(residues, moduli):
        Ni = N // n
        x += r * Ni * pow(Ni, -1, n)
    return x % N, N


# ---- factoring methods ----
def trial_division(n, bound=5_000_000):
    if n % 2 == 0:
        return 2
    f = 3
    while f <= bound and f * f <= n:
        if n % f == 0:
            return f
        f += 2
    return None


def fermat(n, max_iter=5_000_000):
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b
        a += 1
    return None


def pollard_rho(n, max_tries=8, step_cap=2_000_000):
    if n % 2 == 0:
        return 2
    if is_prime(n):
        return n
    for _ in range(max_tries):
        c = random.randrange(1, n)
        f = lambda x: (x * x + c) % n
        x = y = random.randrange(2, n)
        d = 1
        steps = 0
        while d == 1 and steps < step_cap:   # cap so big semiprimes don't hang
            x = f(x)
            y = f(f(y))
            d = gcd(abs(x - y), n)
            steps += 1
        if 1 < d < n:
            return d
    return None


def pollard_pm1(n, bound=200_000):
    a = 2
    for j in range(2, bound):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d
    return None


def factor(n):
    """Return a nontrivial factor of n, or None. Size-aware so it never hangs:
    trial division + Fermat always (Fermat is fast at any size and catches
    close primes); rho / p-1 only when n is small enough to be feasible."""
    small = n.bit_length() <= 160          # rho/p-1 realistic below ~160 bits
    methods = [lambda: trial_division(n),
               lambda: fermat(n, 1_000_000)]   # close-prime catch, any size
    if small:
        methods += [lambda: pollard_rho(n), lambda: pollard_pm1(n)]
    for fn in methods:
        try:
            f = fn()
        except Exception:
            f = None
        if f and 1 < f < n and n % f == 0:
            return f
    return None


# ---- Wiener ----
def wiener(n, e):
    def cf(num, den):
        while den:
            q = num // den
            yield q
            num, den = den, num - q * den
    h_prev, h = 1, None
    k_prev, k = 0, None
    first = True
    for a in cf(e, n):
        if first:
            h, k = a, 1
            first = False
        else:
            h, h_prev = a * h + h_prev, h
            k, k_prev = a * k + k_prev, k
        kk, dd = k, h  # convergent h/k of e/n  == k_guess/d_guess? use (k_num=h, d=k)
        # convergents of e/n are h/k; here k_guess=h, d=k
        k_guess, d = h, k
        if k_guess == 0:
            continue
        if (e * d - 1) % k_guess != 0:
            continue
        phi = (e * d - 1) // k_guess
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        s = isqrt(disc)
        if s * s != disc:
            continue
        p = (b + s) // 2
        q = (b - s) // 2
        if p * q == n:
            return d, p, q
    return None


# ======================================================================
#  decode
# ======================================================================
def long_to_bytes(m):
    if m == 0:
        return b"\x00"
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def show(m_or_bytes, flaghint=None):
    b = m_or_bytes if isinstance(m_or_bytes, (bytes, bytearray)) else long_to_bytes(m_or_bytes)
    try:
        t = b.decode("utf-8")
        return t, b
    except UnicodeDecodeError:
        return repr(b), b


def looks_like_flag(text, hint):
    if hint and hint in text:
        return True
    printable = sum(32 <= ord(ch) < 127 or ch in "\n\t" for ch in text if ord(ch) < 128)
    return len(text) > 0 and printable >= 0.8 * len(text)


# ======================================================================
#  parse arbitrary inputs
# ======================================================================
def harvest(paths):
    # n/e/c are ORDERED lists preserving file order and every repeat
    # (broadcast files repeat bare 'n =' with no numeric suffix).
    P = {"n": [], "e": [], "c": [], "cipherlist": None,
         "d": None, "p": None, "q": None,
         "block_size": None, "original_length": None}

    for path in paths:
        raw = open(path).read()
        data = None
        try:
            data = json.loads(raw)
        except Exception:
            data = None
        if isinstance(data, dict):
            # sort keys so n,e1,e2,c1,c2 come out in a stable, suffix order
            for key in sorted(data.keys(), key=lambda s: (re.sub(r"\d", "", s.lower()), s.lower())):
                val = data[key]
                k = key.strip().lower()
                if k == "ciphertext" and isinstance(val, list):
                    P["cipherlist"] = [int(x) for x in val]
                elif k in ("block_size", "original_length", "d", "p", "q"):
                    P[k] = int(val)
                elif re.fullmatch(r"n\d*", k):
                    P["n"].append(int(val))
                elif re.fullmatch(r"e\d*", k):
                    P["e"].append(int(val))
                elif (re.fullmatch(r"c\d*", k) or k == "ciphertext") and not isinstance(val, list):
                    P["c"].append(int(val))
        else:
            for line in raw.splitlines():
                m = re.match(r"\s*([a-zA-Z]+)(\d*)\s*=\s*([0-9]+)", line)
                if not m:
                    continue
                name, val = m.group(1).lower(), int(m.group(3))
                if name == "n":
                    P["n"].append(val)
                elif name == "e":
                    P["e"].append(val)
                elif name in ("c", "ct", "ciphertext"):
                    P["c"].append(val)
                elif name in ("d", "p", "q"):
                    P[name] = val
    return P


def build(P):
    """Return (keys, cts, extras). keys = [(n,e)], cts aligned with keys when possible."""
    ns = list(P["n"])
    es = list(P["e"])
    cs = list(P["c"])
    if not es:
        es = [3]  # exam default

    # build key list
    if len(ns) >= 1 and len(es) >= 1:
        if len(ns) == 1 and len(es) > 1:          # common modulus: one n, many e
            keys = [(ns[0], e) for e in es]
        elif len(es) == 1 and len(ns) > 1:        # broadcast: many n, one e
            keys = [(n, es[0]) for n in ns]
        elif len(ns) == len(es):                  # aligned
            keys = list(zip(ns, es))
        else:
            keys = [(n, es[0]) for n in ns]
    else:
        keys = []
    return keys, cs, ns, es


# ======================================================================
#  the dispatcher
# ======================================================================
def decrypt_with_d(d, n, P, single_c=None):
    if P["cipherlist"] is not None and P["block_size"]:
        out = bytearray()
        for c in P["cipherlist"]:
            m = pow(c, d, n)
            out.extend(m.to_bytes(P["block_size"], "big"))
        if P["original_length"]:
            out = out[:P["original_length"]]
        return bytes(out)
    if single_c is not None:
        return long_to_bytes(pow(single_c, d, n))
    return None


def solve(paths, flaghint="cns"):
    P = harvest(paths)
    keys, cs, ns, es = build(P)
    distinct_n = sorted(set(ns))
    distinct_e = sorted(set(es)) if es else [3]
    results = []

    print("=" * 60)
    print(f"Harvested: {len(distinct_n)} distinct modulus/moduli, "
          f"exponent(s) {distinct_e if distinct_e else '(default 3)'}, "
          f"{len(cs)} separate ciphertext(s)"
          + (f", 1 block-ciphertext list of {len(P['cipherlist'])}" if P['cipherlist'] else ""))
    if P["d"]: print("  -> private exponent d supplied")
    if P["p"] and P["q"]: print("  -> p, q supplied")
    print("=" * 60)

    n0 = distinct_n[0] if distinct_n else None
    e0 = distinct_e[0]
    single_c = cs[0] if len(cs) == 1 else (None if not cs else cs[0])

    def report(name, plaintext_bytes):
        txt, b = show(plaintext_bytes, flaghint)
        ok = looks_like_flag(txt, flaghint)
        print(f"\n[{'+' if ok else '?'}] {name}:")
        print("    " + (txt if len(txt) < 400 else txt[:400] + "..."))
        if ok:
            results.append((name, txt))
        return ok

    # 0) d given
    if P["d"] is not None and n0:
        pt = decrypt_with_d(P["d"], n0, P, single_c)
        if pt is not None and report("given-d decrypt", pt):
            return finish(results)

    # 0b) p,q given
    if P["p"] and P["q"]:
        n = P["p"] * P["q"]
        phi = (P["p"] - 1) * (P["q"] - 1)
        d = pow(e0, -1, phi)
        pt = decrypt_with_d(d, n, P, single_c)
        if pt is not None and report("given-pq decrypt", pt):
            return finish(results)

    # 1) common factor across moduli (use ORIGINAL order so each n keeps its own c, e)
    if len(ns) >= 2:
        for i in range(len(ns)):
            for j in range(i + 1, len(ns)):
                if ns[i] == ns[j]:
                    continue
                g = gcd(ns[i], ns[j])
                if g > 1:
                    print(f"\n[!] gcd(n{i+1}, n{j+1}) = shared prime -> factoring both!")
                    for idx in (i, j):
                        n = ns[idx]
                        p = g; q = n // g
                        phi = (p - 1) * (q - 1)
                        e_here = es[idx] if idx < len(es) else e0
                        try:
                            d = pow(e_here, -1, phi)
                        except Exception:
                            continue
                        c = cs[idx] if idx < len(cs) else single_c
                        if c is not None:
                            report(f"common-factor decrypt (key {idx+1})",
                                   long_to_bytes(pow(c, d, n)))
                    if results:
                        return finish(results)

    # 2) & 3) broadcast with small e (many n, one small e, >=e ciphertexts)
    if len(distinct_n) >= 2 and len(distinct_e) == 1 and e0 <= 11 and len(cs) >= e0:
        # Case A: direct e-th root on any ciphertext
        for i, c in enumerate(cs):
            r, exact = iroot(c, e0)
            if exact and report(f"small-e cube root (c{i+1}, no wraparound)", r):
                return finish(results)
        # Case B: CRT broadcast
        resid = cs[:e0]; mods = ns[:e0]
        try:
            C, _ = crt(resid, mods)
            r, exact = iroot(C, e0)
            print(f"\n    Håstad CRT: {e0}-th root exact = {exact}")
            if report("Håstad broadcast (CRT)", r):
                return finish(results)
        except Exception as ex:
            print(f"    CRT failed: {ex}")

    # 4) common modulus: one n, >=2 distinct e, matching c's
    if len(distinct_n) == 1 and len(distinct_e) >= 2 and len(cs) >= 2:
        for ia in range(len(cs)):
            for ib in range(ia + 1, len(cs)):
                ea = keys[ia][1] if ia < len(keys) else es[ia]
                eb = keys[ib][1] if ib < len(keys) else es[ib]
                g, a, b = egcd(ea, eb)
                if g != 1:
                    continue
                ca, cb = cs[ia], cs[ib]
                if a < 0:
                    ca = pow(ca, -1, n0); a = -a
                if b < 0:
                    cb = pow(cb, -1, n0); b = -b
                m = (pow(ca, a, n0) * pow(cb, b, n0)) % n0
                if report(f"common-modulus (e{ia+1},e{ib+1})", m):
                    return finish(results)

    # 5) single key: cube root / Wiener / factor
    if n0:
        c = single_c if single_c is not None else (cs[0] if cs else None)
        # 5a small-e cube root
        if e0 <= 11 and c is not None:
            r, exact = iroot(c, e0)
            if exact and report("small-e cube root (single key)", r):
                return finish(results)
        # 5b Wiener (always cheap to try; most telling when e is huge)
        try:
            w = wiener(n0, e0)
        except Exception:
            w = None
        if w:
            d, p, q = w
            print(f"\n[!] Wiener: small d = {d} ({d.bit_length()} bits); "
                  f"p,q recovered.")
            pt = decrypt_with_d(d, n0, P, c)
            if pt is not None and report("Wiener (small d)", pt):
                return finish(results)
        # 5c factor n
        f = factor(n0)
        if f:
            p, q = f, n0 // f
            phi = (p - 1) * (q - 1)
            try:
                d = pow(e0, -1, phi)
                print(f"\n[!] factored n: p={p}\n               q={q}")
                pt = decrypt_with_d(d, n0, P, c)
                if pt is not None and report("factor-n decrypt", pt):
                    return finish(results)
            except Exception:
                pass
        elif n0.bit_length() > 300:
            print(f"\n[i] n is {n0.bit_length()} bits — too big to factor with "
                  f"bundled methods (expected: the attack is structural, not factoring).")

    return finish(results)


def finish(results):
    print("\n" + "=" * 60)
    if results:
        print(f"SOLVED via {results[0][0]}:")
        print(f"  {results[0][1]}")
    else:
        print("No attack produced a flag-like plaintext. "
              "Check inputs, or the challenge needs an attack not bundled "
              "(Boneh-Durfee, Franklin-Reiter, padding/LSB oracle, ...).")
    print("=" * 60)
    return results


def main():
    args = [a for a in sys.argv[1:]]
    flaghint = "cns"
    if "--flag" in args:
        i = args.index("--flag")
        flaghint = args[i + 1]
        del args[i:i + 2]
    if not args:
        print(__doc__); sys.exit(1)
    solve(args, flaghint)


if __name__ == "__main__":
    main()