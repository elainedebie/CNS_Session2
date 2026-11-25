#!/usr/bin/env python3
"""
RSA solver for the "factor a small/weak n" family.

When n is small, or its two primes are badly chosen, you can recover the
private key by FACTORING n. This script tries several methods in order of
speed and prints the first factorisation it finds, then computes d and
decrypts the ciphertext from a challenge.json.

Methods (each is a different "sieve"/factoring idea you can mention):
  1. Trial division        - cheap; catches small primes and tiny n.
  2. Pollard's rho         - fast for n up to ~2^80; the workhorse here.
  3. Fermat's method       - instant when p and q are CLOSE together
                             (n = a^2 - b^2). Classic exam trap.
  4. Pollard's p-1         - works when p-1 is "smooth" (only small factors).
  (For truly large n you'd reach for the Quadratic Sieve / GNFS, but those
   aren't needed below ~100+ digits and aren't bundled here.)

Decryption matches the provided decryptor.py:
  each ciphertext block c  ->  m = c^d mod n  ->  block_size bytes big-endian,
  concatenate, then trim to original_length.

Usage:
    python3 -I rsa_factor.py challenge.json
"""
import sys, json, random
from math import gcd, isqrt


# ---------- 1. trial division ----------
def trial_division(n, bound=1_000_000):
    if n % 2 == 0:
        return 2
    f = 3
    while f <= bound and f * f <= n:
        if n % f == 0:
            return f
        f += 2
    return None


# ---------- 2. Pollard's rho (Brent) ----------
def is_probable_prime(n):
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


def pollard_rho(n):
    if n % 2 == 0:
        return 2
    if is_probable_prime(n):
        return n
    while True:
        c = random.randrange(1, n)
        f = lambda x: (x * x + c) % n
        x = y = random.randrange(2, n)
        d = 1
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = gcd(abs(x - y), n)
        if d != n:
            return d


# ---------- 3. Fermat (close primes) ----------
def fermat(n, max_iter=1_000_000):
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b  # a factor
        a += 1
    return None


# ---------- 4. Pollard p-1 ----------
def pollard_pm1(n, bound=100_000):
    a = 2
    for j in range(2, bound):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d
    return None


def factor_n(n):
    for name, fn in [
        ("trial division", lambda: trial_division(n)),
        ("Fermat (close primes)", lambda: fermat(n, 200_000)),
        ("Pollard's rho", lambda: pollard_rho(n)),
        ("Pollard's p-1", lambda: pollard_pm1(n)),
    ]:
        try:
            f = fn()
        except Exception:
            f = None
        if f and 1 < f < n and n % f == 0:
            return f, n // f, name
    return None, None, None


# ---------- decrypt (mirrors decryptor.py) ----------
def decrypt(ciphertext, d, n, block_size, original_length):
    out = bytearray()
    for c in ciphertext:
        m = pow(c, d, n)
        out.extend(m.to_bytes(block_size, "big"))
    return bytes(out[:original_length])


def main():
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    ch = json.load(open(sys.argv[1]))
    n, e = ch["n"], ch["e"]
    ct = ch["ciphertext"]
    block_size = ch["block_size"]
    original_length = ch["original_length"]

    print(f"n = {n}  ({n.bit_length()} bits)")
    print(f"e = {e}\n")

    p, q, method = factor_n(n)
    if not p:
        print("[-] none of the bundled methods factored n."); return
    print(f"[+] factored with: {method}")
    print(f"    p = {p}")
    print(f"    q = {q}")
    assert p * q == n and is_probable_prime(p) and is_probable_prime(q)

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    print(f"\n[+] phi(n) = {phi}")
    print(f"[+] d = {d}\n")

    msg = decrypt(ct, d, n, block_size, original_length)
    print("[+] Decrypted message:")
    print("---------------------")
    try:
        print(msg.decode("utf-8"))
    except UnicodeDecodeError:
        print(repr(msg))


if __name__ == "__main__":
    main()
