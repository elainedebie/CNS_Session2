#!/usr/bin/env python3
"""
RSA Wiener's attack (small private exponent d).

Scenario: the engineer wanted FAST decryption, so he chose a SMALL private
exponent d (decryption cost grows with d's size). Wiener proved that if
    d < (1/3) * n^(1/4)
then d can be recovered from the PUBLIC key (n, e) alone — no factoring.

Fingerprint in the file: e is HUGE, nearly the size of n (because d is tiny
and e is its inverse mod phi, e gets pushed up close to n). Normal RSA uses a
small e like 65537; a giant e screams "small d -> Wiener".

How it works (continued fractions):
    e/n is very close to e/phi(n), and e*d = 1 + k*phi, so k/d is one of the
    convergents of the continued fraction expansion of e/n. For each convergent
    k/d we test whether it yields a valid factorisation of n; the right one
    makes phi = (e*d - 1)/k, from which x^2 - (n-phi+1)x + n = 0 has integer
    roots p, q.

Decoding matches the hint: m = bytes_to_long(FLAG) -> FLAG = long_to_bytes(m).

Usage:
    python3 -I rsa_wiener.py challenge.json      # needs n, e, (optional) c
"""
import sys, json
from math import isqrt


def continued_fraction(num, den):
    """CF expansion of num/den as a list of quotients."""
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf


def convergents(cf):
    """Yield (h, k) = numerator/denominator convergents of the CF."""
    h_prev, h = 1, cf[0]
    k_prev, k = 0, 1
    yield h, k
    for a in cf[1:]:
        h, h_prev = a * h + h_prev, h
        k, k_prev = a * k + k_prev, k
        yield h, k


def isqrt_exact(x):
    if x < 0:
        return None
    r = isqrt(x)
    return r if r * r == x else None


def wiener(n, e):
    """Return d (and p,q) if a small private exponent is recoverable, else None."""
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):      # convergents of e/n are k/d
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # solve x^2 - (n - phi + 1)x + n = 0  -> roots are p, q
        b = n - phi + 1
        disc = b * b - 4 * n
        s = isqrt_exact(disc)
        if s is None:
            continue
        p = (b + s) // 2
        q = (b - s) // 2
        if p * q == n:
            return d, p, q
    return None


def long_to_bytes(m):
    if m == 0:
        return b"\x00"
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def main():
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    ch = json.load(open(sys.argv[1]))
    n, e = ch["n"], ch["e"]
    c = ch.get("c") or ch.get("ciphertext")

    print(f"n ({n.bit_length()} bits)")
    print(f"e ({e.bit_length()} bits)  "
          f"{'<-- e nearly as big as n: classic small-d sign' if e.bit_length() > n.bit_length() - 10 else ''}\n")

    res = wiener(n, e)
    if not res:
        print("[-] Wiener failed: d is probably not small enough "
              "(needs d < n^(1/4)/3)."); return
    d, p, q = res
    print(f"[+] small private exponent recovered!")
    print(f"    d = {d}  ({d.bit_length()} bits)")
    print(f"    p = {p}")
    print(f"    q = {q}\n")

    if c is None:
        print("[i] no ciphertext in file; d is enough to decrypt their challenge.")
        return
    m = pow(c, d, n)
    flag = long_to_bytes(m)
    print("[+] FLAG = long_to_bytes(pow(c, d, n)):")
    print("--------------------------------------")
    try:
        print(flag.decode("utf-8"))
    except UnicodeDecodeError:
        print(repr(flag))


if __name__ == "__main__":
    main()
