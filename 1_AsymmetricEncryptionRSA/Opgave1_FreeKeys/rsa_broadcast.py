#!/usr/bin/env python3
"""
RSA solver for the "small exponent / broadcast" family of attacks.

Covers the two cases you'll meet with a small public exponent e (usually e=3):

  CASE A - Small message, no wraparound.
      If m^e < n, then c = m^e mod n = m^e exactly (the mod did nothing).
      Recover m = e-th integer root of c. You don't even need multiple keys.
      Tell-tale sign: c is much SHORTER than n, and/or all broadcast
      ciphertexts are IDENTICAL even though the moduli differ.

  CASE B - Hastad's broadcast attack.
      The SAME message m is sent to e recipients, each with exponent e
      and a different modulus n_i. You have e ciphertexts c_i = m^e mod n_i.
      By CRT, combine them into  C = m^e mod (n1*n2*...*ne).
      Because m < min(n_i), we have m^e < n1*...*ne, so C = m^e exactly.
      Recover m = e-th integer root of C.

The script tries CASE A on each ciphertext first (cheap), then falls back
to CASE B (CRT). It prints m as a number and decodes it as bytes/UTF-8.

Usage:
    python3 -I rsa_broadcast.py KEYS.txt CIPHERTEXTS.txt

The two files just need lines of the form  n = ...,  e = ...,  c = ...
(c1/c2/... and n/e in any order). Blank lines and "--- KEY x ---" headers
are ignored, so the exam's format works as-is.
"""
import sys, re
from math import gcd


# ---------- integer e-th root (exact) ----------
def iroot(x, e):
    """Return (r, exact) where r = floor(x**(1/e)) and exact tells if r**e == x."""
    if x < 0:
        raise ValueError("negative")
    if x == 0:
        return 0, True
    # binary search on the root
    lo, hi = 1, 1 << ((x.bit_length() // e) + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** e <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo ** e == x


# ---------- CRT ----------
def crt(residues, moduli):
    """Solve x = residues[i] (mod moduli[i]); moduli must be pairwise coprime."""
    # sanity: pairwise coprime
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if gcd(moduli[i], moduli[j]) != 1:
                raise ValueError(f"moduli {i} and {j} share a factor -> CRT invalid "
                                 f"(but that shared factor FACTORS both keys!)")
    N = 1
    for m in moduli:
        N *= m
    x = 0
    for r, n in zip(residues, moduli):
        Ni = N // n
        x += r * Ni * pow(Ni, -1, n)
    return x % N, N


# ---------- decode integer to text ----------
def to_text(m):
    b = m.to_bytes((m.bit_length() + 7) // 8, "big")
    try:
        return repr(b.decode("utf-8")), b
    except UnicodeDecodeError:
        return "(not valid UTF-8)", b


# ---------- parse the exam's files ----------
def parse_numbers(text, letter):
    """Grab every 'letter... = <bignum>' in order (letter is 'n', 'e', or 'c')."""
    out = []
    for line in text.splitlines():
        m = re.match(rf"\s*{letter}\w*\s*=\s*([0-9]+)", line)
        if m:
            out.append(int(m.group(1)))
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    keys_text = open(sys.argv[1]).read()
    ct_text = open(sys.argv[2]).read()

    ns = parse_numbers(keys_text, "n")
    es = parse_numbers(keys_text, "e")
    cs = parse_numbers(ct_text, "c")

    if not es:
        es = [3] * len(ns)
    e = es[0]
    if len(set(es)) != 1:
        print(f"[!] exponents differ {es}; this script assumes a single shared e. "
              f"Using e={e}.")

    print(f"Parsed {len(ns)} modulus/moduli, {len(cs)} ciphertext(s), e = {e}\n")

    # ---- CASE A: try a direct e-th root on each ciphertext ----
    print("== Case A: direct e-th root (works if m^e < n) ==")
    for i, c in enumerate(cs, 1):
        r, exact = iroot(c, e)
        if exact:
            txt, raw = to_text(r)
            print(f"  c{i}: EXACT {e}-th root found.")
            print(f"       m = {r}")
            print(f"       bytes = {raw!r}")
            print(f"       utf-8 = {txt}")
            return
        else:
            print(f"  c{i}: no exact root (message wrapped around this modulus)")

    # ---- CASE B: Hastad broadcast via CRT ----
    print("\n== Case B: Hastad broadcast (CRT over all keys) ==")
    if len(cs) < e or len(ns) < e:
        print(f"  need at least e={e} (ciphertext, modulus) pairs; "
              f"have {min(len(cs), len(ns))}.")
        return
    residues = cs[:e]
    moduli = ns[:e]
    C, N = crt(residues, moduli)
    r, exact = iroot(C, e)
    txt, raw = to_text(r)
    print(f"  CRT combine -> C = m^{e} mod (product of {e} moduli)")
    print(f"  {e}-th root exact: {exact}")
    print(f"  m = {r}")
    print(f"  bytes = {raw!r}")
    print(f"  utf-8 = {txt}")


if __name__ == "__main__":
    main()
