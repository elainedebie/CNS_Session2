#!/usr/bin/env python3
"""
RSA common-modulus attack.

Scenario: the SAME message m is encrypted under the SAME modulus n but with
TWO different public exponents:
    c1 = m^e1 mod n
    c2 = m^e2 mod n
If gcd(e1, e2) == 1 (which holds for almost any two distinct exponents),
you recover m WITHOUT factoring n and WITHOUT either private key.

Why it works:
    gcd(e1,e2)=1  =>  extended Euclid gives a,b with  a*e1 + b*e2 = 1.
    Then  c1^a * c2^b = m^(a*e1) * m^(b*e2) = m^(a*e1+b*e2) = m^1 = m (mod n).
One of a,b is negative, so for that term use the modular inverse of the
ciphertext: c^(-k) = (c^-1)^k mod n.

The lesson: changing only the exponent is NOT "a new set of keys". Reusing n
across users/exponents breaks RSA whenever the plaintext is shared.

Decoding matches the hint: m = bytes_to_long(FLAG), so FLAG = long_to_bytes(m)
(plain big-endian integer -> bytes).

Usage:
    python3 -I rsa_common_modulus.py challenge.json
challenge.json must contain n, e1, e2, c1, c2.
"""
import sys, json


def egcd(a, b):
    """Return (g, x, y) with a*x + b*y = g = gcd(a,b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def long_to_bytes(m):
    if m == 0:
        return b"\x00"
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def common_modulus(n, e1, e2, c1, c2):
    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError(f"gcd(e1,e2) = {g} != 1; basic attack needs coprime "
                         f"exponents. (If g>1, take the g-th root at the end.)")
    # handle negative exponents via modular inverse of the ciphertext
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n


def main():
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    ch = json.load(open(sys.argv[1]))
    n, e1, e2 = ch["n"], ch["e1"], ch["e2"]
    c1, c2 = ch["c1"], ch["c2"]

    print(f"n  ({n.bit_length()} bits)")
    print(f"e1 = {e1}, e2 = {e2}")
    g, _, _ = egcd(e1, e2)
    print(f"gcd(e1, e2) = {g}\n")

    m = common_modulus(n, e1, e2, c1, c2)
    flag = long_to_bytes(m)
    print(f"[+] recovered m = {m}\n")
    print("[+] FLAG = long_to_bytes(m):")
    print("---------------------------")
    try:
        print(flag.decode("utf-8"))
    except UnicodeDecodeError:
        print(repr(flag))


if __name__ == "__main__":
    main()
