#!/usr/bin/env python3
"""
rsa_lsb_oracle.py  —  LSB / parity decryptie-oracle aanval.

    python3 -I rsa_lsb_oracle.py --demo                # gesimuleerde oracle (test)
    (echte opgave: vul oracle() hieronder in met je server-call)

WANNEER: de opgave geeft je een service die ciphertexts decrypteert en per keer
IETS lekt over de plaintext -- meestal de laatste bit (even/oneven) of of de
decryptie > n/2 is. Je mag onbeperkt (of veel) queries doen. Je hebt (n, e) en
een doel-ciphertext c, en je wil m.

IDEE (binary search): kies een ciphertext voor 2^i * m door c te vermenigvuldigen
met 2^e. De oracle vertelt je telkens de pariteit van 2^i*m mod n. Omdat n oneven
is, vertelt elke verdubbeling je of m in de boven- of onderhelft van het huidige
interval ligt. Na ~log2(n) queries is het interval tot 1 getal gekrompen = m.

Dit is de kern van waarom "een beetje info lekken" per decryptie fataal is.
"""
import sys, hashlib
from fractions import Fraction


def long_to_bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b"\x00"


def lsb_attack(n, e, c, oracle):
    """oracle(ciphertext) -> int 0/1 = pariteit (laatste bit) van de plaintext."""
    lo, hi = Fraction(0), Fraction(n)
    mult = pow(2, e, n)
    cc = c
    for _ in range(n.bit_length()):
        cc = (cc * mult) % n            # ciphertext voor 2*m
        bit = oracle(cc)
        mid = (lo + hi) / 2
        if bit == 0:                    # 2*m mod n is even -> geen wrap -> m < mid
            hi = mid
        else:                           # oneven -> wrap -> m > mid
            lo = mid
    from math import floor
    return int(hi)                      # afronden naar boven geeft m


# --------- demo-oracle (gesimuleerd), zodat je de aanval kan testen ----------
def build_demo():
    import random
    def randprime(bits):
        while True:
            x = random.getrandbits(bits) | (1 << (bits-1)) | 1
            if all(x % p for p in (3,5,7,11,13,17,19,23)) and pow(2, x-1, x) == 1:
                return x
    p, q = randprime(256), randprime(256)
    n = p*q; e = 65537; phi = (p-1)*(q-1); d = pow(e, -1, phi)
    secret = b"cns{lsb_oracle_leaks_everything}"
    m = int.from_bytes(secret, "big")
    c = pow(m, e, n)
    def oracle(ciph):                   # lekt de laatste bit van de decryptie
        return pow(ciph, d, n) & 1
    return n, e, c, oracle


def main():
    if "--demo" in sys.argv:
        n, e, c, oracle = build_demo()
        print(f"[i] demo: n {n.bit_length()} bits")
        m = lsb_attack(n, e, c, oracle)
        print("[+] hersteld:", long_to_bytes(m).decode(errors="replace"))
    else:
        print(__doc__)
        print("Voor een echte opgave: vervang build_demo()/oracle door een functie\n"
              "die jouw server aanroept en de gelekte bit teruggeeft, en roep\n"
              "lsb_attack(n, e, c, oracle) aan.")


if __name__ == "__main__":
    main()
