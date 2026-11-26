#!/usr/bin/env python3
"""
rsa_cca.py  —  chosen-ciphertext / malleability aanval op textbook-RSA (slide 56).

    python3 -I rsa_cca.py --demo

WANNEER: er is een decryptie-orakel (een service die ciphertexts voor je
ontsleutelt), maar het weigert JOUW doel-ciphertext c zelf te decrypteren.
RSA zonder padding is MALLEABLE:  E(M1)*E(M2) = E(M1*M2).

AANVAL (uit de slides):
  1. kies factor t (meestal 2), bereken  X = c * t^e mod n
  2. geef X aan het orakel -> krijg  Y = X^d = (t*M)  mod n
  3. deel weg:  M = Y * t^-1 mod n
Het orakel ziet een andere ciphertext (X != c), dus de weigering op c helpt niet.
Tegenmaatregel: padding (OAEP) -> dan geldt E(M1)*E(M2)=E(M1*M2) niet meer.

Voor een echte opgave: vervang het demo-orakel door je server-call (die X stuurt
en Y=X^d teruggeeft), en roep cca_recover(n, e, c, oracle) aan.
"""
import sys, random


def long_to_bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b"\x00"


def cca_recover(n, e, c, oracle, t=2):
    X = c * pow(t, e, n) % n          # E(t*M) = E(M)*E(t)
    Y = oracle(X)                     # = t*M mod n
    return Y * pow(t, -1, n) % n      # M


def build_demo():
    def randprime(b):
        while True:
            x = random.getrandbits(b) | (1 << (b-1)) | 1
            if all(x % p for p in (3,5,7,11,13,17,19,23,29,31)) and pow(2, x-1, x) == 1:
                return x
    p, q = randprime(256), randprime(256)
    n = p*q; e = 65537; d = pow(e, -1, (p-1)*(q-1))
    secret = b"cns{rsa_is_malleable_without_padding}"
    c = pow(int.from_bytes(secret, "big"), e, n)
    target = c
    def oracle(x):                   # decrypteert alles BEHALVE de doel-ciphertext
        if x % n == target:
            raise ValueError("orakel weigert de doel-ciphertext")
        return pow(x, d, n)
    return n, e, c, oracle


def main():
    if "--demo" in sys.argv:
        n, e, c, oracle = build_demo()
        print(f"[i] demo: n {n.bit_length()} bits; orakel weigert c zelf")
        m = cca_recover(n, e, c, oracle)
        print("[+] hersteld:", long_to_bytes(m).decode(errors="replace"))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
