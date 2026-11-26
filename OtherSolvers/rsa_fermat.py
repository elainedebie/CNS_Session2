#!/usr/bin/env python3
"""
rsa_fermat.py  —  Fermat-factorisatie: p en q liggen DICHT bij elkaar.

    python3 -I rsa_fermat.py challenge.json        # velden: n, e, c (of ciphertext+block)

WANNEER: de opgave zegt iets als "de twee priemen zijn vlak bij elkaar gekozen",
"opeenvolgende priemen", "p en q verschillen weinig", of je ziet een enorme n
die rho/trial NIET kraakt maar waarvan de priemen toch close zijn.

IDEE: als p,q dicht bij elkaar liggen, dan is n = a^2 - b^2 = (a-b)(a+b) met
a ~ sqrt(n) en b klein. Begin bij a = ceil(sqrt(n)) en tel op tot a^2 - n een
perfect kwadraat is. Werkt razendsnel als |p-q| klein is, ongeacht de grootte
van n (zelfs 1024-bit!). Hoe verder p en q uiteen, hoe trager -> dan is dit
NIET de aanval.

VERSCHIL MET gewone factorisatie: Pollard rho hangt af van de KLEINSTE priem
(onhaalbaar bij twee grote priemen). Fermat hangt af van |p-q| (de AFSTAND).
"""
import sys, json
from math import isqrt


def long_to_bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b"\x00"


def fermat(n, max_iter=10_000_000):
    a = isqrt(n)
    if a * a < n:
        a += 1
    for i in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b, i
        a += 1
    return None


def main():
    d = json.load(open(sys.argv[1]))
    n, e = int(d["n"]), int(d.get("e", 65537))
    res = fermat(n)
    if not res:
        print("[-] geen close-prime factorisatie gevonden -> p en q liggen te ver "
              "uiteen; probeer een andere aanval (rho/Wiener/...).")
        return
    p, q, iters = res
    print(f"[+] Fermat gelukt na {iters} stappen (|p-q| = {abs(p-q)})")
    print(f"    p = {p}\n    q = {q}")
    phi = (p - 1) * (q - 1)
    dkey = pow(e, -1, phi)
    # decrypt
    if "ciphertext" in d and isinstance(d["ciphertext"], list):
        bs = int(d["block_size"]); out = bytearray()
        for c in d["ciphertext"]:
            out += pow(int(c), dkey, n).to_bytes(bs, "big")
        msg = bytes(out[:int(d.get("original_length", len(out)))])
    else:
        c = int(d.get("c") or d.get("ciphertext"))
        msg = long_to_bytes(pow(c, dkey, n))
    try:
        print("\n[+] bericht:", msg.decode())
    except UnicodeDecodeError:
        print("\n[+] bericht (bytes):", msg)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    main()
