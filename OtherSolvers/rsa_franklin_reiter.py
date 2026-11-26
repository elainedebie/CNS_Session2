#!/usr/bin/env python3
"""
rsa_franklin_reiter.py  —  Franklin-Reiter: twee GERELATEERDE berichten, zelfde n, kleine e.

    python3 -I rsa_franklin_reiter.py challenge.json

WANNEER: twee ciphertexts onder DEZELFDE publieke sleutel (n, e), en je weet dat
de twee plaintexts een bekende lineaire relatie hebben:  m2 = a*m1 + b  (mod n).
Typisch: "hetzelfde bericht met een andere aanhef", "m en m+1", "bericht met een
teller erin". e is klein (meestal 3).

IDEE: m1 is een wortel van beide veeltermen (mod n):
      f1(x) = x^e - c1
      f2(x) = (a*x + b)^e - c2
Dus (x - m1) deelt beide. Bereken gcd(f1, f2) in (Z/nZ)[x]; dat is lineair
(x - m1), en m1 lees je er rechtstreeks uit. Geen factorisatie, geen privésleutel.

JSON-velden: n, e, c1, c2, en de relatie a, b  (standaard a=1, b=1 -> m2=m1+1).
            Of 'relation': [a, b].
"""
import sys, json


# ---- veeltermen modulo n (coeff-lijst, laagste graad eerst) ----
def poly_trim(p):
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def poly_mul(a, b, n):
    r = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                r[i + j] = (r[i + j] + ai * bj) % n
    return poly_trim(r)


def poly_sub(a, b, n):
    r = [0] * max(len(a), len(b))
    for i in range(len(r)):
        x = (a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)
        r[i] = x % n
    return poly_trim(r)


def poly_mod(a, b, n):
    """a mod b in (Z/nZ)[x]; faalt (raise) als leidende coeff van b niet inverteerbaar."""
    a = a[:]
    inv = pow(b[-1], -1, n)
    while len(a) >= len(b) and poly_trim(a[:]) != [0]:
        if len(a) < len(b):
            break
        coef = (a[-1] * inv) % n
        shift = len(a) - len(b)
        for i in range(len(b)):
            a[shift + i] = (a[shift + i] - coef * b[i]) % n
        poly_trim(a)
        if len(a) == 1 and a[0] == 0:
            break
    return poly_trim(a)


def poly_gcd(a, b, n):
    while poly_trim(b[:]) != [0]:
        a, b = b, poly_mod(a, b, n)
    return a


def powmod_poly(base, e, modpoly, n):
    # niet nodig hier; e is klein, we bouwen (a x + b)^e direct
    pass


def pow_poly(base, e, n):
    r = [1]
    for _ in range(e):
        r = poly_mul(r, base, n)
    return r


def long_to_bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b"\x00"


def franklin_reiter(n, e, c1, c2, a, b):
    # f1 = x^e - c1
    f1 = [(-c1) % n] + [0] * (e - 1) + [1]
    # f2 = (a x + b)^e - c2
    f2 = pow_poly([b % n, a % n], e, n)
    f2[0] = (f2[0] - c2) % n
    poly_trim(f2)
    g = poly_gcd(f1, f2, n)
    if len(g) != 2:
        return None
    # g = g0 + g1 x  -> m1 = -g0 / g1
    m1 = (-g[0] * pow(g[1], -1, n)) % n
    return m1


def main():
    d = json.load(open(sys.argv[1]))
    n, e = int(d["n"]), int(d.get("e", 3))
    c1, c2 = int(d["c1"]), int(d["c2"])
    rel = d.get("relation")
    if rel:
        a, b = int(rel[0]), int(rel[1])
    else:
        a, b = int(d.get("a", 1)), int(d.get("b", 1))
    print(f"[i] n: {n.bit_length()} bits, e = {e}, relatie m2 = {a}*m1 + {b}")
    m1 = franklin_reiter(n, e, c1, c2, a, b)
    if m1 is None:
        print("[-] gcd was niet lineair -> klopt de relatie (a,b) of e? Probeer "
              "andere a,b of controleer welk bericht c1/c2 is.")
        return
    print(f"[+] m1 hersteld")
    for naam, m in (("m1", m1), ("m2", (a * m1 + b) % n)):
        b_ = long_to_bytes(m)
        try:
            print(f"    {naam} = {b_.decode()}")
        except UnicodeDecodeError:
            print(f"    {naam} = {b_!r}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    main()
