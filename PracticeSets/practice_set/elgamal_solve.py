#!/usr/bin/env python3
"""
elgamal_solve.py  —  ElGamal CTF-solver met automatische herkenning.

    python3 -I elgamal_solve.py challenge.json
    python3 -I elgamal_solve.py challenge.json --flag cns

ELGAMAL IN 4 REGELS
    publieke sleutel : p (priem), g (generator), y = g^x mod p
    privésleutel     : x
    encryptie        : kies nonce k,  c1 = g^k mod p,  c2 = m * y^k mod p
    decryptie        : s = c1^x = y^k (gedeeld geheim),  m = c2 * s^-1 mod p

De volledige veiligheid hangt aan k: geheim, willekeurig en NOOIT hergebruikt.

AANVALLEN (script probeert ze in deze volgorde):
  1. x gegeven            -> m = c2 * c1^(-x)                 (gewoon decrypteren)
  2. k gegeven (gelekt)   -> m = c2 * y^(-k)
  3. NONCE HERGEBRUIK     -> twee ciphertexts met DEZELFDE c1, één plaintext bekend:
                             s = c2_known * m_known^-1   (= y^k)
                             m_flag = c2_flag * s^-1
                             (geen x nodig!)
  4. kleine nonce k       -> brute force k uit c1 = g^k  (baby-step giant-step)
  5. zwakke p             -> discrete log van y: x uit y = g^x
                             (Pohlig-Hellman als p-1 "smooth" is, BSGS als p klein is)
                             daarna gewone decryptie

INVOER (JSON, namen flexibel):
    p, g, y (of h / pub / public_key), optioneel x / k
    known_plaintext (tekst of getal), cipher_known [c1, c2]
    cipher_flag [c1, c2]   — of 'ciphertext', 'c', een lijst van paren (blokken)
    Losse c1/c2 velden mogen ook.

DECODERING: m = bytes_to_long(FLAG) -> FLAG = long_to_bytes(m)  (big-endian).
"""
import sys, json, random
from math import gcd, isqrt


# ---------------------------------------------------------------- helpers
def long_to_bytes(m):
    if m == 0:
        return b"\x00"
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def bytes_to_long(b):
    return int.from_bytes(b, "big")


def to_int(v):
    """known_plaintext kan tekst, hex of getal zijn."""
    if isinstance(v, int):
        return v
    s = str(v)
    if s.isdigit():
        return int(s)
    return bytes_to_long(s.encode())


def show(m):
    b = long_to_bytes(m)
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return repr(b)


def looks_ok(txt, hint):
    if hint and hint in txt:
        return True
    return txt and sum(32 <= ord(c) < 127 for c in txt) >= 0.85 * len(txt)


def is_prime(n):
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % q == 0:
            return n == q
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


def rho(n, cap=3_000_000):
    if n % 2 == 0:
        return 2
    for _ in range(6):
        c = random.randrange(1, n)
        x = y = random.randrange(2, n)
        d, steps = 1, 0
        while d == 1 and steps < cap:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = gcd(abs(x - y), n)
            steps += 1
        if 1 < d < n:
            return d
    return None


def factorize(n, limit=1_000_000):
    """Factoriseer n (voor p-1). Geeft dict {priem: exponent} of None als te moeilijk."""
    fac = {}
    for q in [2] + list(range(3, limit, 2)):
        if q * q > n:
            break
        while n % q == 0:
            fac[q] = fac.get(q, 0) + 1
            n //= q
    stack = [n] if n > 1 else []
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if is_prime(m):
            fac[m] = fac.get(m, 0) + 1
            continue
        if m.bit_length() > 140:
            return None, fac, m          # te groot restdeel
        f = rho(m)
        if not f:
            return None, fac, m
        stack += [f, m // f]
    return fac, fac, 1


def bsgs(g, h, p, order, max_m=2**24):
    """Los g^x = h mod p op met x < order. None als order te groot is."""
    m = isqrt(order) + 1
    if m > max_m:
        return None
    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * g % p
    factor = pow(g, -m, p)
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    return None


def pohlig_hellman(g, h, p):
    """Discrete log als p-1 smooth is. Geeft x of None."""
    N = p - 1
    fac, partial, rest = factorize(N)
    if fac is None:
        return None, partial, rest
    residues, moduli = [], []
    for q, e in fac.items():
        qe = q ** e
        if q > 2**48:
            return None, fac, q       # factor te groot voor BSGS
        g_i = pow(g, N // qe, p)
        h_i = pow(h, N // qe, p)
        # los stap voor stap op modulo q^e
        x_i = 0
        gamma = pow(g_i, q ** (e - 1), p)
        for k in range(e):
            hk = pow(pow(g_i, -x_i, p) * h_i % p, q ** (e - 1 - k), p)
            d = bsgs(gamma, hk, p, q)
            if d is None:
                return None, fac, q
            x_i += d * q ** k
        residues.append(x_i)
        moduli.append(qe)
    # CRT
    x, M = 0, 1
    for m in moduli:
        M *= m
    for r, m in zip(residues, moduli):
        Mi = M // m
        x += r * Mi * pow(Mi, -1, m)
    return x % M, fac, None


# ---------------------------------------------------------------- parse
def first(d, *names):
    for n in names:
        if n in d:
            return d[n]
    return None


def pairs_from(v):
    """[c1,c2] -> [(c1,c2)];  [[c1,c2],[c1,c2]] -> lijst paren; {"c1":..,"c2":..} -> paar."""
    if v is None:
        return []
    if isinstance(v, dict):
        return [(int(v.get("c1", v.get("a"))), int(v.get("c2", v.get("b"))))]
    if isinstance(v, list) and v and isinstance(v[0], list):
        return [(int(a), int(b)) for a, b in v]
    if isinstance(v, list) and len(v) == 2:
        return [(int(v[0]), int(v[1]))]
    return []


def load(path):
    d = {k.lower(): v for k, v in json.load(open(path)).items()}
    P = {
        "p": int(first(d, "p", "prime", "modulus")),
        "g": int(first(d, "g", "generator", "alpha") or 2),
        "y": first(d, "y", "h", "pub", "public_key", "beta", "a"),
        "x": first(d, "x", "priv", "private_key", "secret"),
        "k": first(d, "k", "nonce", "ephemeral"),
        "known_m": first(d, "known_plaintext", "known_message", "plaintext_known", "known"),
        "known_c": pairs_from(first(d, "cipher_known", "known_ciphertext", "ciphertext_known")),
        "flag_c": pairs_from(first(d, "cipher_flag", "flag_ciphertext", "ciphertext", "c", "cipher")),
    }
    if not P["flag_c"] and "c1" in d and "c2" in d:
        P["flag_c"] = [(int(d["c1"]), int(d["c2"]))]
    for k in ("y", "x", "k"):
        if P[k] is not None:
            P[k] = int(P[k])
    if P["known_m"] is not None:
        if isinstance(P["known_m"], list):          # meerdere bekende blokken
            P["known_m"] = [to_int(v) for v in P["known_m"]]
        else:
            P["known_m"] = to_int(P["known_m"])
    return P


# ---------------------------------------------------------------- decrypt helpers
def dec_with_x(pairs, x, p):
    return [c2 * pow(pow(c1, x, p), -1, p) % p for c1, c2 in pairs]


def dec_with_k(pairs, k, y, p):
    s_inv = pow(pow(y, k, p), -1, p)
    return [c2 * s_inv % p for _, c2 in pairs]


def join(ms):
    return "".join(show(m) for m in ms)


# ---------------------------------------------------------------- solve
def solve(path, hint="cns"):
    P = load(path)
    p, g, y = P["p"], P["g"], P["y"]
    flag_c = P["flag_c"]
    print("=" * 62)
    print(f"p: {p.bit_length()} bits   g = {g}   y {'aanwezig' if y else 'ONTBREEKT'}")
    print(f"flag-ciphertext: {len(flag_c)} paar/paren   "
          f"bekend paar: {len(P['known_c'])}   bekende plaintext: "
          f"{'ja' if P['known_m'] is not None else 'nee'}")
    print("=" * 62)

    def done(name, ms):
        txt = join(ms)
        ok = looks_ok(txt, hint)
        print(f"\n[{'+' if ok else '?'}] {name}\n    {txt}")
        return ok

    # 1. x gegeven
    if P["x"] is not None:
        if done("x gegeven -> gewone decryptie", dec_with_x(flag_c, P["x"], p)):
            return

    # 2. k gegeven
    if P["k"] is not None and y:
        if done("nonce k gegeven -> m = c2 * y^-k", dec_with_k(flag_c, P["k"], y, p)):
            return

    # 3. nonce hergebruik
    c1s_flag = {c1 for c1, _ in flag_c}
    c1s_known = {c1 for c1, _ in P["known_c"]}
    shared = c1s_flag & c1s_known
    if shared:
        print(f"\n[!] NONCE HERGEBRUIK: {len(shared)} gelijke c1-waarde(n) "
              f"tussen bekend en flag-ciphertext.")
    if shared and P["known_m"] is not None:
        # s = y^k per c1 uit de bekende paren
        s_by_c1 = {}
        km = P["known_m"] if isinstance(P["known_m"], list) else [P["known_m"]]
        if len(km) != len(P["known_c"]):
            print(f"    [!] {len(P['known_c'])} bekende paren maar {len(km)} bekende "
                  f"plaintext(s): geef known_plaintext als lijst, één per blok.")
        for (c1, c2), m_known in zip(P["known_c"], km):
            s_by_c1[c1] = c2 * pow(m_known, -1, p) % p      # s = y^k
        ms = []
        for c1, c2 in flag_c:
            if c1 in s_by_c1:
                ms.append(c2 * pow(s_by_c1[c1], -1, p) % p)
            else:
                ms = None; break
        if ms and done("nonce hergebruik: m_flag = c2_flag * c2_known^-1 * m_known", ms):
            return
    elif shared:
        print("    maar geen bekende plaintext -> je kent alleen m_flag / m_known "
              "(verhouding). Zoek een bekende plaintext!")

    # 4. kleine nonce: c1 = g^k met kleine k
    for c1, _ in flag_c[:1]:
        k = bsgs(g, c1, p, 2**40)
        if k is not None and y:
            print(f"\n[!] kleine nonce gevonden: k = {k}")
            if done("kleine nonce -> m = c2 * y^-k", dec_with_k(flag_c, k, y, p)):
                return

    # 5. discrete log van y (zwakke p)
    if y:
        x, fac, blocker = pohlig_hellman(g, y, p)
        if x is not None and pow(g, x, p) == y:
            print(f"\n[!] discrete log gelukt (p-1 smooth): x = {x}")
            if done("Pohlig-Hellman -> x -> decryptie", dec_with_x(flag_c, x, p)):
                return
        else:
            print(f"\n[i] discrete log van y niet haalbaar "
                  f"(p-1 heeft een grote priemfactor ~{blocker.bit_length() if blocker else '?'} bits)"
                  f" -> p is sterk; de zwakte zit elders (nonce).")

    print("\nGeen aanval gaf leesbare tekst. Check de JSON-velden of zoek een andere zwakte.")


if __name__ == "__main__":
    args = sys.argv[1:]
    hint = "cns"
    if "--flag" in args:
        i = args.index("--flag"); hint = args[i + 1]; del args[i:i + 2]
    if not args:
        print(__doc__); sys.exit(1)
    solve(args[0], hint)
