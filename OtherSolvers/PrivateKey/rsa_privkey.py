#!/usr/bin/env python3
"""
rsa_privkey.py  —  je HEBT de RSA-privésleutel: gewoon decrypteren (en meer).

    python3 -I rsa_privkey.py challenge.json

Dit is het simpele geval: geen aanval nodig, je bezit de geheime sleutel. Het
script accepteert elke vorm waarin de privésleutel gegeven kan zijn:
    - d + n                 -> decrypteer rechtstreeks
    - p + q (+ e)           -> d = e^-1 mod (p-1)(q-1), dan decrypteer
    - d + e + n (geen p,q)  -> BONUS: reconstrueer p en q uit d (zie onder),
                               handig als een vervolgvraag p of q wil
Ciphertext mag:
    - één getal c / ciphertext
    - een lijst 'ciphertext' met 'block_size' (+ 'original_length')  [block-mode]

BONUS — waarom "d krijgen" net zo erg is als "p,q krijgen":
Met (n, e, d) kun je n FACTORISEREN. e*d-1 = k*phi is een veelvoud van phi;
kies willekeurige a, neem herhaald vierkantswortels van a^(e*d-1) tot je een
niet-triviale vierkantswortel van 1 vindt -> gcd(x-1, n) = p. Dus de privé-
exponent lekt de volledige sleutel. Het script doet dit automatisch.
"""
import sys, json, random
from math import gcd


def long_to_bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b"\x00"


def factor_from_d(n, e, d):
    """Herstel (p, q) uit (n, e, d).  Standaardalgoritme."""
    k = e * d - 1
    t = k
    while t % 2 == 0:
        t //= 2
    for _ in range(100):
        a = random.randrange(2, n - 1)
        x = pow(a, t, n)
        while x != 1 and x != n - 1:
            y = x * x % n
            if y == 1 and x != 1 and x != n - 1:
                p = gcd(x - 1, n)
                return p, n // p
            x = y
    return None


def decrypt(d, n, data):
    if isinstance(data.get("ciphertext"), list) and data.get("block_size"):
        bs = int(data["block_size"]); out = bytearray()
        for c in data["ciphertext"]:
            out += pow(int(c), d, n).to_bytes(bs, "big")
        return bytes(out[:int(data.get("original_length", len(out)))])
    c = data.get("c")
    if c is None:
        c = data.get("ciphertext")
    if c is None:
        return None
    return long_to_bytes(pow(int(c), d, n))


def main():
    data = {k.lower(): v for k, v in json.load(open(sys.argv[1])).items()}
    e = int(data.get("e", 65537))
    p = data.get("p"); q = data.get("q"); d = data.get("d"); n = data.get("n")
    p = int(p) if p is not None else None
    q = int(q) if q is not None else None
    d = int(d) if d is not None else None
    n = int(n) if n is not None else None

    if p and q:
        n = n or p * q
        phi = (p - 1) * (q - 1)
        d = d or pow(e, -1, phi)
        print(f"[i] p,q gegeven -> d berekend")
    elif d and n:
        print(f"[i] d gegeven")
        pq = factor_from_d(n, e, d)
        if pq:
            p, q = pq
            print(f"[+] bonus: n gefactoriseerd uit d -> p = {p}\n"
                  f"                                      q = {q}")
    else:
        print("[-] geen bruikbare privésleutel (geef d+n of p+q)."); return

    msg = decrypt(d, n, data)
    if msg is None:
        print(f"[i] geen ciphertext in bestand; sleutel staat klaar: d = {d}")
        return
    try:
        print("\n[+] bericht:", msg.decode())
    except UnicodeDecodeError:
        print("\n[+] bericht (bytes):", msg)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    main()
