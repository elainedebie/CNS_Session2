#!/usr/bin/env python3
"""
elgamal_privkey.py  —  je HEBT de ElGamal-privésleutel x: gewoon decrypteren.

    python3 -I elgamal_privkey.py challenge.json

ElGamal: publiek (p, g, y=g^x), privé x. Ciphertext (c1, c2).
Decryptie:  s = c1^x mod p   (het gedeelde geheim y^k),  m = c2 * s^-1 mod p.

Het script accepteert:
    - x gegeven                 -> decrypteer rechtstreeks
    - (geen x maar) k gegeven   -> s = y^k, zelfde decryptie zonder x
Ciphertext mag:
    - één paar: cipher_flag / ciphertext / c = [c1, c2]  (of velden c1, c2)
    - meerdere paren: lijst van [c1, c2]  (blokken) -> aaneengeplakt
Decodering: m = bytes_to_long(FLAG) -> FLAG = long_to_bytes(m) (big-endian).
"""
import sys, json


def long_to_bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b"\x00"


def pairs(v):
    if v is None:
        return []
    if isinstance(v, dict):
        return [(int(v.get("c1", v.get("a"))), int(v.get("c2", v.get("b"))))]
    if isinstance(v, list) and v and isinstance(v[0], list):
        return [(int(a), int(b)) for a, b in v]
    if isinstance(v, list) and len(v) == 2:
        return [(int(v[0]), int(v[1]))]
    return []


def main():
    d = {k.lower(): v for k, v in json.load(open(sys.argv[1])).items()}
    p = int(d["p"]); g = int(d.get("g", 2))
    y = d.get("y") or d.get("h")
    y = int(y) if y is not None else None
    x = d.get("x"); k = d.get("k")
    x = int(x) if x is not None else None
    k = int(k) if k is not None else None

    cts = pairs(d.get("cipher_flag") or d.get("ciphertext") or d.get("c") or d.get("cipher"))
    if not cts and "c1" in d and "c2" in d:
        cts = [(int(d["c1"]), int(d["c2"]))]
    if not cts:
        print("[-] geen ciphertext (c1,c2) gevonden."); return

    out = []
    for c1, c2 in cts:
        if x is not None:
            s = pow(c1, x, p)                 # = y^k
        elif k is not None and y is not None:
            s = pow(y, k, p)
        else:
            print("[-] geef x (privésleutel) of k (nonce)."); return
        m = c2 * pow(s, -1, p) % p
        out.append(m)

    txt = "".join(long_to_bytes(m).decode(errors="replace") for m in out)
    print(f"[i] {'x' if x is not None else 'k'} gebruikt, {len(cts)} blok(ken)")
    print("\n[+] bericht:", txt)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    main()
