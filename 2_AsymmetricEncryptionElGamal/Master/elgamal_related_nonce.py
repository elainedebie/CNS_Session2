#!/usr/bin/env python3
"""
elgamal_related_nonce.py  —  ElGamal met een BEKENDE nonce-relatie k2 = k1 + d.

    python3 -I elgamal_related_nonce.py challenge.json
    python3 -I elgamal_related_nonce.py challenge.json --delta -1

Algemener dan nonce-hergebruik (dat is het geval d=0). Twee berichten onder
dezelfde sleutel, met nonces die een bekend verschil d hebben:
    cipher_known = (c1k, c2k)   met nonce k
    cipher_flag  = (c1f, c2f)   met nonce k + d
en je kent de plaintext van het eerste bericht.

HERKENNEN van d:  c1f = g^(k+d) = c1k * g^d  =>  g^d = c1f * c1k^-1.
Het script probeert d in [-RANGE, RANGE] en vindt de match (geen zoektocht in de
exponent nodig, gewoon kleine d's aftoetsen). Of geef d expliciet met --delta.

HERSTEL:
    y^k   = c2k * m_known^-1                     (gedeeld geheim van bericht 1)
    y^(k+d) = y^k * y^d
    m_flag = c2f * (y^(k+d))^-1
           = c2f * m_known * c2k^-1 * y^(-d)     (mod p)

d = 0  -> klassiek nonce-hergebruik.  d = +1/-1/+2/... -> deze generalisatie.
De les is identiek: de per-bericht nonce moet onafhankelijk en willekeurig zijn;
een vaste STAP tussen nonces (teller, timestamp+1) is net zo fataal als hergebruik.
Decodering: m = bytes_to_long(FLAG) -> long_to_bytes(m), big-endian.
"""
import sys, json

RANGE = 1000          # bereik waarin we een onbekende d zoeken (klein & bekend)


def long_to_bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b"\x00"


def to_int_plain(v):
    if isinstance(v, int):
        return v
    s = str(v)
    return int(s) if s.isdigit() else int.from_bytes(s.encode(), "big")


def pair(v):
    if isinstance(v, dict):
        return int(v.get("c1", v.get("a"))), int(v.get("c2", v.get("b")))
    return int(v[0]), int(v[1])


def detect_delta(c1k, c1f, g, p, rng=RANGE):
    """Zoek d met c1f = c1k * g^d, voor |d| <= rng."""
    target = c1f * pow(c1k, -1, p) % p          # = g^d
    val = 1                                     # g^0
    pos = {}
    gi = 1
    for d in range(rng + 1):                     # g^0..g^rng
        pos[gi] = d
        gi = gi * g % p
    # check d >= 0 en d < 0 (via inverse)
    if target in pos:
        return pos[target]
    ginv = pow(g, -1, p); gi = ginv
    for d in range(1, rng + 1):
        if gi == target:
            return -d
        gi = gi * ginv % p
    return None


def recover(c2k, c2f, m_known, y, d, p):
    yk = c2k * pow(m_known, -1, p) % p           # y^k
    y_kd_inv = pow(yk * pow(y, d, p) % p, -1, p) # (y^(k+d))^-1
    return c2f * y_kd_inv % p


def main():
    args = sys.argv[1:]
    delta = None
    if "--delta" in args:
        i = args.index("--delta"); delta = int(args[i + 1]); del args[i:i + 2]
    d = {k.lower(): v for k, v in json.load(open(args[0])).items()}
    p = int(d["p"]); g = int(d.get("g", 2)); y = int(d.get("y") or d.get("h"))
    m_known = to_int_plain(d.get("known_plaintext") or d.get("known_message"))
    c1k, c2k = pair(d.get("cipher_known") or d.get("known_ciphertext"))
    c1f, c2f = pair(d.get("cipher_flag") or d.get("ciphertext") or d.get("cipher"))
    if delta is None:
        delta = int(d["delta"]) if "delta" in d else detect_delta(c1k, c1f, g, p)
    if delta is None:
        print(f"[-] geen kleine nonce-stap d gevonden in [-{RANGE},{RANGE}]. "
              f"Geef --delta, of de relatie is niet additief-constant."); return
    print(f"[i] nonce-relatie: k_flag = k_known + ({delta})"
          + ("   (= nonce-hergebruik)" if delta == 0 else ""))
    m = recover(c2k, c2f, m_known, y, delta, p)
    b = long_to_bytes(m)
    try:
        print("\n[+] flag:", b.decode())
    except UnicodeDecodeError:
        print("\n[+] flag (bytes):", b)


if __name__ == "__main__":
    if not sys.argv[1:]:
        print(__doc__); sys.exit(1)
    main()
