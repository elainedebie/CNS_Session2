#!/usr/bin/env python3
"""
make_practice.py  —  genereert oefenopgaven voor asymmetric encryption.

    python3 -I make_practice.py            # 9 opgaven in ./practice_set/, random volgorde
    python3 -I make_practice.py 20         # 20 opgaven (types herhalen)

Elke opgave staat in het exam-formaat, zodat je solvers er direct op werken:
  challenge_NN.json  (of _keys.txt + _cts.txt voor broadcast)
De flags zijn verborgen; ANSWERS.txt bevat per opgave het TYPE en de flag,
zodat je jezelf kan testen. Workflow:
    1. open challenge_NN, raad het type (gebruik solutions/00-decision-guide.md)
    2. draai de juiste solver (rsa_solve.py / elgamal_solve.py)
    3. check tegen ANSWERS.txt
"""
import json, os, random, sys, hashlib

# ----------------------------------------------------------- priemgetallen
def is_prime(n):
    if n < 2: return False
    for q in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % q == 0: return n == q
    d, s = n-1, 0
    while d % 2 == 0: d //= 2; s += 1
    for a in (2,3,5,7,11,13,17,19,23,29,31,37):
        x = pow(a, d, n)
        if x in (1, n-1): continue
        for _ in range(s-1):
            x = x*x % n
            if x == n-1: break
        else: return False
    return True

def randprime(bits):
    while True:
        c = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_prime(c): return c

def safe_prime(bits):
    while True:
        q = randprime(bits-1)
        if is_prime(2*q+1): return 2*q+1

b2l = lambda s: int.from_bytes(s.encode(), "big")

WORDS = ["falcon","sunset","copper","lychee","gravity","marble","tundra","zephyr",
         "quartz","ember","willow","cobalt","nimbus","saffron","onyx","cedar"]
def flag():
    return "cns{" + "_".join(random.sample(WORDS, 3)) + "}"

# ----------------------------------------------------------- RSA generators
def rsa_keypair(bits, e=65537):
    while True:
        p, q = randprime(bits), randprime(bits)
        if p == q: continue
        phi = (p-1)*(q-1)
        from math import gcd
        if gcd(e, phi) == 1:
            return p, q, p*q, e, pow(e, -1, phi)

def g_broadcast_A():
    # kleine e=3, m^3 < n -> directe derdemachtswortel
    f = flag(); m = b2l(f)
    keys, cts = [], []
    for _ in range(3):
        n = randprime(600) * randprime(600)      # ~1200-bit n, ruim > m^3
        keys.append((n, 3)); cts.append(pow(m, 3, n))
    return ("RSA broadcast Case A (kleine e, geen wraparound -> derdemachtswortel)",
            f, ("txt", keys, cts))

def g_broadcast_B():
    # e=3, m^3 > n -> Hastad CRT nodig
    f = flag(); m = b2l(f)
    keys, cts = [], []
    while len(keys) < 3:
        n = randprime(256) * randprime(256)      # ~512-bit n, m^3 wrapt
        if m < n:
            keys.append((n, 3)); cts.append(pow(m, 3, n))
    return ("RSA Hastad broadcast Case B (e=3, ciphertexts verschillen -> CRT)",
            f, ("txt", keys, cts))

def g_factor():
    # kleine n (~66-bit, vlot met Pollard rho) + block-mode zoals het echte exam,
    # zodat een volledige flag past (elk blok < n).
    f = flag(); data = f.encode()
    p, q = randprime(34), randprime(34)          # n ~68-bit: rho kraakt dit direct
    n = p*q; e = 65537
    from math import gcd
    while gcd(e, (p-1)*(q-1)) != 1: e += 2
    bs = 8                                        # 64-bit blokken < 68-bit n
    padded = data + b"\x00" * ((-len(data)) % bs)
    blocks = [int.from_bytes(padded[i:i+bs], "big") for i in range(0, len(padded), bs)]
    ct = [pow(mblk, e, n) for mblk in blocks]
    return ("RSA kleine n (factoriseren, block-mode zoals het exam)", f,
            ("json", {"n": n, "e": e, "ciphertext": ct,
                      "block_size": bs, "original_length": len(data)}))

def g_common_modulus():
    f = flag(); m = b2l(f)
    p, q, n, _, _ = rsa_keypair(512)
    e1, e2 = 65537, 17
    return ("RSA common modulus (1 n, 2 exponenten)", f,
            ("json", {"n": n, "e1": e1, "e2": e2,
                      "c1": pow(m, e1, n), "c2": pow(m, e2, n)}))

def g_common_factor():
    f = flag(); m = b2l(f)
    shared = randprime(512)
    q1, q2 = randprime(512), randprime(512)
    n1, n2 = shared*q1, shared*q2
    e = 65537
    return ("RSA common factor (twee n delen een priem; gcd!)", f,
            ("json", {"n1": n1, "e1": e, "c1": pow(m, e, n1),
                      "n2": n2, "e2": e, "c2": pow(m, e, n2)}))

def g_wiener():
    # klein privé-exponent d < n^(1/4)/3
    f = flag(); m = b2l(f)
    while True:
        p, q = randprime(512), randprime(512)
        if p == q: continue
        if q < p: p, q = q, p
        if p < q < 2*p:                          # p,q niet te ver uiteen
            n = p*q; phi = (p-1)*(q-1)
            d = randprime(120)                   # klein d, ~120 bit << n^1/4 (~256)
            from math import gcd
            if gcd(d, phi) != 1: continue
            e = pow(d, -1, phi)
            if e.bit_length() > n.bit_length() - 20:   # e groot => Wiener-vorm
                return ("RSA Wiener (klein d; e enorm, ~grootte van n)", f,
                        ("json", {"n": n, "e": e, "c": pow(m, e, n)}))

# ----------------------------------------------------------- ElGamal generators
def eg_params():
    p = safe_prime(512)
    for g in range(2, 1000):
        if pow(g, 2, p) != 1 and pow(g, (p-1)//2, p) != 1:
            return p, g

def g_eg_nonce_reuse():
    f = flag(); p, g = eg_params()
    x = random.randrange(2, p-2); y = pow(g, x, p)
    k = random.randrange(2, p-2)
    km = "The weather today is sunny"
    enc = lambda m, kk: [pow(g, kk, p), m*pow(y, kk, p) % p]
    return ("ElGamal nonce hergebruik (zelfde c1 + bekende plaintext)", f,
            ("json", {"p": p, "g": g, "y": y, "known_plaintext": km,
                      "cipher_known": enc(b2l(km), k), "cipher_flag": enc(b2l(f), k)}))

def g_eg_small_nonce():
    f = flag(); p, g = eg_params()
    x = random.randrange(2, p-2); y = pow(g, x, p)
    k = random.randrange(2, 2**28)
    return ("ElGamal kleine nonce (brute-force k uit c1)", f,
            ("json", {"p": p, "g": g, "y": y,
                      "cipher_flag": [pow(g, k, p), b2l(f)*pow(y, k, p) % p]}))

GENERATORS = [g_broadcast_A, g_broadcast_B, g_factor, g_common_modulus,
              g_common_factor, g_wiener, g_eg_nonce_reuse, g_eg_small_nonce]

def write(idx, payload):
    kind = payload[0]
    if kind == "txt":
        _, keys, cts = payload
        with open(f"practice_set/challenge_{idx:02d}_keys.txt", "w") as fh:
            for i, (n, e) in enumerate(keys, 1):
                fh.write(f"--- KEY {i} ---\nn = {n}\ne = {e}\n\n")
        with open(f"practice_set/challenge_{idx:02d}_cts.txt", "w") as fh:
            for i, c in enumerate(cts, 1):
                fh.write(f"c{i} = {c}\n")
        return f"challenge_{idx:02d}_keys.txt + _cts.txt"
    else:
        with open(f"practice_set/challenge_{idx:02d}.json", "w") as fh:
            json.dump(payload[1], fh, indent=1)
        return f"challenge_{idx:02d}.json"

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else len(GENERATORS)
    os.makedirs("practice_set", exist_ok=True)
    gens = []
    while len(gens) < n:
        batch = GENERATORS[:]; random.shuffle(batch); gens += batch
    gens = gens[:n]
    answers = []
    for i, gen in enumerate(gens, 1):
        typ, fl, payload = gen()
        fname = write(i, payload)
        answers.append((i, fname, typ, fl))
    with open("practice_set/ANSWERS.txt", "w") as fh:
        fh.write("OEFENSET — antwoordsleutel (pas bekijken NA je poging)\n")
        fh.write("="*60 + "\n")
        for i, fname, typ, fl in answers:
            fh.write(f"\n[{i:02d}] {fname}\n     type : {typ}\n     flag : {fl}\n")
    print(f"{n} opgaven geschreven in practice_set/  (+ ANSWERS.txt)")
    print("Raad het type, draai de juiste solver, check dan ANSWERS.txt.")

if __name__ == "__main__":
    main()
