#!/usr/bin/env python3
"""Maakt oefen-challenges voor elke ElGamal-variant in ./elgamal_tests/ ."""
import json, os, random

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

def safe_prime(bits):
    while True:
        q = random.getrandbits(bits-1) | (1 << (bits-2)) | 1
        if is_prime(q) and is_prime(2*q+1): return 2*q+1

def smooth_prime(bits):
    # p-1 = product van kleine priemen -> Pohlig-Hellman werkt
    small = [q for q in range(3, 5000) if is_prime(q)]
    while True:
        n = 2
        while n.bit_length() < bits:
            n *= random.choice(small)
        if is_prime(n+1): return n+1

def gen(p):
    # vind generator: voor safe prime p=2q+1, g met g^2!=1 en g^q!=1
    for g in range(2, 1000):
        if pow(g, 2, p) != 1 and pow(g, (p-1)//2, p) != 1:
            return g
    return 2

b2l = lambda s: int.from_bytes(s.encode(), "big")
os.makedirs("elgamal_tests", exist_ok=True)

def enc(m, p, g, y, k):
    return [pow(g, k, p), m * pow(y, k, p) % p]

def save(name, d):
    json.dump(d, open(f"elgamal_tests/{name}.json", "w"), indent=1)

# sterke p (512-bit safe prime) voor de nonce-varianten
P = safe_prime(512); G = gen(P); X = random.randrange(2, P-2); Y = pow(G, X, P)
FLAG = "cns{test_variant_ok}"

# A. nonce hergebruik, andere veldnamen (h ipv y, ciphertext ipv cipher_flag)
k = random.randrange(2, P-2)
save("A_nonce_reuse_other_names", {"p": P, "g": G, "h": Y,
     "known_message": "hello world", "known_ciphertext": enc(b2l("hello world"), P, G, Y, k),
     "ciphertext": enc(b2l(FLAG), P, G, Y, k)})

# B. nonce hergebruik over meerdere blokken (elk blok eigen k, telkens hergebruikt)
k1, k2 = random.randrange(2, P-2), random.randrange(2, P-2)
save("B_nonce_reuse_blocks", {"p": P, "g": G, "y": Y,
     "known_plaintext": ["AAAA", "BBBB"],
     "cipher_known": [enc(b2l("AAAA"), P, G, Y, k1), enc(b2l("BBBB"), P, G, Y, k2)],
     "cipher_flag": [enc(b2l("cns{blok"), P, G, Y, k1), enc(b2l("ken_ok}"), P, G, Y, k2)]})

# C. x (privésleutel) gegeven
save("C_x_given", {"p": P, "g": G, "y": Y, "x": X,
     "cipher_flag": enc(b2l(FLAG), P, G, Y, random.randrange(2, P-2))})

# D. nonce k gelekt
k = random.randrange(2, P-2)
save("D_k_leaked", {"p": P, "g": G, "y": Y, "k": k, "cipher_flag": enc(b2l(FLAG), P, G, Y, k)})

# E. kleine nonce (k < 2^30)
k = random.randrange(2, 2**30)
save("E_small_nonce", {"p": P, "g": G, "y": Y, "cipher_flag": enc(b2l(FLAG), P, G, Y, k)})

# F. zwakke p: p-1 smooth -> Pohlig-Hellman vindt x
Ps = smooth_prime(256); Gs = gen(Ps)
# kies een generator van de volledige groep
while True:
    Gs = random.randrange(2, Ps-1)
    # check order = p-1 grof: g^((p-1)/q) != 1 voor kleine q in p-1
    n, ok = Ps-1, True
    for q in range(2, 5000):
        if n % q == 0 and is_prime(q) and pow(Gs, (Ps-1)//q, Ps) == 1:
            ok = False; break
    if ok: break
Xs = random.randrange(2, Ps-2); Ys = pow(Gs, Xs, Ps)
save("F_smooth_p", {"p": Ps, "g": Gs, "y": Ys,
     "cipher_flag": enc(b2l("cns{pohlig_hellman}"), Ps, Gs, Ys, random.randrange(2, Ps-2))})

print("tests geschreven in elgamal_tests/")
