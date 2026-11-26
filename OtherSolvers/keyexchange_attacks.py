#!/usr/bin/env python3
"""
keyexchange_attacks.py  —  aanvallen op sleuteldistributie / sleuteluitwisseling.

    python3 -I keyexchange_attacks.py --demo all      # alle aanvallen gesimuleerd
    python3 -I keyexchange_attacks.py --demo mitm      # één specifieke demo

De rode draad: een directory/kanaal ZONDER authenticatie. Je kunt dan sleutels
substitueren of ONTAARDE sleutels injecteren, zodat het gedeelde geheim bekend
of klein wordt. Per aanval staat hieronder (a) wanneer, (b) de truc, (c) een
gesimuleerde demo, (d) hoe je het op een echte server inplugt.

OVERZICHT
  1. elgamal_directory  - registreer een sleutel die jij beheert / y=1-truc
  2. dh_mitm            - Diffie-Hellman via directory: sta in het midden
  3. degenerate_key     - y in {1, p-1, 0}  -> gedeeld geheim = 1 / +-1 / 0
  4. small_subgroup     - registreer element van KLEINE orde -> geheim lekt, CRT
  5. weak_params        - p-1 smooth -> discrete log van de publieke sleutel
"""
import sys, hashlib, random
from math import gcd


# ============================ hulp ============================
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
        x = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_prime(x): return x

def safe_prime(bits):
    while True:
        q = randprime(bits-1)
        if is_prime(2*q+1): return 2*q+1

def kdf(shared, p):
    return hashlib.sha256(str(shared).encode()).digest()

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def bsgs(g, h, p, order):
    from math import isqrt
    m = isqrt(order) + 1
    tbl = {}; e = 1
    for j in range(m):
        tbl.setdefault(e, j); e = e*g % p
    fac = pow(g, -m, p); gamma = h
    for i in range(m):
        if gamma in tbl: return i*m + tbl[gamma]
        gamma = gamma*fac % p
    return None


# ============================ 1. ElGamal directory ============================
def demo_elgamal_directory():
    print(">> 1. ElGamal directory zonder authenticatie")
    p, g = safe_prime(256), 2
    # Alice heeft een geheim en stuurt het ElGamal-versleuteld naar 'de sleutel onder naam X'
    secret = b"cns{directory_no_auth}"
    m = int.from_bytes(secret, "big")
    def alice_encrypt_to(y):
        k = random.randrange(2, p-2)
        return pow(g, k, p), m * pow(y, k, p) % p
    # AANVAL A: registreer eigen sleutel met bekende x
    x = random.randrange(2, p-2); y = pow(g, x, p)
    c1, c2 = alice_encrypt_to(y)                 # Alice stuurt naar jouw entry
    rec = c2 * pow(pow(c1, x, p), -1, p) % p
    print("   eigen sleutel:", int.to_bytes(rec,(rec.bit_length()+7)//8,"big").decode())
    # AANVAL B: registreer y=1 -> c2 = m rechtstreeks
    c1, c2 = alice_encrypt_to(1)
    print("   y=1 truc     :", int.to_bytes(c2,(c2.bit_length()+7)//8,"big").decode())


# ============================ 2. Diffie-Hellman MITM ============================
def demo_dh_mitm():
    print(">> 2. Diffie-Hellman via directory -> man-in-the-middle")
    p, g = safe_prime(256), 2
    msg = b"cns{dh_mitm_no_auth}"
    # Alice en Bob halen elkaars sleutel uit de directory; jij vervangt beide.
    a = random.randrange(2, p-2); A = pow(g, a, p)   # Alice privé/publiek
    b = random.randrange(2, p-2); B = pow(g, b, p)   # Bob
    # Jij registreert JOUW sleutel onder beide namen:
    e = random.randrange(2, p-2); E = pow(g, e, p)
    # Alice denkt E is Bob -> shared_A = E^a = A^e ; Bob denkt E is Alice -> shared_B = E^b
    shared_A = pow(A, e, p)     # = jij kent dit (A publiek, e van jou)
    shared_B = pow(B, e, p)
    # Alice stuurt msg versleuteld met kdf(shared_A); jij leest, herversleutelt naar Bob
    ct_from_alice = xor(msg, kdf(shared_A, p)*((len(msg)//32)+1))
    read = xor(ct_from_alice, kdf(shared_A, p)*((len(msg)//32)+1))
    print("   jij leest Alice->Bob:", read.decode())
    print("   (en kunt het herversleutelen met shared_B naar Bob; hij merkt niets)")


# ============================ 3. ontaarde sleutel ============================
def demo_degenerate_key():
    print(">> 3. Ontaarde publieke sleutel -> voorspelbaar gedeeld geheim")
    p, g = safe_prime(256), 2
    a = random.randrange(2, p-2)                 # Alice' geheim (onbekend voor jou)
    msg = b"cns{degenerate_key}"
    def alice_session_key(peer_y):               # Alice: shared = peer_y^a
        return kdf(pow(peer_y, a, p), p)
    for naam, y, verwacht in [("y=1", 1, 1), ("y=p-1", p-1, None), ("y=0", 0, 0)]:
        sk = alice_session_key(y)
        # jij weet: y=1 -> shared=1 ; y=0 -> shared=0 ; y=p-1 -> shared=+-1
        kandidaten = [1] if y == 1 else ([0] if y == 0 else [1, p-1])
        ct = xor(msg, sk*((len(msg)//32)+1))
        for guess in kandidaten:
            pt = xor(ct, kdf(guess, p)*((len(msg)//32)+1))
            if pt.startswith(b"cns{"):
                print(f"   {naam}: gedeeld geheim geraden -> {pt.decode()}")
                break


# ============================ 4. small subgroup ============================
def demo_small_subgroup():
    print(">> 4. Small-subgroup confinement -> geheim lekt mod kleine orde")
    # p-1 = 2 * q1 * q2 * ... met kleine qi: elementen van orde qi dwingen
    # shared = h^a in een kleine groep -> a mod qi afleesbaar, CRT -> a.
    small = [3, 5, 7, 11, 13, 17, 19, 23]
    while True:
        prod = 1
        for s in small: prod *= s
        p = 2*prod*randprime(80) + 1
        if is_prime(p): break
    g = 2
    a = random.randrange(2, p-2)                 # Alice' geheim
    def alice_shared(peer_y):                    # Alice geeft (indirect) peer_y^a terug
        return pow(peer_y, a, p)
    residues, moduli = [], []
    for q in small:
        h = pow(g, (p-1)//q, p)                  # element van orde q
        if h == 1: continue
        s = alice_shared(h)                      # = h^a, ligt in groep van orde q
        # vind r met h^r = s  (r = a mod q), kleine zoektocht
        val, r = 1, None
        for e in range(q):
            if val == s: r = e; break
            val = val*h % p
        if r is not None:
            residues.append(r); moduli.append(q)
    # CRT -> a mod (product)
    M = 1
    for m in moduli: M *= m
    x = 0
    for r, m in zip(residues, moduli):
        Mi = M//m; x += r*Mi*pow(Mi, -1, m)
    x %= M
    print(f"   a mod {M} = {x}   (echte a mod {M} = {a % M})  match={x == a % M}")
    print("   -> met genoeg kleine priemen (of Pollard-lambda voor de rest) krijg je heel a")


# ============================ 5. zwakke parameters ============================
def demo_weak_params():
    print(">> 5. Zwakke p (p-1 smooth) -> discrete log van publieke sleutel")
    small = [q for q in range(3, 2000) if is_prime(q)]
    while True:
        n = 2
        while n.bit_length() < 200: n *= random.choice(small)
        if is_prime(n+1): break
    p = n+1; g = 2
    x = random.randrange(2, p-2); y = pow(g, x, p)   # iemands privésleutel
    # Pohlig-Hellman (vereenvoudigd: p-1 squarefree-ish)
    fac = {}
    tmp = p-1
    for q in [2]+small:
        while tmp % q == 0: fac[q] = fac.get(q,0)+1; tmp //= q
    if tmp > 1: fac[tmp] = 1
    res, mod = [], []
    ok = True
    for q, ee in fac.items():
        qe = q**ee
        if q > 2**40: ok = False; break
        gi = pow(g, (p-1)//qe, p); hi = pow(y, (p-1)//qe, p)
        d = bsgs(gi, hi, p, qe)
        if d is None: ok = False; break
        res.append(d); mod.append(qe)
    if ok:
        M = 1
        for m in mod: M *= m
        xr = 0
        for r, m in zip(res, mod):
            Mi = M//m; xr += r*Mi*pow(Mi, -1, m)
        xr %= M
        print(f"   privésleutel x hersteld: {xr == x}  (x = {xr})")
    else:
        print("   p-1 had een te grote priemfactor -> p is sterk.")


DEMOS = {"elgamal": demo_elgamal_directory, "mitm": demo_dh_mitm,
         "degenerate": demo_degenerate_key, "subgroup": demo_small_subgroup,
         "weak": demo_weak_params}


def main():
    if "--demo" not in sys.argv:
        print(__doc__); return
    which = sys.argv[sys.argv.index("--demo")+1] if len(sys.argv) > sys.argv.index("--demo")+1 else "all"
    if which == "all":
        for fn in DEMOS.values():
            fn(); print()
    elif which in DEMOS:
        DEMOS[which]()
    else:
        print("keuzes:", ", ".join(DEMOS) + ", all")


if __name__ == "__main__":
    main()
