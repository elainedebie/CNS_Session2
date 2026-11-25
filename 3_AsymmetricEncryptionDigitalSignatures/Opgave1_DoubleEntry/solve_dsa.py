import json
import hashlib

with open("dsa1_challenge.json") as f:
    data = json.load(f)

p = data["p"]
q = data["q"]
g = data["g"]
y = data["y"]

sigs = data["signatures"]
sig1, sig2 = sigs[0], sigs[1]

m1 = sig1["message"]
m2 = sig2["message"]
r1, s1 = sig1["r"], sig1["s"]
r2, s2 = sig2["r"], sig2["s"]

assert r1 == r2, "r's zijn niet gelijk; nonce-hergebruik-aanval werkt niet direct"

def H(msg: str) -> int:
    return int(hashlib.sha256(msg.encode()).hexdigest(), 16) % q

h1 = H(m1)
h2 = H(m2)

r = r1

# k = (h1 - h2) / (s1 - s2) mod q
k = ((h1 - h2) * pow((s1 - s2) % q, -1, q)) % q

# x = (s1*k - h1) / r mod q
x = ((s1 * k - h1) * pow(r, -1, q)) % q

print("[+] k =", k)
print("[+] x =", x)

# Controle: y == g^x mod p
assert pow(g, x, p) == y, "Private key klopt niet!"
print("[+] Controle y == g^x mod p geslaagd")

# Flag ontsleutelen
ct = bytes.fromhex(data["encrypted_flag"])

keystream = b""
i = 0
while len(keystream) < len(ct):
    keystream += hashlib.sha256(f"{x}:{i}".encode()).digest()
    i += 1

flag = bytes(a ^ b for a, b in zip(ct, keystream[:len(ct)]))

print("[+] flag bytes:", flag)
print("[+] flag tekst:", flag.decode(errors="replace"))