import json

with open("ElGamal_challenge.json") as f:
    data = json.load(f)

p = data["p"]
g = data["g"]
y = data["y"]

known_plaintext = data["known_plaintext"].encode()
c1_known, c2_known = data["cipher_known"]
c1_flag, c2_flag = data["cipher_flag"]

def inv(a, mod):
    return pow(a, -1, mod)

def int_to_bytes(n):
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

# Bekende plaintext als integer
m_known = int.from_bytes(known_plaintext, "big")

# y^k_known = c2_known / m_known mod p
K = c2_known * inv(m_known, p) % p

# Zoek d zodat c1_flag = c1_known * g^d mod p
ratio = c1_flag * inv(c1_known, p) % p

d = None
for cand in range(0, 100000):
    if pow(g, cand, p) == ratio:
        d = cand
        break
    if pow(inv(g, p), cand, p) == ratio:
        d = -cand
        break

if d is None:
    raise ValueError("Geen kleine nonce-offset d gevonden")

print(f"[+] d = {d}")

# shared_flag = y^(k_known + d)
if d >= 0:
    y_d = pow(y, d, p)
else:
    y_d = pow(inv(y, p), -d, p)

shared_flag = K * y_d % p

# flag = c2_flag / shared_flag mod p
m_flag = c2_flag * inv(shared_flag, p) % p

flag_bytes = int_to_bytes(m_flag)

print("[+] flag als integer:")
print(m_flag)
print()
print("[+] flag als bytes:")
print(flag_bytes)
print()
print("[+] flag als tekst:")
print(flag_bytes.decode(errors="replace"))