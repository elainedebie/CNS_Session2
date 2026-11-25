# RSA — Wiener's attack (small private exponent d)

**Flag seen in this variant:** `cns{wiener_attack}`
**Script:** `rsa_wiener.py` — `python3 -I rsa_wiener.py challenge.json`
(challenge.json has n, e, and c / ciphertext.)

## How to recognize it
- **e is HUGE — nearly the full bit-length of n** (here both 1024-bit). Normal
  RSA uses tiny e (65537). A giant e = small d pushed up by the inverse.
- Story cues: "fast decryption", "small/questionable private key", and the
  pun — "Wiener" sounds like a fast-car brand joke.

## Why it works (no factoring)
Wiener: if d < n^(1/4)/3, then d is recoverable from (n, e) alone.
e*d = 1 + k*phi, and e/n ~ e/phi, so k/d is a **convergent of the continued
fraction** of e/n. For each convergent k/d: phi = (e*d-1)/k; solve
x^2 - (n-phi+1)x + n = 0; if roots are integers they are p, q. Done -> decrypt
with m = pow(c, d, n).

## Gotcha
- If it fails, d was too big (>= n^(1/4)/3) and Wiener does not apply — try a
  different attack. The script says so rather than looping forever.
- Decode: m = bytes_to_long(FLAG) -> long_to_bytes(m), big-endian.

## e tells you the attack
| e looks like | attack |
|---|---|
| small/standard (3, 17, 65537) | broadcast / factor / common-modulus |
| **huge, close to n** | **Wiener (small d)** |

## This instance
n 1024-bit, e 1024-bit, recovered d = 252 bits (just under the n^(1/4)/3 bound).
