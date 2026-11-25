# RSA — common-modulus attack

**Flag seen in this variant:** `cns{common_modulus_attack}`
**Script:** `rsa_common_modulus.py` — `python3 -I rsa_common_modulus.py challenge.json`
(challenge.json has n, e1, e2, c1, c2.)

## How to recognize it
The fingerprint: **one n, TWO exponents (e1, e2), TWO ciphertexts (c1, c2),
same message.** Often n is large (1024-bit here) so factoring is hopeless —
that's the clue you are NOT meant to factor. Story framing: "we reused the
key and just changed the exponent."

## Why it works (no factoring, no private key)
gcd(e1, e2) = 1  => extended Euclid gives a, b with  a*e1 + b*e2 = 1.
Then  c1^a * c2^b = m^(a*e1 + b*e2) = m  (mod n).
One of a, b is negative -> replace that ciphertext with its modular inverse
pow(c, -1, n) and use the positive exponent.

## Gotchas
- If gcd(e1,e2) = g > 1, you get m^g; take the integer g-th root at the end.
- Decode hint `m = bytes_to_long(FLAG)` just means plaintext is a big-endian
  integer -> recover with long_to_bytes (m.to_bytes(len,"big")).

## Distinguish from siblings
| See | Attack |
|---|---|
| one n, two e's, two c's | common modulus (this) |
| small e, same msg to several different n | Hastad broadcast |
| small n, normal e | factor n |
| huge e (near n) / tiny d | Wiener (not yet in toolkit) |

## This instance
e1=65537, e2=17, gcd=1, n is 1024-bit.
m = 159780179182590384703436563831537484378419925012952696121158525
