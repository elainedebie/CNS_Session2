# RSA — factor a small/weak n

**Flag seen in this variant:** `cns{more-fun-than-sifting-sand}`
**Script:** `rsa_factor.py` — `python3 -I rsa_factor.py challenge.json`
(Reads n, e, ciphertext, block_size, original_length; factors; computes d; decrypts.)

## How to recognize it
- **n is small** (here 65 bits / 20 digits). Anything that fits in a ~64-bit
  range is a "factor me" task. `e = 65537` is normal — NOT the weakness.
- Challenge ships a `decryptor.py` that only asks for **d**. So the whole job
  is: factor n -> phi -> d.

## Method order (script tries each, reports the winner)
| Method | Wins when |
|---|---|
| Trial division | n has a small factor / n is tiny |
| Fermat | p and q are **close**, n = a^2 - b^2 (classic trap) |
| Pollard's rho | general, up to ~80-bit n  — **cracked this one** |
| Pollard's p-1 | p-1 is **smooth** (only small prime factors) |

Real "sieves" (Quadratic Sieve, GNFS) are only for large n (100+ digits) and
are NOT needed for exam-sized n. If asked which sieve: name QS/GNFS as the
large-n tools, but say rho/Fermat suffice here.

## Mechanical finish (same every time)
```
phi = (p-1)*(q-1)
d   = pow(e, -1, phi)        # modular inverse
# decrypt each block: m = pow(c, d, n); m.to_bytes(block_size,"big")
# concatenate, trim to original_length, decode utf-8
```

## This instance
p = 9794267101, q = 3539306293, d = 24157058732653669073
