# RSA — master decision guide + dispatcher

**One script to run on anything:** `rsa_solve.py`
```
python3 -I rsa_solve.py challenge.json
python3 -I rsa_solve.py public_keys.txt ciphertexts.txt
python3 -I rsa_solve.py challenge.json --flag cns      # set flag prefix for auto-detect
```
It harvests every n, e, c (also `ciphertext` block lists, block_size,
original_length, and any given d / p / q), fingerprints the setup, runs the
matching attack, and if unsure CASCADES through all of them until the
plaintext looks like a flag. Verified on all 5 session challenges.

## Recognise it yourself (what to look at FIRST)

```
          START: what did they give you?
                      |
   +------------------+--------------------------------+
   | d given?  -> decrypt: m = c^d mod n               |
   | p,q given? -> d = e^-1 mod (p-1)(q-1), decrypt     |
   +------------------+--------------------------------+
                      |
          How many MODULI (n)?
                      |
      ONE n ----------+---------- MANY n
        |                           |
   look at e                   same msg to all?
        |                           |
  +-----+------+        +-----------+-----------+
  | e small    |        | e small (3/5)         |
  |  (3,5,...) |        |  -> ciphertexts equal/ |
  |  one c     |        |     short? CUBE ROOT   |
  |  -> CUBE   |        |  -> ciphertexts differ?|
  |     ROOT   |        |     HASTAD CRT (need   |
  |  (if m^e<n)|        |     e of them)         |
  +-----+------+        +-----------+-----------+
        |                           |
  | TWO different e, two c |   also always check:
  |  (same n) -> COMMON    |   gcd(ni,nj) > 1 ?
  |     MODULUS            |    -> COMMON FACTOR,
        |                  |       factor both keys
  | e HUGE (~bits of n)    |
  |  -> WIENER (small d)   |
        |
  | n small (<~128 bit)    |
  |  -> FACTOR n           |
  |   (trial/Fermat/rho/p-1)|
```

## Fingerprint table
| What you see in the files | Attack | Why |
|---|---|---|
| `d` or `p,q` given | direct decrypt | nothing to break |
| gcd(nᵢ,nⱼ) > 1 | **common factor** | shared prime factors both |
| small e, one key, c ≪ n | **cube root** (Håstad A) | m^e didn't wrap |
| small e, ≥e keys, same msg | **Håstad broadcast** (CRT) | combine then e-th root |
| one n, two e, two c | **common modulus** | a·e1+b·e2=1 ⇒ m |
| **huge e** (≈ bit-length of n) | **Wiener** | e huge ⇔ d tiny |
| **small/weak n** | **factor n** | split n → d |

## e is the fastest tell
- e ∈ {3, 5, 17, 65537} and **small** → broadcast / cube-root / common-modulus / factor
- e **huge, close to n** → Wiener (small d)

## Decode convention (all these challenges)
`m = bytes_to_long(FLAG)` ⇒ `FLAG = long_to_bytes(m)` (big-endian int→bytes).
Block mode: `ciphertext` is a list + `block_size` + `original_length` →
decrypt each block, concat, trim to original_length.

## If NONE of them fire
The challenge wants an attack not bundled here. Likely candidates to recognise:
- **Boneh–Durfee**: small d but just above Wiener's bound (d < n^0.292). Needs lattice.
- **Franklin–Reiter / related-message**: same key, two ciphertexts of messages
  with a known linear relation (e.g. m and m+1).
- **Padding / LSB / parity oracle**: the challenge lets you query decryptions.
- **Coppersmith / stereotyped message**: part of the plaintext known.
These need more machinery — flag them by what's given (an oracle you can call,
a known linear relation, partial plaintext) rather than trying rsa_solve.py.
