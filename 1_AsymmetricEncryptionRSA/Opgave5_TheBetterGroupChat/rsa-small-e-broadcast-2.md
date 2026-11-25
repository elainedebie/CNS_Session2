# RSA — small-e / Håstad broadcast attack

**Flags seen:** `cns{h4st4d_br04dc4st_4tt4ck}` (Case A, identical/short c),
`cns{th3_h@rd_h4st4d_br04dc4st_4tt4ck}` (Case B, ciphertexts differ -> CRT).
**Script:** `rsa_broadcast.py` — `python3 -I rsa_broadcast.py KEYS.txt CIPHERTEXTS.txt`
(Tries Case A on each c, then falls through to Case B automatically.)

## How to recognize it
Public exponent is small (**e = 3**, sometimes 5). Same message broadcast to
several recipients (a "group chat"). Then:
- Ciphertexts **identical / much shorter than n**  -> Case A (no wraparound).
- Ciphertexts **differ**, each ~size of its n       -> Case B (real Håstad).

RSA encryption is `c = m^e mod n`. Weakness: unpadded message under a low
exponent, broadcast to many keys.

## Two cases (script tries A, then B)
**Case A — no wraparound.** If `m^e < n`, then `c = m^e` as a plain integer.
Recover m with a single integer e-th root. No extra keys, no factoring.

**Case B — real Håstad.** If `m^e >= n` (ciphertexts differ), collect **e**
ciphertexts of the same m under e pairwise-coprime moduli. CRT ->
`C = m^e mod (n1·…·ne)`. Since m < min(n_i), C = m^e exactly -> e-th root.
(Need e ciphertexts for exponent e: 3 keys for e=3.)

## Adjacent variants to watch for
- **Common factor:** if gcd(n_i, n_j) != 1, that gcd factors both keys ->
  compute d, decrypt normally. The script's CRT step raises an error naming it.
- Different e: script reads e from the file, handles any exponent.

## Key idea to state in the exam
Per-key RSA was used correctly, but broadcasting one unpadded message under a
low exponent is the flaw — "only the recipient can read it" is false. Fix with
padding (OAEP) or a larger exponent (65537).
