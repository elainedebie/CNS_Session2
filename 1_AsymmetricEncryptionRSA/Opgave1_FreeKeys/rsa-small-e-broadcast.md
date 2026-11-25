# RSA — small-e / Håstad broadcast attack

**Flag seen in this variant:** `cns{h4st4d_br04dc4st_4tt4ck}`
**Script:** `rsa_broadcast.py` — `python3 -I rsa_broadcast.py KEYS.txt CIPHERTEXTS.txt`

## How to recognize it
Public exponent is small (**e = 3**, sometimes 5). One or more of:
- The ciphertext `c` has far fewer digits than the modulus `n`.
- The same message was broadcast to several recipients, and the ciphertexts are **identical** (strong hint that m^e < every n).
- The question stresses "sent the same message to everyone / to the group."

RSA encryption is `c = m^e mod n`. The weakness is a small message and/or a
reused message under a small exponent with no padding.

## Two cases (the script tries A, then B)

**Case A — no wraparound.** If `m^e < n`, then `mod n` did nothing, so
`c = m^e` as a plain integer. Recover `m` with a single integer `e`-th root.
No extra keys, no factoring. (This is what fired here.)

**Case B — real Håstad.** If `m^e >= n` (ciphertexts differ), collect `e`
ciphertexts of the same `m` under `e` pairwise-coprime moduli. Use **CRT** to
get `C = m^e mod (n1·n2·…·ne)`. Since `m < min(n_i)`, `C = m^e` exactly →
integer `e`-th root.

## Adjacent variants to watch for
- **Common factor:** if `gcd(n_i, n_j) != 1`, that gcd is a prime factor of
  both keys → factor `n`, compute `d`, decrypt normally. The script's CRT step
  raises an error naming this when it happens.
- Different `e`: the script reads `e` from the file and handles any exponent.

## Key idea to state in the exam
Per-key RSA was used correctly, but broadcasting one unpadded message under a
low exponent is the flaw — "only the recipient can read it" is false. Proper
padding (OAEP) or a larger exponent (65537) prevents it.
