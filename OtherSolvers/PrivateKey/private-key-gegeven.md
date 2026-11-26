# Je krijgt de privésleutel — gewoon decrypteren

Soms is er geen aanval nodig: de opgave geeft je de **privésleutel**. Dan
decrypteer je rechtstreeks. Twee kleine, heldere scripts.

## RSA — `rsa_privkey.py challenge.json`
Accepteert elke vorm van de privésleutel:
| Gegeven | Wat het doet |
|---|---|
| `d` + `n` | decrypteer meteen: `m = c^d mod n` |
| `p` + `q` (+ `e`) | `d = e^-1 mod (p-1)(q-1)`, dan decrypteer |
| `d` + `e` + `n` (geen p,q) | **bonus:** reconstrueer p,q uit d (zie onder) |
Ciphertext mag één getal `c` zijn, of block-mode (`ciphertext`-lijst +
`block_size` + `original_length`).

**Bonus — waarom `d` krijgen = de hele sleutel krijgen:** met (n, e, d) kun je n
**factoriseren**. `e·d − 1` is een veelvoud van φ(n); via herhaalde
vierkantswortels van `a^(e·d−1)` vind je een niet-triviale wortel van 1, en
`gcd(x−1, n) = p`. Dus de privé-exponent lekt p en q. Handig als een
vervolgvraag p of q wil. Het script doet dit automatisch.

## ElGamal — `elgamal_privkey.py challenge.json`
Publiek (p, g, y=g^x), privé x, ciphertext (c1, c2).
Decryptie: `s = c1^x mod p` (= het gedeelde geheim y^k), `m = c2 · s^-1 mod p`.
| Gegeven | Wat het doet |
|---|---|
| `x` | decrypteer meteen |
| `k` (nonce) i.p.v. x | `s = y^k`, zelfde decryptie zonder x |
Ciphertext mag één paar zijn (`c1,c2` / `cipher_flag` / `ciphertext`) of een
lijst van paren (blokken, aaneengeplakt). Decodering big-endian
(`long_to_bytes`).

## Herkennen
Staat er een **`d`, `p`, `q` of `x`** in het bestand? Dan is het dit — geen
aanval. Twijfel je, draai gewoon `rsa_solve.py` / `elgamal_solve.py`; die pakken
"d gegeven" / "x gegeven" ook, maar deze scripts zijn directer en tonen de
bonus-factorisatie.
