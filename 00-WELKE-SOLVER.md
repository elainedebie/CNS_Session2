# Welke solver moet ik gebruiken? (master-gids)

Lees dit eerst bij elke opgave. Twee stappen: (1) welk **systeem**, (2) welke
**aanval** binnen dat systeem. De veldnamen in het bestand verraden het systeem;
de getallen verraden de aanval.

---

## STAP 1 — Welk systeem? Kijk naar de velden.

| Wat staat er in het bestand | Systeem | Solver |
|---|---|---|
| `n`, `e`, `c` (RSA-sleutels, exponent e) | **RSA** | `rsa_solve.py` |
| `p`, `g`, `y` + `cipher_*` (geen `q`) | **ElGamal** | `elgamal_solve.py` |
| `p`, `q`, `g`, `y` + `signatures` (r, s) | **DSA** (handtekeningen) | cursusmateriaal |
| een URL / server + "directory" / "register" | **key distribution** | `keydir_solve.py` |

Snelle ezelsbrug:
- alleen **`n` en `e`** → RSA
- **`g`** erbij (generator) → ElGamal of DSA; heb je `signatures` met `r,s` → DSA, anders ElGamal
- een **server om mee te praten** → key distribution

Twijfel je? Draai gewoon `rsa_solve.py` of `elgamal_solve.py` — beide cascaderen
door al hun aanvallen en zeggen het als niets past.

---

## STAP 2a — RSA: welke aanval?  → `rsa_solve.py`
```
python3 -I rsa_solve.py challenge.json
python3 -I rsa_solve.py keys.txt cts.txt        # broadcast-formaat
```
Kijk in deze volgorde:

| Teken in de opgave/data | Aanval |
|---|---|
| `d` of `p,q` staan er al in | gewoon decrypteren |
| twee `n`'s, `gcd(n1,n2) > 1` | **common factor** (gedeelde priem) |
| **klein `n`** (< ~130 bit, "embedded", "quick key") | **factoriseren** |
| **één `n`, twee `e`'s**, twee `c`'s ("reuse modulus") | **common modulus** |
| **enorme `e`** (~zo groot als `n`; "fast decryption", "small key") | **Wiener** (klein d) |
| kleine `e` (3/5), zelfde bericht naar **meerdere `n`** ("group chat") | **Håstad broadcast** |
| kleine `e`, `c` veel korter dan `n` / ciphertexts gelijk | **kubuswortel** (Case A) |

**Het snelst af te lezen: de grootte van `e`.**
- `e` klein & standaard (3, 17, 65537) → broadcast / factor / common-modulus
- `e` enorm, bijna grootte van `n` → Wiener

Details per aanval: `rsa-*.md` en `00-decision-guide.md`.

---

## STAP 2b — ElGamal: welke aanval?  → `elgamal_solve.py`
```
python3 -I elgamal_solve.py challenge.json
```
Kijk in deze volgorde:

| Teken in de opgave/data | Aanval |
|---|---|
| `x` of `k` staan er al in | gewoon decrypteren |
| twee ciphertexts met **dezelfde `c1`** + een **bekende plaintext** | **nonce hergebruik** |
| opgave zegt `k` is "klein", een "teller/counter", een "tijdstip" | **kleine nonce** (brute-force k) |
| **`p` klein**, of **`p-1` = product van kleine priemen** (smooth) | **discrete log** (Pohlig-Hellman) |

**Het snelst af te lezen: zijn twee `c1`-waarden gelijk?** → nonce hergebruik.
Dat is de klassieker (het woord "nonce" in de opgave is de hint).

Details: `elgamal.md`.

---

## STAP 2c — Key distribution  → `keydir_solve.py`
Herken je aan: een **server/URL**, een **directory** waar iedereen een publieke
sleutel mag registreren, en iets dat "naar een naam" versleutelt.
```
python3 -I keydir_solve.py --url http://.../  
```
De zwakte is **geen authenticatie**: registreer een sleutel die jij controleert,
laat het slachtoffer ernaartoe versleutelen, decrypteer. Varianten (`--overwrite`,
`--trick y1`) in `key-distribution.md`.

---

## Als GEEN solver aanslaat
Dan is het een aanval buiten je toolkit. Herken het aan wat gegeven is:
- **handtekeningen (r, s)** met één gelijke `r` → DSA nonce-hergebruik (sleutelherstel)
- een **oracle** die je mag bevragen (decrypt/parity) → padding/LSB-oracle
- twee ciphertexts van berichten met een **bekende relatie** (m en m+1) → Franklin-Reiter
- **deel van de plaintext bekend** → Coppersmith / stereotyped message
- **klein d net boven Wiener's grens** → Boneh-Durfee
Val dan terug op je cursusmateriaal; de solvers hier dekken deze niet.

---

## Oefenen
`make_practice.py` maakt een set met verhaaltjes (`challenge_XX_OPGAVE.txt`) +
data + `ANSWERS.txt`. Lees het verhaal, gebruik deze gids om systeem en aanval
te raden, draai de solver, check het antwoord.
