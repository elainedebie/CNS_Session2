# ElGamal — alle varianten

**Flag deze opgave:** `cns{elgamal_nonce_reuse}`
**Script:** `elgamal_solve.py` — `python3 -I elgamal_solve.py challenge.json`
Herkent zelf de zwakte en probeert alles in volgorde. Getest op 6 varianten
(`elgamal_make_variants.py` maakt ze opnieuw aan om te oefenen).

## ElGamal in het kort
| | |
|---|---|
| publieke sleutel | `p` (priem), `g` (generator), `y = g^x mod p` |
| privésleutel | `x` |
| encryptie | kies nonce `k`: `c1 = g^k`, `c2 = m · y^k` (mod p) |
| decryptie | `s = c1^x = y^k`, `m = c2 · s⁻¹ mod p` |

`s = y^k` is het **gedeelde geheim**. Wie `s` kent, kan decrypteren — x is niet nodig.
Alle veiligheid hangt aan `k`: geheim, willekeurig, **nooit hergebruikt**.

## Herkennen: waar kijk je eerst naar?
1. **Zijn twee `c1`-waarden gelijk?** → nonce hergebruik (deze opgave).
2. **Staat er `x` of `k` in de JSON?** → gewoon decrypteren.
3. **Bekende plaintext gegeven?** → bijna zeker nonce hergebruik.
4. **Is p klein, of p-1 opgebouwd uit kleine priemen?** → discrete log (Pohlig-Hellman).
5. **Niets van dit?** → probeer kleine nonce (script doet dit vanzelf).

## Variant 1 — nonce hergebruik + bekende plaintext (DEZE OPGAVE)
**Hint-woorden:** "nonce", "known plaintext", "this message is public".
**Kenmerk:** `cipher_known[0] == cipher_flag[0]` (zelfde c1 ⇒ zelfde k).

Waarom: beide c2's gebruiken hetzelfde `s = y^k`:
```
c2_known = m_known · s        c2_flag = m_flag · s
s      = c2_known · m_known⁻¹  (mod p)
m_flag = c2_flag  · s⁻¹        (mod p)
```
Geen x nodig, geen discrete log. Eén bekende plaintext is genoeg.

**Wat verandert bij varianten:**
- *Andere veldnamen* (`h` i.p.v. `y`, `ciphertext`, `known_message`): script
  herkent ze. Werkt het niet → hernoem de velden in de JSON naar
  `p, g, y, known_plaintext, cipher_known, cipher_flag`.
- *Meerdere blokken*: geef `known_plaintext` als **lijst** (één per blok) en
  `cipher_known`/`cipher_flag` als lijst van paren `[[c1,c2],[c1,c2]]`.
  Elk flag-blok wordt gedecrypteerd met de `s` van het bekende blok met
  **dezelfde c1**.
- *Bekende plaintext is een getal* i.p.v. tekst: werkt ook (wordt als int gelezen).
- *Zelfde c1 maar géén bekende plaintext*: dan ken je alleen de verhouding
  `m_flag / m_known`. Je hebt toch een bekende plaintext nodig (zoek in de
  opgavetekst!).

## Variant 2 — privésleutel x gegeven
`m = c2 · (c1^x)⁻¹ mod p`. Script doet dit als `x` in de JSON staat.

## Variant 3 — nonce k gelekt
`s = y^k`, `m = c2 · s⁻¹`. Script doet dit als `k` in de JSON staat.

## Variant 4 — kleine nonce
**Kenmerk:** opgave zegt dat k "klein", "snel", "teller", "tijdstip" is.
Brute force k uit `c1 = g^k` met baby-step giant-step (tot ~2^40), dan zoals variant 3.
**Wat verandert:** is k groter (bv. 2^50), verhoog de grens `2**40` in stap 4
van het script (`bsgs(g, c1, p, 2**40)`) — kost wel geheugen (√grens).
Als k een *tijdstip* is (unix time): k ligt rond 1.7·10^9 → past ruim.

## Variant 5 — zwakke p (discrete log)
**Kenmerk:** p klein (< ~60 bits) of p-1 = product van kleine priemen ("smooth").
Pohlig-Hellman: los `y = g^x` op per kleine priemfactor van p-1, combineer met CRT
→ x → decrypteren. Script print welke grote factor het blokkeert als het niet lukt
(dan is p sterk en zit de zwakte ergens anders).

## Andere dingen die ze kunnen vragen (uitleg-vragen)
- **Malleabiliteit:** `(c1, t·c2)` decrypteert naar `t·m`. ElGamal is
  multiplicatief homomorf: `(c1·c1', c2·c2')` → `m·m'`. Zo kan je een
  ciphertext aanpassen zonder te decrypteren.
- **Waarom moet k random zijn?** Hergebruik ⇒ variant 1; voorspelbaar ⇒ variant 4.
- **Waarom is ElGamal niet-deterministisch?** Elke encryptie neemt nieuwe k, dus
  dezelfde m geeft telkens een andere ciphertext (anders dan textbook RSA).
- **Verschil met RSA-broadcast:** bij RSA is het kleine e het probleem, bij
  ElGamal is het altijd k.
