# ElGamal — key distribution zonder authenticatie

**Script:** `keydir_solve.py` — `python3 -I keydir_solve.py --url http://cns-test.idlab.uantwerpen.be:50011`
(Netwerk-opgave: draai dit op je eigen machine tijdens de voorbereiding.)

## De zwakte (niet-crypto!)
De directory controleert **niet** of je de privésleutel bezit die bij een
geregistreerde publieke sleutel hoort. Iedereen mag eender welke `y` onder
eender welke naam zetten. Alice versleutelt blind naar wat er staat. Dit is
een **authenticatie-/PKI-probleem**, geen wiskundige zwakte in ElGamal zelf.
De les: publieke-sleutel-distributie heeft authenticatie nodig (certificaten,
een CA die ownership verifieert, key fingerprints).

## De aanval
1. `GET /params` → p, g
2. Kies een sleutel die JIJ controleert: `x` (bv. 2), `y = g^x mod p`
3. `POST /directory` met `{"name": "mallory", "y": y}`
4. `GET /send?to=mallory` → Alice geeft `(c1, c2)` met
   `c1 = g^k`, `c2 = m · y^k`
5. Decrypteer met jouw x: `s = c1^x mod p`, `m = c2 · s^-1 mod p`
6. `secret = long_to_bytes(m)`

Werkt omdat "Alice is happy to send her secret to anyone" — het geheim naar
Bob is hetzelfde als naar jou.

## Varianten — wat verandert er
| Situatie | Vlag / aanpak | Waarom |
|---|---|---|
| geheim is voor iedereen gelijk | standaard (eigen naam) | je leest het via je eigen entry |
| geheim verschilt per ontvanger, moet per se "naar Bob" | `--overwrite Bob` | overschrijf Bob's entry met jouw y, dan `/send?to=Bob` |
| je wil zonder rekenen | `--trick y1` | registreer `y=1` ⇒ `y^k=1` ⇒ `c2 = m` rechtstreeks |
| server weigert y=1 | `--trick g` (of eigen x) | `y=g, x=1` ⇒ `s=c1`, `m=c2·c1^-1` |
| /send geeft andere veldnamen | niets | script leest c1/c2, a/b, alpha/beta, ciphertext |
| overschrijven niet toegestaan | eigen naam | de meeste directories laten nieuwe namen toe |

## Wat als ze het "fixen"
- *Directory vereist een handtekening/bewijs van bezit (proof of possession)*:
  dan kan je geen vreemde sleutel meer registreren → aanval dicht.
- *Alice verifieert Bob's sleutel via een fingerprint/CA*: idem.
Noem dit als "hoe te verhelpen": authenticatie van de sleuteldistributie.

## Snelle sanity-check zonder server
De crypto is getest met een nagebootste Alice (eigen x, y=1 en y=g geven
alle drie dezelfde plaintext terug). Als het script op de echte server een
rare tekst teruggeeft: controleer dat `m = int.from_bytes(secret,"big")` de
afspraak is (big-endian) en dat je de juiste `(c1,c2)`-volgorde leest.
