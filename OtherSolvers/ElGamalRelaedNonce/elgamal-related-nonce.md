# ElGamal — gerelateerde nonce (k2 = k1 + d)

**Script:** `elgamal_related_nonce.py challenge.json` (of `--delta -1`)
Generalisatie van nonce-hergebruik: daar is d=0, hier is d een bekende STAP.

## Wanneer
Twee berichten onder dezelfde sleutel, bekende plaintext bij het eerste, en de
nonces verschillen met een vaste bekende stap d (teller, timestamp+1, +2, −1…).
De `c1`-waarden zijn NIET gelijk (anders is het gewoon hergebruik), maar wel
gerelateerd: `c1_flag = c1_known · g^d`.

## d herkennen
`g^d = c1_flag · c1_known⁻¹`. Het script toetst kleine d in [−1000, 1000] af
(gewoon `g^d` vergelijken — geen discrete-log-zoektocht) en vindt de match.
Of geef d expliciet met `--delta`.

## Herstel (algebra)
```
y^k        = c2_known · m_known⁻¹          (gedeeld geheim bericht 1)
y^(k+d)    = y^k · y^d
m_flag     = c2_flag · (y^(k+d))⁻¹
           = c2_flag · m_known · c2_known⁻¹ · y^(−d)   (mod p)
```
d = 0 → de `y^(−d)`-term verdwijnt → exact nonce-hergebruik.
d = +1/−1/+2/… → deze generalisatie. Getest voor +1, −1, +2, +7.

## De les
Niet alleen hergebruik is fataal; elke VOORSPELBARE relatie tussen nonces
(opeenvolgende tellers, tijdstip+vast interval) laat je, met één bekende
plaintext, elk ander bericht ontsleutelen. De nonce moet onafhankelijk en
willekeurig zijn.

## Varianten
- *Geen bekende plaintext, wel bekende d*: dan ken je alleen de verhouding
  `m_flag / m_known`. Je hebt een bekende plaintext nodig.
- *d onbekend en groot*: het aftoetsen tot ±1000 faalt; dan zou je de discrete
  log `g^d` moeten oplossen — dat valt buiten dit script (en is zelden de
  bedoeling: de hint in de opgave geeft de relatie meestal weg).
- *Multiplicatieve relatie k2 = a·k1*: andere aanval, niet gedekt hier.
