# Key distribution / key exchange — alle varianten

**Script:** `keyexchange_attacks.py` — `python3 -I keyexchange_attacks.py --demo all`
(elke aanval heeft een gesimuleerde demo; `--demo mitm|degenerate|subgroup|weak|elgamal`)
Vorige, specifieke solver voor de basisopgave: `keydir_solve.py` (echte server-calls).

De rode draad: **een kanaal/directory zonder authenticatie**. Je kunt dan sleutels
**substitueren** (MITM) of **ontaarde sleutels injecteren** zodat het gedeelde
geheim bekend of klein wordt. De les: sleuteldistributie heeft authenticatie
nodig (CA, certificaten, fingerprints) én sleutelvalidatie (verwerp 0, 1, p-1,
elementen van kleine orde).

## Herkennen — waar kijk je naar?
| Teken in de opgave | Aanval | Demo |
|---|---|---|
| directory waar je een publieke sleutel mag registreren; Alice versleutelt "naar een naam" | **ElGamal substitutie** / `y=1` | `--demo elgamal`, `keydir_solve.py` |
| Alice en Bob doen Diffie-Hellman via de directory; jij zit ertussen | **DH MITM** | `--demo mitm` |
| je mag een sleutel kiezen en de server valideert hem niet | **ontaarde sleutel** (1, p-1, 0) | `--demo degenerate` |
| p-1 heeft kleine factoren; je mag een willekeurige "sleutel" insturen | **small subgroup** | `--demo subgroup` |
| p is klein of p-1 is smooth, publieke sleutel gegeven | **zwakke params / discrete log** | `--demo weak` |

## 1. ElGamal directory-substitutie
Registreer een sleutel die jij beheert (`y=g^x`, x bekend) → Alice versleutelt
naar jou → decrypteer. Of `y=1`: dan is `c2 = m·1^k = m` rechtstreeks. Details &
echte server-calls: `key-distribution.md` + `keydir_solve.py`.

## 2. Diffie-Hellman MITM
Alice en Bob halen elkaars sleutel uit de directory. Vervang beide door JOUW
sleutel E=g^e. Alice denkt E=Bob → `shared_A = A^e` (jij kent A en e). Bob denkt
E=Alice → `shared_B = B^e`. Jij deelt met allebei een geheim, leest alles en
kunt herversleutelen; zij merken niets. Enige fix: de sleutels authenticeren.

## 3. Ontaarde publieke sleutel
Stuur een "sleutel" die het gedeelde geheim vastpint, ongeacht het geheim van
de ander:
- `y = 1`  → shared = 1^a = **1**
- `y = 0`  → shared = **0**
- `y = p-1`→ shared = (−1)^a = **±1** (twee kandidaten, probeer beide)
De sessiesleutel wordt dan `KDF(1/0/±1)` — bekend → ontsleutel de laag erbovenop.
Werkt zodra de server deze waarden niet verwerpt.

## 4. Small-subgroup confinement
`p-1 = 2·q1·q2·…` met kleine qi. Stuur een element `h` van **kleine orde** qi
(h = g^((p-1)/qi)). Dan ligt `shared = h^a` in een groepje van orde qi → maar qi
mogelijkheden → je leest `a mod qi` af. Herhaal voor meerdere qi en combineer met
**CRT** → a (Alice' geheim). De demo haalt a mod (3·5·7·…·23) exact terug. Fix:
valideer dat ontvangen sleutels in de juiste (grote) subgroep liggen.

## 5. Zwakke parameters (discrete log)
p klein, of p-1 = product van kleine priemen (smooth). Dan is de discrete log
haalbaar met **Pohlig-Hellman** (+ BSGS per factor, CRT) → de privésleutel x uit
y = g^x. Demo herstelt x volledig. Fix: veilige priem p (p-1 = 2q), generator
van orde q.

## Op een echte server inpluggen
De demo's simuleren Alice/Bob. Voor een echte opgave:
- registreren: `POST /directory {"name":..., "y":...}` (zie `keydir_solve.py`)
- de "sleutel" die je stuurt vervang je door 1 / p-1 / een klein-orde-element
- de rest (sessiesleutel afleiden, laag ontsleutelen) blijft identiek; pas enkel
  de KDF aan aan wat de opgave gebruikt (vaak `sha256(str(shared))`).

## "Ze fixen het" — wat je dan zegt
- sleutels **authenticeren** (CA / handtekening / fingerprint) → stopt substitutie & MITM
- publieke sleutels **valideren** (verwerp 0, 1, p-1; check orde) → stopt ontaard & subgroup
- **veilige parameters** (p = 2q+1, generator van orde q) → stopt discrete log
