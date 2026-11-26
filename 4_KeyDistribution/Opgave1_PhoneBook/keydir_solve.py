#!/usr/bin/env python3
"""
keydir_solve.py  —  ElGamal key-distribution aanval (directory zonder authenticatie).

    python3 -I keydir_solve.py                         # standaard: eigen sleutel registreren
    python3 -I keydir_solve.py --url http://cns-test.idlab.uantwerpen.be:50011
    python3 -I keydir_solve.py --overwrite Bob         # overschrijf Bob's entry i.p.v. eigen naam
    python3 -I keydir_solve.py --trick y1              # registreer y=1 -> c2 is meteen de plaintext

DE ZWAKTE
    De directory controleert niet of je de bijbehorende privésleutel bezit. Je
    kan dus een sleutel registreren die JIJ controleert. Alice versleutelt haar
    geheim met ElGamal naar die sleutel:
        c1 = g^k mod p,   c2 = m * y^k mod p
    Omdat je de privésleutel x kent bij jouw y = g^x, bereken je het gedeelde
    geheim en haal je m eruit:
        s = c1^x mod p,   m = c2 * s^-1 mod p
    Geen enkele cryptografische aanval nodig — alleen het ontbreken van
    authenticatie in de sleuteldistributie.

VARIANTEN (zie uitleg onderaan en in solutions/key-distribution.md):
    - eigen naam registreren          (standaard; werkt als Alice hetzelfde geheim naar iedereen stuurt)
    - Bob's entry overschrijven       (--overwrite Bob; als het geheim per ontvanger verschilt)
    - degenererende sleutel y=1        (--trick y1; dan is c2 == m rechtstreeks)
    - degenererende sleutel y=g, x=1   (--trick g;  s = c1, m = c2 * c1^-1)
"""
import sys, json, argparse, urllib.request, urllib.parse


def http_get(url):
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.loads(r.read().decode())


def http_post(url, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        body = r.read().decode()
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body


def long_to_bytes(m):
    if m == 0:
        return b"\x00"
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def get_ct(resp):
    """Haal (c1, c2) uit een /send-antwoord, ongeacht de veldnamen."""
    if isinstance(resp, (list, tuple)) and len(resp) == 2:
        return int(resp[0]), int(resp[1])
    if isinstance(resp, dict):
        for a, b in (("c1", "c2"), ("a", "b"), ("r", "s"), ("alpha", "beta")):
            if a in resp and b in resp:
                return int(resp[a]), int(resp[b])
        if "ciphertext" in resp:
            return get_ct(resp["ciphertext"])
    raise SystemExit(f"Kan ciphertext niet lezen uit: {resp}")


def decode(m):
    b = long_to_bytes(m)
    try:
        return b.decode()
    except UnicodeDecodeError:
        return repr(b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://cns-test.idlab.uantwerpen.be:50011")
    ap.add_argument("--name", default="mallory", help="naam waaronder je registreert")
    ap.add_argument("--overwrite", default=None,
                    help="overschrijf de entry van deze naam (bv. Bob) i.p.v. --name")
    ap.add_argument("--x", type=int, default=2, help="privésleutel die jij kiest (y=g^x)")
    ap.add_argument("--trick", choices=["y1", "g"], default=None,
                    help="degenererende sleutel i.p.v. g^x")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    params = http_get(base + "/params")
    p = int(params["p"]); g = int(params["g"])
    print(f"[i] p: {p.bit_length()} bits, g = {g}")

    target = args.overwrite or args.name

    # 1) kies/registreer een sleutel die wij controleren
    if args.trick == "y1":
        y, x = 1, None          # y=1 -> y^k = 1 -> c2 = m rechtstreeks
    elif args.trick == "g":
        y, x = g % p, 1         # y=g, x=1 -> s = c1
    else:
        x = args.x % (p - 1) or 2
        y = pow(g, x, p)

    print(f"[i] registreer '{target}' met y = {y if y != 1 else '1 (degenererend)'}"
          + (f", x = {x}" if x is not None else ""))
    reg = http_post(base + "/directory", {"name": target, "y": y})
    print(f"    directory antwoord: {reg}")

    # 2) laat Alice haar geheim naar die naam sturen
    send_url = base + "/send?" + urllib.parse.urlencode({"to": target})
    c1, c2 = get_ct(http_get(send_url))
    print(f"[i] ciphertext ontvangen: c1={c1}\n                         c2={c2}")

    # 3) herstel m
    if y == 1:
        m = c2 % p                              # y^k = 1
    else:
        s = pow(c1, x, p)                        # = y^k
        m = c2 * pow(s, -1, p) % p

    print("\n[+] geheim hersteld:")
    print("    " + decode(m))


if __name__ == "__main__":
    main()
