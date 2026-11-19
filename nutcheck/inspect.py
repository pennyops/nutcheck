"""Inspect a Cashu token (cashuA / cashuB): decode it, sanity-check it and verify DLEQ proofs offline.

Usage:
  nutcheck token TOKEN                     decode + structural checks
  nutcheck token creqA...                  decode a NUT-18 payment request
  nutcheck token TOKEN --keys KEYS.json    also verify NUT-12 DLEQ proofs against mint keys
  nutcheck token TOKEN --fetch             fetch keys from the token's mint (GET /v1/keys/{id}) and verify

KEYS.json is a mint /v1/keys response ({"keysets": [{"id", "unit", "keys": {amount: pubkey}}]}).
Nothing is sent anywhere unless --fetch is given; then only the public keyset is downloaded.
"""
import json
import urllib.request

from . import secp
from .nut00 import hash_to_curve
from .nut12 import verify as dleq_verify
from .tokens import deserialize


def _hex(v):
    return v.hex() if isinstance(v, (bytes, bytearray)) else v


def normalize(token):
    """Return (version, mint, unit, memo, proofs) with proofs as dicts of hex strings."""
    ver, obj = deserialize(token.strip())
    proofs = []
    if ver == "A":
        entries = obj.get("token", [])
        mint = entries[0].get("mint") if entries else None
        for ent in entries:
            for p in ent.get("proofs", []):
                q = dict(p)
                q["mint"] = ent.get("mint")
                proofs.append(q)
        return ver, mint, obj.get("unit"), obj.get("memo"), proofs
    for grp in obj.get("t", []):
        kid = _hex(grp.get("i"))
        for p in grp.get("p", []):
            q = {"amount": p.get("a"), "id": kid, "secret": p.get("s"), "C": _hex(p.get("c"))}
            if p.get("d"):
                q["dleq"] = {k: _hex(p["d"].get(k)) for k in ("e", "s", "r")}
            if p.get("w") is not None:
                q["witness"] = p.get("w")
            proofs.append(q)
    return ver, obj.get("m"), obj.get("u"), obj.get("d"), proofs


def secret_kind(secret):
    try:
        s = json.loads(secret)
        if isinstance(s, list) and len(s) == 2 and isinstance(s[1], dict):
            return s[0]  # NUT-10 well-known secret, e.g. P2PK / HTLC
    except (ValueError, TypeError):
        pass
    return "random"


def check_dleq(p, keys):
    """NUT-12 'Alice verifies the proof' check. Returns (ok|None, detail)."""
    d = p.get("dleq")
    if not d or not d.get("r"):
        return None, "no DLEQ (with r) in token"
    A_hex = keys.get(str(p["amount"]))
    if not A_hex:
        return False, f"mint has no key for amount {p['amount']}"
    A = secp.decode(A_hex)
    C = secp.decode(p["C"])
    r = int(d["r"], 16)
    Y = hash_to_curve(p["secret"].encode())
    B_ = secp.add(Y, secp.mul(r))
    C_ = secp.add(C, secp.mul(r, A))
    ok = dleq_verify(A, B_, C_, int(d["e"], 16), int(d["s"], 16))
    return ok, "DLEQ valid" if ok else "DLEQ INVALID"


def load_keys(path=None, mint=None, keyset_ids=()):
    """Map keyset id -> {amount: pubkey}."""
    out = {}
    if path:
        with open(path, encoding="utf-8") as f:
            docs = [json.load(f)]
    else:
        docs = []
        for kid in keyset_ids:
            url = mint.rstrip("/") + "/v1/keys/" + kid
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "nutcheck"}), timeout=15) as r:
                docs.append(json.load(r))
    for doc in docs:
        for ks in doc.get("keysets", []):
            out[ks["id"]] = {str(k): v for k, v in ks.get("keys", {}).items()}
    return out


NAMES = {"i": "id", "a": "amount", "u": "unit", "s": "single_use", "m": "mints", "d": "description",
         "t": "transports", "nut10": "nut10_lock"}


def show_request(req):
    """Decode a NUT-18 payment request (creqA...) and print it in readable form."""
    from .nut18 import decode_request, strip_undefined
    try:
        obj = strip_undefined(decode_request(req))
    except Exception as e:  # noqa: BLE001
        print(f"FAIL  cannot decode payment request: {type(e).__name__}: {e}")
        return 1
    print("NUT-18 payment request")
    for k, v in obj.items():
        print(f"{NAMES.get(k, k):12}: {json.dumps(v, default=_hex)}")
    return 0


def main(args):
    if not args or args[0].startswith("-"):
        print(__doc__)
        return 2
    token, rest = args[0], args[1:]
    if token.strip().startswith("creqA"):
        return show_request(token.strip())
    try:
        ver, mint, unit, memo, proofs = normalize(token)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL  cannot decode token: {type(e).__name__}: {e}")
        return 1
    problems = 0
    print(f"version : cashu{ver} ({'V4 CBOR' if ver == 'B' else 'V3 JSON'})")
    print(f"mint    : {mint}")
    print(f"unit    : {unit or '(unset; sat assumed)'}")
    if memo:
        print(f"memo    : {memo}")
    total = sum(p.get("amount") or 0 for p in proofs)
    print(f"proofs  : {len(proofs)}, total {total} {unit or 'sat'}")
    keys = {}
    if "--keys" in rest or "--fetch" in rest:
        try:
            if "--keys" in rest:
                keys = load_keys(path=rest[rest.index("--keys") + 1])
            else:
                keys = load_keys(mint=mint, keyset_ids=sorted({p["id"] for p in proofs}))
        except Exception as e:  # noqa: BLE001
            print(f"FAIL  could not load mint keys: {type(e).__name__}: {e}")
            problems += 1
    seen = set()
    for i, p in enumerate(proofs):
        notes = []
        amt = p.get("amount")
        if not isinstance(amt, int) or amt <= 0:
            notes.append("bad amount")
        elif amt & (amt - 1):
            notes.append("amount not a power of two")
        try:
            secp.decode(p["C"])
        except Exception:  # noqa: BLE001
            notes.append("C not a valid point")
        if p.get("secret") in seen:
            notes.append("DUPLICATE secret")
        seen.add(p.get("secret"))
        kind = secret_kind(p.get("secret"))
        line = f"  [{i}] {amt:>6} keyset {p.get('id')} secret={kind}"
        if keys:
            ks = keys.get(p.get("id"))
            if ks is None:
                notes.append("keyset not found at mint")
            elif not notes:
                ok, detail = check_dleq(p, ks)
                line += f" {detail}"
                if ok is False:
                    notes.append(detail)
        bad = [n for n in notes if n != "DLEQ valid"]
        problems += bool(bad)
        print(("FAIL" if bad else "ok  ") + line + (f"  ({'; '.join(bad)})" if bad else ""))
    print(f"\n{'no problems found' if not problems else f'{problems} problem(s) found'}")
    return 1 if problems else 0
