"""NUT-28 Pay-to-Blinded-Key: ECDH Zx, blinding scalars r_i, blinded keys P', derived secret keys."""
import hashlib
import json
import re

from . import secp

DST = b"Cashu_P2BK_v1"


def shared_x(k, pt):
    return secp.mul(k, pt)[0].to_bytes(32, "big")


def r_i(zx, i):
    r = int.from_bytes(hashlib.sha256(DST + zx + bytes([i])).digest(), "big")
    if not 0 < r < secp.N:
        r = int.from_bytes(hashlib.sha256(DST + zx + bytes([i, 0xFF])).digest(), "big")
        if not 0 < r < secp.N:
            raise ValueError("blinding scalar out of range twice")
    return r


def _kv(text, heading):
    """key: "hex" pairs from the first shell block after a heading (or after a '# heading' comment)."""
    i = text.find(heading)
    blk = text[i:text.find("```", text.find("```", i) + 3)] if i >= 0 else ""
    return dict(re.findall(r'^(\w+): "([0-9a-f]+)"', blk, re.M))


def run(text, report):
    inp = _kv(text, "Sender ephemeral")
    e, p = int(inp["e"], 16), int(inp["p"], 16)
    E, P = secp.decode(inp["E"]), secp.decode(inp["P"])
    report("NUT-28", "E = e*G", secp.encode(secp.mul(e)) == secp.encode(E), "mismatch")
    report("NUT-28", "P = p*G (x-only match)", secp.mul(p)[0] == P[0], "mismatch")
    zx = shared_x(e, P)
    report("NUT-28", "Zx sender x(eP) == receiver x(pE)", zx == shared_x(p, E), "asymmetric")
    want = _kv(text, "### Shared Secret")
    report("NUT-28", "Zx", zx.hex() == want.get("Zx"), f"got {zx.hex()}")
    rv = _kv(text, "### Deterministic blinding")
    pv = _kv(text, "### Blinded Public Keys")
    sstd = _kv(text[:text.find("# skNeg")] + "```", "# skStd")
    sneg = _kv(text, "# skNeg")
    natural_even = secp.mul(p)[1] % 2 == 0
    p_even_vec = inp["P"].startswith("02")
    for i in range(11):
        r = r_i(zx, i)
        report("NUT-28", f"r{i}", f"{r:064x}" == rv.get(f"r{i}"), f"got {r:064x}")
        Pb = secp.encode(secp.add(P, secp.mul(r))).hex()
        report("NUT-28", f"P'{i}", Pb == pv.get(str(i)), f"got {Pb}")
        k_std, k_neg = (p + r) % secp.N, (-p + r) % secp.N
        report("NUT-28", f"skStd {i}", f"{k_std:064x}" == sstd.get(str(i)), "mismatch")
        report("NUT-28", f"skNeg {i}", f"{k_neg:064x}" == sneg.get(str(i)), "mismatch")
        k = k_std if natural_even == p_even_vec else k_neg
        report("NUT-28", f"chosen sk {i} signs for P'{i}", secp.encode(secp.mul(k)).hex() == Pb, "parity rule wrong")
    proofs = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", text, re.S)]
    for pr in proofs:
        kind, body = json.loads(pr["secret"])
        tags = {t[0]: t[1:] for t in body.get("tags", [])}
        slots = ([body["data"]] if kind == "P2PK" else [None]) + tags.get("pubkeys", []) + tags.get("refund", [])
        ok = pr.get("p2pk_e") == inp["E"] and all(s is None or s == pv.get(str(i)) for i, s in enumerate(slots))
        report("NUT-28", f"{kind} example proof keys are P' at their slots, p2pk_e = E", ok, f"slots {slots}")
