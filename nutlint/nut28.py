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
        if "receiver_static" in pr:
            slot_map(pr, report)
            continue
        if "secret" not in pr:
            continue
        kind, body = json.loads(pr["secret"])
        tags = {t[0]: t[1:] for t in body.get("tags", [])}
        slots = ([body["data"]] if kind == "P2PK" else [None]) + tags.get("pubkeys", []) + tags.get("refund", [])
        ok = pr.get("p2pk_e") == inp["E"] and all(s is None or s == pv.get(str(i)) for i, s in enumerate(slots))
        report("NUT-28", f"{kind} example proof keys are P' at their slots, p2pk_e = E", ok, f"slots {slots}")


def slot_map(v, report):
    """v3 slot map: slot0 blinds the receiver key, slot i>=1 blinds leaf keys, each with its own ECDH."""
    E = secp.decode(v["ephemeral_E"])
    e = next((k for k in range(1, 100) if secp.encode(secp.mul(k)) == secp.encode(E)), None)
    if e is None:
        report("NUT-28", "slot map: ephemeral is a small test key", False, "E not k*G for k<100")
        return
    P0, P1 = secp.decode(v["receiver_static"]), secp.decode(v["slot1_key"])
    r0, r1 = r_i(shared_x(e, P0), 0), r_i(shared_x(e, P1), 1)
    report("NUT-28", "slot map: slot0_r", f"{r0:064x}" == v.get("slot0_r"), f"got {r0:064x}")
    b0 = secp.encode(secp.add(P0, secp.mul(r0))).hex()
    report("NUT-28", "slot map: slot0_blinded = P + r0*G", b0 == v.get("slot0_blinded"), f"got {b0}")
    b1 = secp.encode(secp.add(P1, secp.mul(r1))).hex()
    report("NUT-28", "slot map: slot1_blinded = P4 + r1*G", b1 == v.get("slot1_blinded"), f"got {b1}")
    leaf = v.get("leaf_with_blinded_slot1", "")
    report("NUT-28", "slot map: leaf carries slot1_blinded", b1 in leaf, "blinded key not in leaf bytes")
