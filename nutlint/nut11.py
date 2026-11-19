"""NUT-11 P2PK: BIP340 Schnorr verification and SIG_INPUTS spending rules.

SIG_ALL: full swap/melt request verification (P2PK and NUT-14 HTLC locks).
"""
import hashlib
import json
import re
import time

from . import secp


def tagged(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def schnorr_verify(msg32, pubkey33_hex, sig_hex):
    try:
        P = secp.lift_x(int(pubkey33_hex[2:], 16), False)  # x-only
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    if P is None or len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if r >= secp.P or s >= secp.N:
        return False
    e = int.from_bytes(tagged("BIP0340/challenge", sig[:32] + P[0].to_bytes(32, "big") + msg32), "big") % secp.N
    R = secp.add(secp.mul(s), secp.neg(secp.mul(e, P)))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def _count(msg, keys, sigs):
    """Number of distinct keys with at least one valid signature."""
    return sum(1 for k in set(keys) if any(schnorr_verify(msg, k, s) for s in sigs))


def proof_spendable(proof, now=None):
    now = int(time.time()) if now is None else now
    kind, body = json.loads(proof["secret"])
    if kind != "P2PK":
        raise ValueError("not a P2PK secret")
    tags = {t[0]: t[1:] for t in body.get("tags", [])}
    sigs = json.loads(proof.get("witness") or "{}").get("signatures", [])
    msg = hashlib.sha256(proof["secret"].encode()).digest()
    keys = [body["data"]] + tags.get("pubkeys", [])
    n_sigs = int(tags.get("n_sigs", ["1"])[0])
    if _count(msg, keys, sigs) >= n_sigs:
        return True
    locktime = int(tags["locktime"][0]) if "locktime" in tags else None
    if locktime is not None and now > locktime:
        refund = tags.get("refund", [])
        if not refund:
            return True  # anyone can spend after locktime
        n_ref = int(tags.get("n_sigs_refund", ["1"])[0])
        return _count(msg, refund, sigs) >= n_ref
    return False


def sig_all_msg(req):
    m = "".join(p["secret"] + p["C"] for p in req["inputs"])
    m += "".join(str(o["amount"]) + o["B_"] for o in req.get("outputs") or [])
    return m + req.get("quote", "")


def request_valid(req, now=None):
    """SIG_ALL request check: identical conditions, then first-input witness over the whole tx."""
    now = int(time.time()) if now is None else now
    ins = req["inputs"]
    first = json.loads(ins[0]["secret"])
    for p in ins:
        k, b = json.loads(p["secret"])
        if k != first[0] or b["data"] != first[1]["data"] or b.get("tags") != first[1].get("tags"):
            return False
    kind, body = first
    tags = {t[0]: t[1:] for t in body.get("tags", [])}
    if tags.get("sigflag") != ["SIG_ALL"]:
        return False
    w = json.loads(ins[0].get("witness") or "{}")
    sigs = w.get("signatures", [])
    msg = hashlib.sha256(sig_all_msg(req).encode()).digest()
    if kind == "P2PK":
        keys, ok_main = [body["data"]] + tags.get("pubkeys", []), True
    elif kind == "HTLC":
        pre = w.get("preimage")
        ok_main = pre is not None and hashlib.sha256(bytes.fromhex(pre)).hexdigest() == body["data"]
        keys = tags.get("pubkeys", [])
    else:
        return False
    n_sigs = int(tags.get("n_sigs", ["1"])[0])
    if ok_main and (not keys or _count(msg, keys, sigs) >= n_sigs):
        return True
    if "locktime" in tags and now > int(tags["locktime"][0]):
        refund = tags.get("refund", [])
        if not refund:
            return True
        return _count(msg, refund, sigs) >= int(tags.get("n_sigs_refund", ["1"])[0])
    return False


def run(text, report):
    N = "NUT-11"
    sec = text.split("### SIG_ALL Test Vectors")[0]
    # every json block, with the prose line(s) before it as the expectation
    parts = re.split(r"```json\n(.*?)```", sec, flags=re.S)
    for i in range(1, len(parts), 2):
        prose = parts[i - 1].strip().splitlines()[-1] if parts[i - 1].strip() else ""
        proof = json.loads(parts[i])
        if "witness" not in proof:
            continue
        low = prose.lower()
        want = not any(w in low for w in ("invalid", "**not**", "not spendable", "failing"))
        try:
            got = proof_spendable(proof)
        except Exception as e:  # noqa: BLE001
            report(N, f"SIG_INPUTS vector {i // 2 + 1}", False, f"error {e}")
            continue
        label = re.sub(r"[`*#]", "", prose)[:70]
        report(N, f"SIG_INPUTS {'valid' if want else 'invalid'}: {label}", got == want,
               f"expected spendable={want}, got {got}")
    # SIG_ALL msg_to_sign hash vector(s)
    for m in re.finditer(r"msg_to_sign` on the above `\w+`\.\s*```\n(.*?)\n```.*?should look like this: `([0-9a-f]{64})`",
                         text, re.S):
        got = hashlib.sha256(m.group(1).encode()).hexdigest()
        report(N, "SIG_ALL sha256(msg_to_sign)", got == m.group(2), f"got {got}")
    # SIG_ALL full requests: every request with a witness, expectation from the prose before it
    sa = text.split("### SIG_ALL Test Vectors")[1]
    parts = re.split(r"```json\n(.*?)```", sa, flags=re.S)
    for i in range(1, len(parts), 2):
        prose = parts[i - 1].strip().splitlines()[-1] if parts[i - 1].strip() else ""
        if not prose.startswith("The following"):
            continue
        req = json.loads(parts[i])
        want = " invalid " not in f" {prose.lower()} "
        label = re.sub(r"[`*#]", "", prose)[:80]
        try:
            got = request_valid(req)
        except Exception as e:  # noqa: BLE001
            report(N, f"SIG_ALL {label}", False, f"error {type(e).__name__}: {e}")
            continue
        report(N, f"SIG_ALL {'valid' if want else 'invalid'}: {label}", got == want, f"expected {want}, got {got}")
