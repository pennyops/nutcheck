"""NUT-12 DLEQ proofs: hash_e, deterministic nonce, BlindSignature and Proof checks."""
import hashlib
import hmac
import json
import re

from . import secp
from .nut00 import hash_to_curve


def unc(pt):
    return b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def hash_e(*pts):
    return hashlib.sha256("".join(unc(p).hex() for p in pts).encode()).digest()


def det_nonce(a, A, B_, C_):
    key = a.to_bytes(32, "big")
    for ctr in range(256):
        r = int.from_bytes(hmac.new(key, b"Cashu_DLEQ_R_v1" + unc(A) + unc(B_) + unc(C_) + bytes([ctr]),
                                    hashlib.sha256).digest(), "big")
        if 0 < r < secp.N:
            return r
    raise ValueError("nonce derivation failed")


def prove(a, B_):
    A, C_ = secp.mul(a), secp.mul(a, B_)
    r = det_nonce(a, A, B_, C_)
    e = int.from_bytes(hash_e(secp.mul(r), secp.mul(r, B_), A, C_), "big")
    return e, (r + e * a) % secp.N


def verify(A, B_, C_, e, s):
    R1 = secp.add(secp.mul(s), secp.neg(secp.mul(e, A)))
    R2 = secp.add(secp.mul(s, B_), secp.neg(secp.mul(e, C_)))
    return int.from_bytes(hash_e(R1, R2, A, C_), "big") == e


def _kv(block):
    return {k.strip(): v.strip().strip('"') for k, _, v in
            (l.partition(":") for l in block.splitlines() if ":" in l)}


def run(text, report):
    N = "NUT-12"
    secs = re.split(r"\n## ", text)
    for sec in secs:
        title = sec.split("\n", 1)[0]
        blocks = re.findall(r"```(\w*)\n(.*?)```", sec, re.S)
        if title.startswith("`hash_e`"):
            kv, out = _kv(blocks[0][1]), _kv(blocks[1][1])
            got = hash_e(*(secp.decode(kv[k]) for k in ("R1", "R2", "K", "C_"))).hex()
            want = list(out.values())[0]
            report(N, "hash_e", got == want, f"got {got}")
        elif title.startswith("Deterministic nonce"):
            kv, out = _kv(blocks[0][1]), _kv(blocks[1][1])
            a = int(kv["a"], 16)
            B_ = secp.decode(kv["B_"])
            report(N, "nonce vector: A == a*G", secp.encode(secp.mul(a)).hex() == kv["A"], "")
            report(N, "nonce vector: C_ == a*B_", secp.encode(secp.mul(a, B_)).hex() == kv["C_"], "")
            e, s = prove(a, B_)
            report(N, "deterministic e", f"{e:064x}" == out["e"], f"got {e:064x}")
            report(N, "deterministic s", f"{s:064x}" == out["s"], f"got {s:064x}")
            report(N, "deterministic proof verifies",
                   verify(secp.mul(a), B_, secp.mul(a, B_), int(out["e"], 16), int(out["s"], 16)), "")
        elif title.startswith("DLEQ verification on `BlindSignature`"):
            kv, js = _kv(blocks[0][1]), json.loads(blocks[1][1])
            ok = verify(secp.decode(kv["A"]), secp.decode(kv["B_"]), secp.decode(js["C_"]),
                        int(js["dleq"]["e"], 16), int(js["dleq"]["s"], 16))
            report(N, "BlindSignature DLEQ valid", ok, "verification failed")
        elif title.startswith("DLEQ verification on `Proof`"):
            kv, js = _kv(blocks[0][1]), json.loads(blocks[1][1])
            A = secp.decode(kv["A"])
            r = int(js["dleq"]["r"], 16)
            Y = hash_to_curve(js["secret"].encode())
            B_ = secp.add(Y, secp.mul(r))
            C_ = secp.add(secp.decode(js["C"]), secp.mul(r, A))
            ok = verify(A, B_, C_, int(js["dleq"]["e"], 16), int(js["dleq"]["s"], 16))
            report(N, "Proof DLEQ valid (reblinded)", ok, "verification failed")
