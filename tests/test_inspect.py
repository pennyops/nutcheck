"""Round-trip test for `nutlint token`: build a token with DLEQ proofs from a known mint key, verify, then tamper."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from nutlint import secp, tokencheck as inspect  # noqa: E402
from nutlint.nut00 import hash_to_curve  # noqa: E402
from nutlint.nut12 import prove  # noqa: E402
from nutlint.tokens import serialize_v4  # noqa: E402

KID = "00ad268c4d1f5826"
PRIV = {a: int.from_bytes(secp.sha256(b"nutlint test mint %d" % a), "big") % secp.N for a in (1, 2, 4, 8)}


def make_proof(amount, secret, r):
    k = PRIV[amount]
    B_ = secp.add(hash_to_curve(secret.encode()), secp.mul(r))
    C_ = secp.mul(k, B_)
    e, s = prove(k, B_)
    C = secp.add(C_, secp.neg(secp.mul(r, secp.mul(k))))  # unblind: C = C_ - r*K
    return {"a": amount, "s": secret, "c": secp.encode(C),
            "d": {"e": e.to_bytes(32, "big"), "s": s.to_bytes(32, "big"), "r": r.to_bytes(32, "big")}}


def main():
    proofs = [make_proof(8, "secret-one", 11), make_proof(2, "secret-two", 22)]
    tok = serialize_v4({"m": "https://mint.example", "u": "sat", "t": [{"i": bytes.fromhex(KID), "p": proofs}]})
    keys = {"keysets": [{"id": KID, "unit": "sat", "keys": {str(a): secp.encode(secp.mul(k)).hex() for a, k in PRIV.items()}}]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(keys, f)
    assert inspect.main([tok, "--keys", f.name]) == 0, "valid token rejected"
    proofs[1]["d"]["s"] = (int.from_bytes(proofs[1]["d"]["s"], "big") ^ 1).to_bytes(32, "big")
    bad = serialize_v4({"m": "https://mint.example", "u": "sat", "t": [{"i": bytes.fromhex(KID), "p": proofs}]})
    assert inspect.main([bad, "--keys", f.name]) == 1, "tampered DLEQ accepted"
    os.unlink(f.name)
    print("test_inspect OK")


if __name__ == "__main__":
    main()
