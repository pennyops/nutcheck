"""Prose check: every compressed secp256k1 point (02/03 + 64 hex) quoted in the
NN.md spec documents should be a valid curve point. Example-only values, so an
invalid point is a WARN (spec typo), not a FAIL. Found cashubtc/nuts#486.
"""
import glob
import os
import re

P = 2**256 - 2**32 - 977
POINT = re.compile(r"(?<![0-9a-fA-F])(0[23][0-9a-f]{64})(?![0-9a-fA-F])")


def on_curve(h):
    x = int(h[2:], 16)
    if x >= P:
        return False
    y2 = (pow(x, 3, P) + 7) % P
    return y2 == 0 or pow(y2, (P - 1) // 2, P) == 1


def run_dir(nuts_dir, report):
    total = bad = 0
    for f in sorted(glob.glob(os.path.join(nuts_dir, "[0-9][0-9].md"))):
        name = os.path.basename(f)
        n = 0
        with open(f, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                for m in POINT.finditer(line):
                    n += 1
                    if not on_curve(m.group(1)):
                        bad += 1
                        print(f"WARN  PROSE   {name}:{i} example point {m.group(1)[:16]}... is not on secp256k1")
        total += n
    report("PROSE", f"{total} example points in NN.md parsed", total > 0, "no points found")
    return total, bad


def run_nut14(nuts_dir, report):
    """14.md quotes a matching hash / preimage pair: SHA256(preimage) == data."""
    import hashlib
    path = os.path.join(nuts_dir, "14.md")
    if not os.path.exists(path):
        return
    text = open(path, encoding="utf-8").read()
    d = re.search(r"Proof\.secret\.data = '([0-9a-f]{64})'", text)
    p = re.search(r"Proof\.witness\.preimage = '([0-9a-f]{64})'", text)
    if not (d and p):
        report("NUT-14", "hash/preimage example found in 14.md", False, "pattern not found")
        return
    ok = hashlib.sha256(bytes.fromhex(p.group(1))).hexdigest() == d.group(1)
    report("NUT-14", "prose example: SHA256(preimage) == Secret.data", ok, "hash mismatch")


def run_nut11(nuts_dir, report):
    """11.md quotes a signed P2PK proof: its witness signature must verify
    (BIP340 over SHA256(Proof.secret)) against Secret.data."""
    import hashlib
    import json
    from .nut11 import schnorr_verify
    path = os.path.join(nuts_dir, "11.md")
    if not os.path.exists(path):
        return
    text = open(path, encoding="utf-8").read()
    m = re.search(r'```json\n(\{\n  "amount": \d+,\n  "secret": "\[\\"P2PK.*?\n\})\n```', text, re.S)
    if not m:
        report("NUT-11", "signed P2PK proof example found in 11.md", False, "pattern not found")
        return
    p = json.loads(m.group(1))
    s, w = json.loads(p["secret"]), json.loads(p["witness"])
    ok = schnorr_verify(hashlib.sha256(p["secret"].encode()).digest(), s[1]["data"], w["signatures"][0])
    report("NUT-11", "prose example: P2PK proof witness signature verifies", ok, "bad signature")


def run_nut20(nuts_dir):
    """20.md quotes a signed PostMintBolt11Request. WARN (example-only) if its
    signature does not verify against the quoted pubkey."""
    import hashlib
    import json
    from .nut11 import schnorr_verify
    from .nut20 import msg_to_sign
    path = os.path.join(nuts_dir, "20.md")
    if not os.path.exists(path):
        return
    text = open(path, encoding="utf-8").read()
    m = re.search(r'"quote": "[0-9a-f-]+",\s*"outputs"', text)
    pk = re.search(r'"pubkey": "(0[23][0-9a-f]{64})"\n', text)
    if not (m and pk):
        return
    req = json.JSONDecoder().raw_decode(text[text.rindex("{", 0, m.start()):])[0]
    if not schnorr_verify(hashlib.sha256(msg_to_sign(req)).digest(), pk.group(1), req["signature"]):
        print("WARN  NUT-20  20.md example mint request: signature does not verify for the quoted pubkey")


def run_nut25(nuts_dir):
    """25.md: the bolt12 example quote is locked to a pubkey (NUT-20), so its
    example PostMintBolt12Request must carry a valid signature. WARN otherwise."""
    import hashlib
    import json
    from .nut11 import schnorr_verify
    from .nut20 import msg_to_sign
    path = os.path.join(nuts_dir, "25.md")
    if not os.path.exists(path):
        return
    text = open(path, encoding="utf-8").read()
    m = re.search(r'\{\s*"quote": "[0-9a-f-]+",\s*"outputs"', text)
    pk = re.search(r'"pubkey": "(0[23][0-9a-f]{64})",\n', text)
    if not (m and pk):
        return
    req = json.JSONDecoder().raw_decode(text[m.start():])[0]
    sig = req.get("signature")
    if not sig:
        print("WARN  NUT-25  25.md example mint request: quote has a pubkey but the request has no signature")
    elif not schnorr_verify(hashlib.sha256(msg_to_sign(req)).digest(), pk.group(1), sig):
        print("WARN  NUT-25  25.md example mint request: signature does not verify for the quoted pubkey")
