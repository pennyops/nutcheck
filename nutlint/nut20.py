"""NUT-20 signed mint quotes: key derivation m/129373'/20'/0'/0'/i, msg_to_sign, BIP340 signature."""
import hashlib
import json
import re

from . import secp
from .nut11 import schnorr_verify
from .nut13 import bip32_priv, bip39_seed


def len32(b):
    return len(b).to_bytes(4, "big") + b


def amount_bytes(a):
    return a.to_bytes((a.bit_length() + 7) // 8, "big")


def msg_to_sign(req):
    m = b"Cashu_MintQuoteSig_v1" + len32(req["quote"].encode())
    for o in req["outputs"]:
        m += len32(amount_bytes(int(o["amount"]))) + len32(bytes.fromhex(o["B_"]))
    return m


def run(text, report):
    blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", text, re.S)]
    mnem = next((b["mnemonic"] for b in blocks if "mnemonic" in b), None)
    paths = next((b for b in blocks if any(k.startswith("m/") for k in b)), {})
    if mnem:
        seed = bip39_seed(mnem)
        for path, pub in paths.items():
            got = secp.encode(secp.mul(bip32_priv(seed, path))).hex()
            report("NUT-20", f"pubkey {path}", got == pub, f"got {got}")
    req = next((b for b in blocks if "signature" in b and "outputs" in b), None)
    if not req:
        report("NUT-20", "mint request vector found", False, "missing")
        return
    pk = re.search(r"`pubkey`.*?is `(0[23][0-9a-f]{64})`", text, re.S)
    m = re.search(r"msg_to_sign = ([0-9a-f]+)", text)
    h = re.search(r"sha256\(msg_to_sign\) = ([0-9a-f]{64})", text)
    msg = msg_to_sign(req)
    if m:
        report("NUT-20", "msg_to_sign bytes", msg.hex() == m.group(1), f"got {msg.hex()}")
    digest = hashlib.sha256(msg).digest()
    if h:
        report("NUT-20", "sha256(msg_to_sign)", digest.hex() == h.group(1), f"got {digest.hex()}")
    if pk:
        report("NUT-20", "mint request signature (BIP340)", schnorr_verify(digest, pk.group(1), req["signature"]), "invalid")
        if pk.group(1) == secp.encode(secp.mul(1)).hex():
            bad = dict(req, quote=req["quote"] + "x")
            report("NUT-20", "signature rejects tampered quote",
                   not schnorr_verify(hashlib.sha256(msg_to_sign(bad)).digest(), pk.group(1), req["signature"]), "accepted")
