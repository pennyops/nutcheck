"""NUT-27 Nostr mint-list backup keys: sk = SHA256(bip39_seed || "cashu-mint-backup"), x-only pubkey."""
import hashlib
import json
import re

from . import secp
from .nut13 import bip39_seed


def backup_keys(mnemonic, sep=b"cashu-mint-backup"):
    sk = hashlib.sha256(bip39_seed(mnemonic) + sep).digest()
    pk = secp.mul(int.from_bytes(sk, "big"))[0].to_bytes(32, "big")
    return sk.hex(), pk.hex()


def run(text, report):
    blocks = {}
    for b in re.findall(r"```json\n(.*?)```", text, re.S):
        blocks.update(json.loads(b))
    sep = re.search(r"domain separator used for key derivation is `([^`]+)`", text)
    if "mnemonic" not in blocks:
        report("NUT-27", "mnemonic vector found", False, "missing")
        return
    sk, pk = backup_keys(blocks["mnemonic"], sep.group(1).encode() if sep else b"cashu-mint-backup")
    report("NUT-27", "backup secret key", sk == blocks.get("secret_key"), f"got {sk}")
    report("NUT-27", "backup public key (x-only)", pk == blocks.get("public_key"), f"got {pk}")
