"""NUT-01 keyset validation: every key must be a valid compressed point, amounts fit in u64."""
import json
import re

from . import secp


def keyset_valid(keys):
    for amount, pub in keys.items():
        try:
            a = int(amount)
        except ValueError:
            return False, f"amount {amount!r} not an integer"
        if not 0 < a < 2**64:
            return False, f"amount {a} outside u64"
        try:
            b = bytes.fromhex(pub)
        except ValueError:
            return False, f"key {amount} not hex"
        if len(b) != 33 or b[0] not in (2, 3):
            return False, f"key {amount} not 33-byte compressed"
        try:
            secp.decode(b)
        except ValueError:
            return False, f"key {amount} not on curve"
    return True, ""


def run(text, report):
    parts = text.split("should be accepted")
    reject = re.findall(r"```json\n(.*?)```", parts[0], re.S)
    accept = re.findall(r"```json\n(.*?)```", parts[1], re.S) if len(parts) > 1 else []
    if not reject or not accept:
        report("NUT-01", "vectors found", False, "could not locate reject/accept keysets")
        return
    for i, blk in enumerate(reject, 1):
        ok, why = keyset_valid(json.loads(blk))
        report("NUT-01", f"invalid keyset #{i} rejected", not ok, "accepted but should be rejected")
    for i, blk in enumerate(accept, 1):
        ks = json.loads(blk)
        ok, why = keyset_valid(ks)
        report("NUT-01", f"valid keyset #{i} accepted ({len(ks)} keys)", ok, why)
