"""NUT-00 crypto: hash_to_curve and blind-signature (BDHKE) vectors."""
import re

from . import secp

DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"


def hash_to_curve(msg: bytes):
    msg_hash = secp.sha256(DOMAIN_SEPARATOR + msg)
    for counter in range(2**16):
        h = secp.sha256(msg_hash + counter.to_bytes(4, "little"))
        pt = secp.lift_x(int.from_bytes(h, "big"), False)
        if pt is not None:
            return pt
    raise ValueError("no point found")


def blind(x: bytes, r: int):
    return secp.add(hash_to_curve(x), secp.mul(r))


def sign_blinded(k: int, B_):
    return secp.mul(k, B_)


def _blocks(text, heading):
    """Return ```shell code blocks that follow a markdown heading."""
    i = text.find(heading)
    if i < 0:
        return ""
    m = re.search(r"```\w*\n(.*?)```", text[i:], re.S)
    return m.group(1) if m else ""


def _field(line):
    k, _, v = line.partition(":")
    return k.strip(), v.split("#")[0].strip()


def run(text, report):
    # hash to curve
    block = _blocks(text, "### Hash-to-curve function")
    msgs = re.findall(r"Message:\s*([0-9a-f]+)\s*\nPoint:\s*([0-9a-f]+)", block)
    for i, (m, p) in enumerate(msgs, 1):
        got = secp.encode(hash_to_curve(bytes.fromhex(m))).hex()
        report("NUT-00", f"hash_to_curve #{i}", got == p, f"expected {p} got {got}")
    # blinded messages
    block = _blocks(text, "### Blinded messages")
    for i, (x, r, b) in enumerate(re.findall(
            r"x:\s*([0-9a-f]+).*?\nr:\s*([0-9a-f]+).*?\nB_:\s*([0-9a-f]+)", block), 1):
        got = secp.encode(blind(bytes.fromhex(x), int(r, 16))).hex()
        report("NUT-00", f"blinded message #{i}", got == b, f"expected {b} got {got}")
    # blinded signatures
    block = _blocks(text, "### Blinded signatures")
    for i, (k, b, c) in enumerate(re.findall(
            r"mint private key:\s*([0-9a-f]+)\s*\nB_:\s*([0-9a-f]+)\s*\nC_:\s*([0-9a-f]+)", block), 1):
        got = secp.encode(sign_blinded(int(k, 16), secp.decode(b))).hex()
        report("NUT-00", f"blinded signature #{i}", got == c, f"expected {c} got {got}")
