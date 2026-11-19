"""NUT-00 token serialization: V3 (base64url JSON) and V4 (base64url CBOR).

Includes a tiny CBOR encoder/decoder (major types 0-5 and 7 simple values),
enough for Cashu tokens, so no third-party dependency is needed.
"""
import base64
import json
import re
import struct


# ---------------- CBOR ----------------
class _Undefined:
    def __repr__(self):
        return "undefined"


UNDEFINED = _Undefined()  # CBOR simple value 23


def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if n < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | ai]) + struct.pack(fmt, n)
    raise ValueError("int too large")


def cbor_encode(obj):
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if obj is None:
        return b"\xf6"
    if obj is UNDEFINED:
        return b"\xf7"
    if isinstance(obj, int):
        return _head(0, obj) if obj >= 0 else _head(1, -1 - obj)
    if isinstance(obj, bytes):
        return _head(2, len(obj)) + obj
    if isinstance(obj, str):
        b = obj.encode()
        return _head(3, len(b)) + b
    if isinstance(obj, list):
        return _head(4, len(obj)) + b"".join(cbor_encode(x) for x in obj)
    if isinstance(obj, dict):
        return _head(5, len(obj)) + b"".join(cbor_encode(k) + cbor_encode(v) for k, v in obj.items())
    raise TypeError(type(obj))


def cbor_decode(data):
    obj, i = _dec(data, 0)
    if i != len(data):
        raise ValueError(f"trailing bytes after CBOR item ({len(data) - i})")
    return obj


def _dec(d, i):
    ib = d[i]
    major, ai = ib >> 5, ib & 31
    i += 1
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        size = 1 << (ai - 24)
        n = int.from_bytes(d[i:i + size], "big")
        i += size
    elif ai == 31 and major in (2, 3, 4, 5):
        n = None  # indefinite length
    else:
        raise ValueError(f"unsupported CBOR additional info {ai}")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if n is None:
            chunks = []
            while d[i] != 0xFF:
                c, i = _dec(d, i)
                chunks.append(c)
            i += 1
            v = b"".join(chunks) if major == 2 else "".join(chunks)
            return v, i
        raw = d[i:i + n]
        return (bytes(raw) if major == 2 else raw.decode()), i + n
    if major == 4:
        out = []
        if n is None:
            while d[i] != 0xFF:
                v, i = _dec(d, i)
                out.append(v)
            return out, i + 1
        for _ in range(n):
            v, i = _dec(d, i)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        count = 0
        while (n is None and d[i] != 0xFF) or (n is not None and count < n):
            k, i = _dec(d, i)
            v, i = _dec(d, i)
            out[k] = v
            count += 1
        return out, (i + 1 if n is None else i)
    if major == 7:
        return {20: False, 21: True, 22: None, 23: UNDEFINED}[ai], i
    raise ValueError(f"unsupported CBOR major type {major}")


# ---------------- tokens ----------------
def b64url_decode(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def deserialize(token):
    """Return ('A'|'B', dict). Raises ValueError on a malformed token."""
    if not token.startswith("cashu"):
        raise ValueError("missing 'cashu' prefix")
    ver, body = token[5:6], token[6:]
    if ver == "A":
        return "A", json.loads(b64url_decode(body))
    if ver == "B":
        return "B", cbor_decode(b64url_decode(body))
    raise ValueError(f"unknown token version {ver!r}")


def serialize_v4(obj):
    return "cashuB" + b64url_encode(cbor_encode(obj))


def parse_diag(text):
    """Parse the spec's CBOR-diagnostic-like JSON (h'..' bytes, trailing commas)."""
    text = re.sub(r"h'([0-9a-fA-F]*)'", r'{"__bytes__": "\1"}', text)
    text = re.sub(r",(\s*[\]}])", r"\1", text)

    def hook(d):
        return bytes.fromhex(d["__bytes__"]) if set(d) == {"__bytes__"} else d
    return json.loads(text, object_hook=hook)


def _sections(text, start, end=None):
    i = text.find(start)
    if i < 0:
        return ""
    j = text.find(end, i + len(start)) if end else -1
    return text[i:j if j > 0 else len(text)]


def run(text, report):
    N = "NUT-00"
    # V3 serialization
    sec = _sections(text, "## Serialization of TokenV3", "## Deserialization of TokenV3")
    blocks = re.findall(r"```\w*\n(.*?)```", sec, re.S)
    if len(blocks) >= 2:
        want = json.loads(blocks[0])
        tok = blocks[1].strip()
        try:
            v, got = deserialize(tok)
            report(N, "TokenV3 serialized -> JSON", v == "A" and got == want, "decoded JSON differs")
        except Exception as e:  # noqa: BLE001
            report(N, "TokenV3 serialized -> JSON", False, str(e))
    # V3 deserialization: invalid then valid tokens
    sec = _sections(text, "## Deserialization of TokenV3", "## Serialization of TokenV4")
    blocks = re.findall(r"```\w*\n(.*?)```", sec, re.S)
    for bi, block in enumerate(blocks):
        toks = [l.strip() for l in block.splitlines() if l.strip() and not l.strip().startswith("#")]
        for t in toks:
            label = t[:12] + "..."
            try:
                deserialize(t)
                ok = bi != 0
            except Exception:  # noqa: BLE001
                ok = bi == 0
            report(N, f"TokenV3 {'reject' if bi == 0 else 'accept'} {label}", ok,
                   "validity did not match the spec")
    # V4 serialization: JSON (diag) block followed by serialized block
    sec = _sections(text, "## Serialization of TokenV4", "## Raw Token Serialization")
    pairs = re.findall(r"```json\n(.*?)```.*?```\n(cashuB.*?)```", sec, re.S)
    for i, (diag, tok) in enumerate(pairs, 1):
        want, tok = parse_diag(diag), tok.strip()
        try:
            _, got = deserialize(tok)
            report(N, f"TokenV4 #{i} decode == JSON", got == want, "decoded token differs")
            report(N, f"TokenV4 #{i} re-encode CBOR byte-exact",
                   cbor_encode(want) == b64url_decode(tok[6:]),
                   "re-encoding in spec key order differs (key order/int width?)")
            if tok.endswith("="):
                report(N, f"TokenV4 #{i} note: serialized vector carries base64 '=' padding",
                       True, "")
        except Exception as e:  # noqa: BLE001
            report(N, f"TokenV4 #{i}", False, str(e))
    # raw binary V4
    sec = _sections(text, "### TokenV4", "[NUT-10]")
    m = re.search(r"```json\n(.*?)```.*?`h'([0-9a-f]+)'`", sec, re.S)
    if m:
        want, raw = parse_diag(m.group(1)), bytes.fromhex(m.group(2))
        ok = raw[:5] == b"crawB" and cbor_decode(raw[5:]) == want
        report(N, "TokenV4 raw binary (crawB) decode == JSON", ok, "raw token differs")
