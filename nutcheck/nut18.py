"""NUT-18 payment requests: creqA + base64url(CBOR) decode, semantic match with JSON, byte-exact round trip."""
import json
import re

from .tokens import UNDEFINED, b64url_decode, b64url_encode, cbor_decode, cbor_encode  # noqa: F401


def strip_undefined(o):
    if isinstance(o, dict):
        return {k: strip_undefined(v) for k, v in o.items() if v is not UNDEFINED}
    if isinstance(o, list):
        return [strip_undefined(v) for v in o]
    return o


def decode_request(s):
    s = s.strip()
    if not s.startswith("creqA"):
        raise ValueError("missing creqA prefix")
    return cbor_decode(b64url_decode(s[5:]))


def run(text, report):
    for sec in re.split(r"^### ", text, flags=re.M)[1:]:
        title = sec.splitlines()[0].strip()
        js = re.search(r"```json\n(.*?)```", sec, re.S)
        enc = re.search(r"```\n(creqA[^\n]+)\n```", sec)
        if not js or not enc:
            continue
        want = json.loads(js.group(1))
        raw = enc.group(1).strip()
        try:
            got = decode_request(raw)
        except ValueError as e:
            report("NUT-18", f"{title}: decode", False, str(e))
            continue
        report("NUT-18", f"{title}: decode == JSON", strip_undefined(got) == want,
               f"got {json.dumps(strip_undefined(got))[:120]}")
        cb = b64url_decode(raw[5:])
        report("NUT-18", f"{title}: byte-exact CBOR re-encode", cbor_encode(got) == cb, "CBOR bytes differ")
        if re.search(r"[+/]", raw):
            print(f"WARN  NUT-18  {title}: vector uses standard base64 ('+' or '/'), spec says base64_urlsafe")
        again = "creqA" + b64url_encode(cb)
        if again != raw.rstrip("=") and not re.search(r"[+/]", raw):
            print(f"WARN  NUT-18  {title}: vector keeps '=' padding")
