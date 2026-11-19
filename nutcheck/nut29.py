"""NUT-29 batch mint: request-shape rules a wallet/mint can check offline, plus per-quote NUT-20 signatures.

Rules needing mint state (unknown quotes, mixed payment methods) are not checkable offline and are skipped.
"""
import hashlib
import json
import re

from .nut11 import schnorr_verify
from .nut20 import msg_to_sign


def shape_error(req):
    q = req.get("quotes")
    if not isinstance(q, list) or not q:
        return "quotes must be a non-empty array"
    if len(set(q)) != len(q):
        return "duplicate quote IDs (11016)"
    if "quote_amounts" in req and len(req["quote_amounts"]) != len(q):
        return "quote_amounts length != quotes length"
    sigs = req.get("signatures")
    if sigs is not None and len(sigs) != len(q):
        return "signatures length != quotes length"
    return None


def _sections(text):
    return re.split(r"^## ", text, flags=re.M)[1:]


def run(text, report):
    for sec in _sections(text):
        title = sec.splitlines()[0].strip()
        blocks = []
        for b in re.findall(r"```json\n(.*?)```", sec, re.S):
            try:
                blocks.append(json.loads(b))
            except ValueError:
                pass  # elided example ("...")
        reqs = [b for b in blocks if "quotes" in b and "outputs" in b]
        if not reqs:
            continue
        req = reqs[0]
        err = shape_error(req)
        if title.startswith("Batch mint rejects") and ("empty" in title or "duplicate" in title or "length" in title):
            report("NUT-29", f"{title}: rejected offline", err is not None, "accepted")
        elif title.startswith("Batch mint rejects"):
            report("NUT-29", f"{title}: shape OK (needs mint state to reject)", err is None, err or "")
        else:
            report("NUT-29", f"{title}: shape valid", err is None, err or "")
        if req.get("signatures") and err is None:
            pk = re.search(r"^pubkey: (0[23][0-9a-f]{64})", sec, re.M)
            mb = re.search(r"^msg_to_sign_bytes: ([0-9a-f]+)", sec, re.M)
            mh = re.search(r"^msg_hash: ([0-9a-f]{64})", sec, re.M)
            for i, (quote, sig) in enumerate(zip(req["quotes"], req["signatures"])):
                if sig is None:
                    continue
                msg = msg_to_sign({"quote": quote, "outputs": req["outputs"]})
                h = hashlib.sha256(msg).digest()
                if mb:
                    report("NUT-29", f"signature[{i}] msg_to_sign bytes", msg.hex() == mb.group(1), f"got {msg.hex()}")
                if mh:
                    report("NUT-29", f"signature[{i}] msg_hash", h.hex() == mh.group(1), f"got {h.hex()}")
                ss = re.search(rf"^signature\[{i}\]: ([0-9a-f]{{128}})", sec, re.M)
                if ss:
                    report("NUT-29", f"signature[{i}] listing matches request JSON", ss.group(1) == sig, "differs")
                if pk:
                    report("NUT-29", f"signature[{i}] valid BIP340 over full outputs", schnorr_verify(h, pk.group(1), sig), "invalid")
                    short = msg_to_sign({"quote": quote, "outputs": req["outputs"][:1]})
                    report("NUT-29", f"signature[{i}] fails if an output is dropped",
                           not schnorr_verify(hashlib.sha256(short).digest(), pk.group(1), sig), "still valid")
