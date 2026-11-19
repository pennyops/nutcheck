"""NUT-26: payment request Bech32m + TLV encoding vectors."""
import json
import re

CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
M_CONST = 0x2BC830A3


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(h):
    return [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]


def _convert(data, frm, to, pad):
    acc = bits = 0
    out = []
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & ((1 << to) - 1))
    if pad and bits:
        out.append((acc << (to - bits)) & ((1 << to) - 1))
    elif not pad and (bits >= frm or ((acc << (to - bits)) & ((1 << to) - 1))):
        raise ValueError("bad padding")
    return out


def bech_decode(s):
    s = s.lower()
    pos = s.rfind("1")
    hrp, data = s[:pos], [CH.index(c) for c in s[pos + 1:]]
    const = _polymod(_hrp_expand(hrp) + data)
    return hrp, bytes(_convert(data[:-6], 5, 8, False)), const


def bech_encode(hrp, payload, const):
    data = _convert(payload, 8, 5, True)
    pm = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ const
    data += [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CH[d] for d in data)


def tlv(b):
    i = 0
    while i < len(b):
        t, ln = b[i], int.from_bytes(b[i + 1:i + 3], "big")
        yield t, b[i + 3:i + 3 + ln]
        i += 3 + ln


def tag_tuple(b):
    kl = b[0]
    vals, i = [b[1:1 + kl].decode()], 1 + kl
    while i < len(b):
        vals.append(b[i + 1:i + 1 + b[i]].decode())
        i += 1 + b[i]
    return vals


def nip19(s):
    """Return (pubkey_hex, relays) for npub/nprofile."""
    hrp, data, _ = bech_decode(s)
    if hrp == "npub":
        return data.hex(), []
    pk, relays, i = None, [], 0
    while i < len(data):
        t, ln = data[i], data[i + 1]
        v = data[i + 2:i + 2 + ln]
        if t == 0:
            pk = v.hex()
        elif t == 1:
            relays.append(v.decode())
        i += 2 + ln
    return pk, relays


def decode_req(b):
    r = {"m": [], "t": []}
    for t, v in tlv(b):
        if t == 1:
            r["i"] = v.decode()
        elif t == 2:
            r["a"] = int.from_bytes(v, "big")
        elif t == 3:
            r["u"] = "sat" if v == b"\x00" else v.decode()
        elif t == 4:
            r["s"] = bool(v[0])
        elif t == 5:
            r["m"].append(v.decode())
        elif t == 6:
            r["d"] = v.decode()
        elif t == 7:
            tr = {"tags": []}
            for st, sv in tlv(v):
                if st == 1:
                    tr["kind"] = sv[0]
                elif st == 2:
                    tr["target"] = sv
                elif st == 3:
                    tr["tags"].append(tag_tuple(sv))
            r["t"].append(tr)
        elif t == 8:
            n = {"t": []}
            for st, sv in tlv(v):
                if st == 1:
                    n["k"] = {0: "P2PK", 1: "HTLC"}.get(sv[0], sv[0])
                elif st == 2:
                    n["d"] = sv.decode()
                elif st == 3:
                    n["t"].append(tag_tuple(sv))
            r["nut10"] = n
        elif t == 9:
            r["mp"] = bool(v[0])
        elif t == 10:
            sm = {}
            for st, sv in tlv(v):
                if st == 1:
                    sm["mn"] = sv.decode()
                elif st == 2:
                    sm["mf"] = int.from_bytes(sv, "big")
            r.setdefault("sm", []).append(sm)
    return r


def blocks(text):
    sec = re.split(r"\n### ", text)
    for s in sec[1:]:
        name = s.splitlines()[0].strip()
        js = re.search(r"```json\n(.*?)```", s, re.S)
        enc = re.search(r"Encoded[^\n]*\n+```\n(.*?)\n```", s, re.S)
        if js and enc:
            yield name, json.loads(js.group(1)), enc.group(1).strip()


def compare(j, d):
    errs = []
    for k in ("i", "a", "u", "d", "s"):
        if k in j and j.get(k) != d.get(k):
            errs.append(f"{k}: json={j.get(k)!r} tlv={d.get(k)!r}")
    for k in ("nut10", "mp", "sm"):
        if k in j and j[k] != d.get(k):
            errs.append(f"{k}: json={j[k]!r} tlv={d.get(k)!r}")
    if "nut10" in j and not re.fullmatch(r"[0-9a-f]{64}|0[23][0-9a-f]{64}", j["nut10"]["d"]):
        print(f"WARN  NUT-26  nut10.d is not a hex hash/pubkey: {j['nut10']['d'][:10]}... (vector typo; JSON and TLV agree)")
    if j.get("m", []) != d["m"]:
        errs.append("mints differ")
    jt = j.get("t", [])
    if len(jt) != len(d["t"]):
        errs.append("transport count differs")
    for a, b in zip(jt, d["t"]):
        typ = a.get("t", a.get("type"))
        target = a.get("a", a.get("target"))
        tags = a.get("g", a.get("tags", [])) or []
        if typ == "nostr":
            pk, relays = nip19(target)
            if b.get("kind") != 0 or b["target"].hex() != pk:
                errs.append("nostr pubkey differs")
            rt = [x[1:] for x in b["tags"] if x[0] == "r"]
            if sorted(sum(rt, [])) != sorted(relays):
                errs.append("relay tags differ")
            nt = [x for x in b["tags"] if x[0] != "r"]
            if nt != tags:
                errs.append("nostr tags differ")
        elif typ == "post":
            if b.get("kind") != 1 or b["target"].decode() != target:
                errs.append("post target differs")
    return errs


def run(text, report):
    for name, j, enc in blocks(text):
        hrp, payload, const = bech_decode(enc)
        ok = hrp == "creqb" and const == M_CONST
        report("NUT-26", f"{name}: bech32m checksum/hrp", ok, f"hrp={hrp} const={const:#x}")
        rt = bech_encode(hrp, payload, M_CONST).upper()
        report("NUT-26", f"{name}: re-encode byte-exact", rt == enc.upper(), "mismatch")
        errs = compare(j, decode_req(payload))
        report("NUT-26", f"{name}: TLV fields == JSON", not errs, "; ".join(errs))
