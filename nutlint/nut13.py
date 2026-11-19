"""NUT-13 deterministic secrets: BIP39 seed, BIP32 legacy (v00), HMAC KDF (v01), P2PK keys."""
import hashlib
import hmac
import json
import re
import unicodedata

from . import secp


def bip39_seed(mnemonic, passphrase=""):
    m = unicodedata.normalize("NFKD", mnemonic).encode()
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode()
    return hashlib.pbkdf2_hmac("sha512", m, salt, 2048)


def bip32_priv(seed, path):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(I[:32], "big"), I[32:]
    for part in path.split("/")[1:]:
        hard = part.endswith("'")
        idx = int(part.rstrip("'")) + (0x80000000 if hard else 0)
        data = (b"\x00" + k.to_bytes(32, "big")) if hard else secp.encode(secp.mul(k))
        I = hmac.new(c, data + idx.to_bytes(4, "big"), hashlib.sha512).digest()
        k, c = (int.from_bytes(I[:32], "big") + k) % secp.N, I[32:]
    return k


def keyset_id_int(kid):
    return int(kid, 16) % (2**31 - 1)


def derive_v1(seed, kid, counter):
    base = f"m/129372'/0'/{keyset_id_int(kid)}'/{counter}'"
    return bip32_priv(seed, base + "/0"), bip32_priv(seed, base + "/1")


def derive_v2(seed, kid, counter):
    msg = b"Cashu_KDF_HMAC_SHA256" + bytes.fromhex(kid) + counter.to_bytes(8, "big")
    secret = hmac.new(seed, msg + b"\x00", hashlib.sha256).digest()
    r = int.from_bytes(hmac.new(seed, msg + b"\x01", hashlib.sha256).digest(), "big") % secp.N
    return int.from_bytes(secret, "big"), r


def run(text, report):
    N = "NUT-13"
    for sec in re.split(r"\n## ", text)[1:]:
        title = sec.split("\n", 1)[0]
        js = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", sec, re.S)]
        if title.startswith("Version 1: keyset ID integer"):
            d = js[0]
            got = keyset_id_int(d["keyset_id"])
            report(N, "v1 keyset_id_int", got == d["keyset_id_int"], f"got {got}")
            report(N, "v1 derivation path template",
                   d["derivation_path"] == f"m/129372'/0'/{got}'/{{counter}}'", "")
            continue
        if not js or "mnemonic" not in js[0]:
            continue
        seed = bip39_seed(js[0]["mnemonic"])
        if title.startswith("Version 1: Secret") or title.startswith("Version 2: Secret"):
            v2 = title.startswith("Version 2")
            if v2:
                kid = re.search(r"keyset ID `([0-9a-f]+)`", sec).group(1)
                fn = derive_v2
            else:
                kid, fn = "009a1f293253e41e", derive_v1
                path = re.search(r"derivation `m/129372'/0'/(\d+)'", sec)
                if path:
                    report(N, "v1 section path matches keyset", int(path.group(1)) == keyset_id_int(kid), "")
            tag = "v2" if v2 else "v1"
            secrets, rs = js[1], js[2]
            for i in range(len(secrets)):
                s, r = fn(seed, kid, i)
                report(N, f"{tag} secret_{i}", f"{s:064x}" == secrets[f"secret_{i}"], f"got {s:064x}")
                report(N, f"{tag} r_{i}", f"{r:064x}" == rs[f"r_{i}"], f"got {r:064x}")
            if len(js) > 3:
                for i, (k, v) in enumerate(js[3].items()):
                    want = f"m/129372'/0'/{keyset_id_int(kid)}'/{i}'"
                    report(N, f"{tag} {k}", v == want, f"expected {want}")
        elif title.startswith("P2PK Derivation"):
            for path, pub in js[1].items():
                got = secp.encode(secp.mul(bip32_priv(seed, path))).hex()
                report(N, f"p2pk {path}", got == pub, f"got {got}")
