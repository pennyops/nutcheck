"""NUT-02 keyset ID derivation (version 00 and version 01)."""
import hashlib
import json
import re


def keyset_id_v1(keys):
    data = b"".join(bytes.fromhex(keys[k]) for k in sorted(keys, key=int))
    return "00" + hashlib.sha256(data).hexdigest()[:14]


def keyset_id_v2(keys, unit, input_fee_ppk=None, final_expiry=None):
    pre = ",".join(f"{int(k)}:{keys[k].lower()}" for k in sorted(keys, key=int))
    pre += f"|unit:{unit.lower()}"
    if input_fee_ppk:
        pre += f"|input_fee_ppk:{input_fee_ppk}"
    if final_expiry:
        pre += f"|final_expiry:{final_expiry}"
    return "01" + hashlib.sha256(pre.encode()).hexdigest()


def run(text, report):
    N = "NUT-02"
    v1, _, v2 = text.partition("## Version 2")
    for i, (kid, js) in enumerate(re.findall(r"Keyset id: `([0-9a-f]+)`\s*```json\n(.*?)```", v1, re.S), 1):
        got = keyset_id_v1(json.loads(js))
        report(N, f"keyset id v1 #{i} {kid}", got == kid, f"got {got}")
    for sec in re.split(r"### Vector ", v2)[1:]:
        name = sec.split("\n", 1)[0].strip()
        kid = re.search(r"Keyset id: `([0-9a-f]+)`", sec).group(1)
        unit = re.search(r"Unit: `([^`]+)`", sec).group(1)
        fee = re.search(r"Input fee ppk: `(\d+)`", sec)
        exp = re.search(r"Final expiry: `(\d+)`", sec)
        keys = json.loads(re.search(r"```json\n(.*?)```", sec, re.S).group(1))
        got = keyset_id_v2(keys, unit, fee and int(fee.group(1)), exp and int(exp.group(1)))
        report(N, f"keyset id v2 vector {name}", got == kid, f"got {got}")
