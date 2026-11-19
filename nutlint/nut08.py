"""NUT-08 (no vector file): check the worked example in 08.md prose against the
spec's own rules: n_blank = max(ceil(log2(fee_reserve)), 1), change = fee_reserve
- actual_fee, decomposed into powers of two that fit in n_blank outputs.
"""
import math
import re


def n_blank(fee_reserve):
    return 0 if fee_reserve == 0 else max(math.ceil(math.log2(fee_reserve)), 1)


def run_text(text, report):
    m = re.search(r"`fee_reserve` is `([\d ]+) sats?`.*?(\d+) blank `outputs`.*?actual fee was `(\d+) sat`.*?`fee_return = (\d+) sat`.*?summands of `2\^n` which is `([\d, ]+)`", text, re.S)
    if not m:
        report("NUT-08", "worked example found in 08.md", False, "pattern not found")
        return
    reserve = int(m.group(1).replace(" ", ""))
    blanks, fee, ret = int(m.group(2)), int(m.group(3)), int(m.group(4))
    parts = [int(x) for x in m.group(5).replace(" ", "").split(",")]
    report("NUT-08", f"example: {reserve} sat reserve -> {blanks} blank outputs", n_blank(reserve) == blanks, f"rule gives {n_blank(reserve)}")
    report("NUT-08", f"example: fee_return {ret} = reserve - fee", reserve - fee == ret, f"{reserve}-{fee}={reserve - fee}")
    ok = sum(parts) == ret and all(p & (p - 1) == 0 for p in parts) and parts == sorted(parts) and len(parts) <= blanks
    report("NUT-08", f"example: {ret} = {'+'.join(map(str, parts))} (powers of 2, fits)", ok, str(parts))
    edge = n_blank(0) == 0 and n_blank(1) == 1 and n_blank(2) == 1 and all(bin(x).count("1") <= n_blank(r) for r in range(1, 2049) for x in (r, (1 << r.bit_length() - 1) - 1))
    report("NUT-08", "blank-output rule covers any change up to fee_reserve", edge, "rule too small")
