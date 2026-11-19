"""Mutation self-test: prove that nutcheck actually detects broken vectors.

Usage: python3 -m nutcheck.mutate PATH_TO_NUTS_REPO [--per-file N] [--seed S]

For every test-vector file, pick up to N long hex strings (>= 32 hex chars)
at random, flip one hex digit inside each, re-run that file's checker on the
mutated text, and count how many mutations are caught (at least one FAIL or an
aborted run). A good checker catches nearly all of them; a mutation that is
NOT caught usually means the value is informational only (never re-derived)
and is listed so it can be reviewed.
"""
import contextlib
import io
import os
import random
import re
import sys

from .__main__ import MODULES  # (file, module) pairs; modules sharing a file run together

HEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{32,}(?![0-9a-fA-F])")


def run_checker(mods, text):
    fails = []

    def report(nut, name, ok, detail=""):
        if not ok:
            fails.append(name)

    for mod in mods:
        try:
            with contextlib.redirect_stdout(io.StringIO()):  # silence WARN lines
                mod.run(text, report)
        except Exception as e:  # noqa: BLE001
            fails.append(f"aborted: {type(e).__name__}")
    return fails


def main(argv):
    args = [a for a in argv[1:]]
    per_file, seed = 8, 1
    if "--per-file" in args:
        i = args.index("--per-file")
        per_file = int(args[i + 1])
        del args[i:i + 2]
    if "--seed" in args:
        i = args.index("--seed")
        seed = int(args[i + 1])
        del args[i:i + 2]
    if len(args) != 1:
        print(__doc__)
        return 2
    rng = random.Random(seed)
    tests = os.path.join(args[0], "tests")
    total = caught = 0
    missed = []
    by_file = {}
    groups = {}
    for fname, mod in MODULES:
        groups.setdefault(fname, []).append(mod)
    for fname, mods in groups.items():
        path = os.path.join(tests, fname)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if run_checker(mods, text):
            print(f"SKIP  {fname}: baseline already fails")
            continue
        spans = [m.span() for m in HEX.finditer(text)]
        rng.shuffle(spans)
        n_ok = n = 0
        for start, end in spans[:per_file]:
            pos = rng.randrange(start, end)
            old = text[pos]
            new = rng.choice([c for c in "0123456789abcdef" if c != old])
            mutated = text[:pos] + new + text[pos + 1:]
            n += 1
            if run_checker(mods, mutated):
                n_ok += 1
            else:
                line = text.count("\n", 0, pos) + 1
                missed.append(f"{fname}:{line}")
        total += n
        caught += n_ok
        by_file[fname] = (n_ok, n)
    for fname, (ok, n) in by_file.items():
        print(f"{ok:3}/{n:<3} caught  {fname}")
    if missed:
        print("\nnot caught (value not re-derived by the checker; review):")
        for x in missed:
            print("  " + x)
    print(f"\nmutation score: {caught}/{total} ({100.0 * caught / max(total, 1):.1f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
