"""nutcheck: verify Cashu NUT spec test vectors with an independent implementation.

Usage: python3 -m nutcheck PATH_TO_NUTS_REPO
"""
import os
import sys

from . import nut00, nut01, nut02, nut11, nut12, nut13, nut20, nut27, nut28, tokens

MODULES = [("00-tests.md", nut00), ("00-tests.md", tokens), ("01-tests.md", nut01), ("02-tests.md", nut02), ("11-test.md", nut11), ("12-tests.md", nut12), ("13-tests.md", nut13), ("20-test.md", nut20), ("27-test.md", nut27), ("28-tests.md", nut28)]


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    tests = os.path.join(argv[1], "tests")
    results = []

    def report(nut, name, ok, detail=""):
        results.append((nut, name, ok, detail))
        print(f"{'PASS' if ok else 'FAIL'}  {nut:7} {name}" + ("" if ok else f"  ({detail})"))

    for fname, mod in MODULES:
        path = os.path.join(tests, fname)
        if not os.path.exists(path):
            print(f"SKIP  {fname} missing")
            continue
        with open(path, encoding="utf-8") as f:
            content = f.read()
        try:
            mod.run(content, report)
        except Exception as e:  # noqa: BLE001  malformed vector must not crash the run
            report(mod.__name__.split(".")[-1].upper(), f"{fname} aborted", False, f"{type(e).__name__}: {e}")
    fails = sum(1 for r in results if not r[2])
    print(f"\n{len(results)} checks, {len(results) - fails} passed, {fails} failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
