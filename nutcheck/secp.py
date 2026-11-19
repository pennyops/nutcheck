"""Minimal pure-Python secp256k1 arithmetic for test-vector checking.

NOT constant time. Do not use for real keys; this exists only to verify
published Cashu NUT test vectors independently of any wallet/mint codebase.
"""
import hashlib

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
INF = None


def on_curve(pt):
    if pt is None:
        return True
    x, y = pt
    return (y * y - x * x * x - 7) % P == 0


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def neg(a):
    return None if a is None else (a[0], (-a[1]) % P)


def mul(k, pt=G):
    k %= N
    res = None
    while k:
        if k & 1:
            res = add(res, pt)
        pt = add(pt, pt)
        k >>= 1
    return res


def lift_x(x, odd):
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if (y & 1) != odd:
        y = P - y
    return (x, y)


def decode(hexstr):
    b = bytes.fromhex(hexstr) if isinstance(hexstr, str) else hexstr
    if len(b) == 33 and b[0] in (2, 3):
        pt = lift_x(int.from_bytes(b[1:], "big"), b[0] == 3)
        if pt is None:
            raise ValueError("not on curve")
        return pt
    if len(b) == 65 and b[0] == 4:
        pt = (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))
        if not on_curve(pt):
            raise ValueError("not on curve")
        return pt
    raise ValueError("bad point encoding")


def encode(pt):
    if pt is None:
        raise ValueError("point at infinity")
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def sha256(b):
    return hashlib.sha256(b).digest()
