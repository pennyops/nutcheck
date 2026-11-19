# nutcheck

[![check-nuts-vectors](https://github.com/pennyops/nutcheck/actions/workflows/vectors.yml/badge.svg)](https://github.com/pennyops/nutcheck/actions/workflows/vectors.yml)

Independent, dependency-free checker for the Cashu protocol test vectors in
[cashubtc/nuts](https://github.com/cashubtc/nuts) (`tests/*.md`).

It parses the markdown test-vector files directly and re-derives every value
with a small standalone implementation written from the spec text (pure
Python 3 standard library: secp256k1 math, BIP340 Schnorr, BIP32/BIP39, CBOR).
No wallet or mint codebase is imported, so a passing run means the published
vectors agree with the spec prose, and a failing run points at either a vector
or a spec ambiguity worth fixing.

Use it to:

- sanity-check vector changes in a NUT pull request before merging;
- port Cashu to a new language: the modules are short, readable reference code;
- learn how each NUT computes its values, step by step.

## Usage

```
git clone --depth 1 https://github.com/cashubtc/nuts
python3 -m nutcheck ./nuts
```

Exit code 0 = all checks pass, 1 = at least one vector disagrees.

## Coverage

| NUT | What is checked |
|-----|-----------------|
| 00 | hash_to_curve, blinded messages, blinded signatures; TokenV3 encode/decode and prefix rejection; TokenV4 CBOR decode + byte-exact re-encode; raw `crawB` binary token |
| 02 | keyset ID v1 (`00`) and v2 (`01`, unit / input_fee_ppk / final_expiry) |
| 11 | BIP340 signatures; SIG_INPUTS spendability (n_sigs multisig, locktime, refund keys); SIG_ALL `msg_to_sign` hashes |
| 12 | DLEQ `hash_e`, deterministic nonce (exact e, s), BlindSignature and Proof (reblinded) verification |
| 13 | BIP39 seed, legacy BIP32 derivation (v1), HMAC-SHA256 KDF (v2), P2PK key derivation |

Planned: NUT-11 SIG_ALL full request verification, NUT-18/26 payment requests,
NUT-20, NUT-28, NUT-29.

## Warning

The crypto here is NOT constant time and is meant only for checking public
test vectors. Never use it with real keys or funds.

## License

MIT
