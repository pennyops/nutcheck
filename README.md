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

Sample output (excerpt):

```
PASS  NUT-12  hash_e
PASS  NUT-12  nonce vector: A == a*G
PASS  NUT-12  nonce vector: C_ == a*B_
PASS  NUT-12  deterministic e
PASS  NUT-12  deterministic s
PASS  NUT-12  deterministic proof verifies
PASS  NUT-12  BlindSignature DLEQ valid
PASS  NUT-12  Proof DLEQ valid (reblinded)
...
236 checks, 236 passed, 0 failed
```

Exit code 0 = all checks pass, 1 = at least one vector disagrees.

## Coverage

| NUT | What is checked |
|-----|-----------------|
| 00 | hash_to_curve, blinded messages, blinded signatures; TokenV3 encode/decode and prefix rejection; TokenV4 CBOR decode + byte-exact re-encode; raw `crawB` binary token |
| 01 | keyset validation: reject truncated / uncompressed keys, accept u64 amounts up to 2^63 |
| 02 | keyset ID v1 (`00`) and v2 (`01`, unit / input_fee_ppk / final_expiry) |
| 11 | BIP340 signatures; SIG_INPUTS spendability (n_sigs multisig, locktime, refund keys); SIG_ALL `msg_to_sign` hashes and full swap/melt request verification (identical conditions, first-input witness, P2PK + NUT-14 HTLC preimage, multisig, refund after locktime) |
| 12 | DLEQ `hash_e`, deterministic nonce (exact e, s), BlindSignature and Proof (reblinded) verification |
| 13 | BIP39 seed, legacy BIP32 derivation (v1), HMAC-SHA256 KDF (v2), P2PK key derivation |
| 18 | payment requests: `creqA` + CBOR decode equals the JSON, byte-exact CBOR re-encode (incl. CBOR `undefined`); WARNs on non-urlsafe base64 in vectors |
| 20 | quote-locking key derivation (m/129373'/20'/...), `msg_to_sign` bytes and hash, BIP340 mint-request signature, tamper rejection |
| 26 | `creqb` payment requests: own Bech32m (checksum const + HRP), TLV decode equals the JSON (unit compact `sat`, transports with NIP-19 npub/nprofile pubkey + relay tags, NUT-10 locks, `mp`, `sm`), byte-exact Bech32m re-encode |
| 27 | Nostr mint-backup key derivation (SHA256(seed \|\| domain separator), x-only pubkey) |
| 28 | P2BK: ECDH Zx symmetry, blinding scalars r0..r10, blinded keys P', skStd/skNeg, parity rule (chosen key really signs for P'), example proof slots |
| 29 | batch mint: offline request-shape rules (empty / duplicate quotes, signatures length), per-quote NUT-20 signature over the full outputs array |

Planned: more NUTs as vectors are published.

Findings so far: [cashubtc/nuts#484](https://github.com/cashubtc/nuts/pull/484) (NUT-18 vectors use standard, not urlsafe, base64), [cashubtc/nuts#485](https://github.com/cashubtc/nuts/pull/485) (NUT-02 prose vs code: `final_expiry: 0` in the keyset ID v2 preimage). [cashubtc/nuts#486](https://github.com/cashubtc/nuts/pull/486) (4 example points in NUT-11/14/29 not on secp256k1).

## Is the checker itself trustworthy? (mutation self-test)

A checker that always says PASS is useless, so nutcheck ships a mutation test:

```
python3 -m nutcheck.mutate ./nuts [--per-file N] [--seed S]
```

It flips one hex digit inside random long hex values of each vector file,
re-runs the checks on the mutated text, and reports how many corruptions were
caught. Current score against cashubtc/nuts HEAD (seed 1, 8 per file):
67/79 (85%). Uncaught locations are listed by file and line. They are
values the vectors only show as examples and that nothing is derived from,
e.g. NUT-01 keyset maps (only the key format is specified), the NUT-29
keyset `id` (not part of the signed message), or NUT-11 secret nonces in
examples that come without a signature to check against.

## Warning

The crypto here is NOT constant time and is meant only for checking public
test vectors. Never use it with real keys or funds.

## License

MIT
