# HVZK-WHIR strict wire source profile

Verdict: this directory freezes a deterministic conventional-hash outer wire,
transcript, MMCS, parser, mutation corpus, source manifest, and fail-closed
security ledger for evaluating the CFW26 HVZK-WHIR challenger. It is not a
transaction proof system, a proof artifact, a proof-size result, a winner, or
production authority.

The sealed tournament pin
3c84c158c0939345a3becba60a387643935593d2 is retained only as evidence for
Plonky3’s HidingWhirPcs. The separately audited local checkout at
5df89eeadae18d6935bb874f8a92808dcc200c9d is later PCS source evidence and is
not silently substituted for the recorded pin. Neither snapshot supplies the
paper’s Section 11 R1CS IOR or an exact Hegemon relation compiler.

## Check

From the repository root:

    python3 -B .agent/hardening/hvzk-whir-strict-wire-profile/check_profile.py

To recheck the optional read-only Plonky3 snapshot as well:

    python3 -B .agent/hardening/hvzk-whir-strict-wire-profile/check_profile.py \
      --local-plonky3 /Users/pldd/.cargo/git/checkouts/plonky3-7d8a3b21a665a86f/5df89ee

The checker uses only the Python standard library. It does not build a crate,
compile code, install a dependency, or run a proof. The optional source check
uses git only to read HEAD and hashes a bounded file inventory.

## Retained artifacts

- hvzk_whir_profile.py implements the binary statement/envelope codec,
  exact-consumption parser, SHAKE256-512 role framing, transcript replay,
  bounded query sampling, canonical Goldilocks field-element encoding, and a
  SHAKE256-512 binary MMCS.
- profile.json is the canonical retained KAT/profile summary.
- source_evidence.json distinguishes the recorded PCS pin from the local later
  source snapshot and records the audited source hashes.
- mutation_corpus.json defines 34 structural rejection mutations and one
  accepted integrity mutation whose transcript identifier must change.
- check_profile.py verifies all retained files, sealed tournament inputs,
  mutations, truncations, deterministic byte accounting, missing security
  terms, and the closed production gate.
- test_profile.py gives focused unit coverage for framing, bounds,
  canonicality, field encoding, transcript binding, MMCS behavior, and
  fail-closed authorization.
- CFW26_SECTION11_SPEC_AUDIT.md records an unresolved primary-paper
  coefficient/type ambiguity that independently blocks the R1CS IOR.

## Wire grammar

All integers are unsigned little-endian. The envelope header is exactly 168
bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic HGWHIR01 |
| 8 | 2 | wire version |
| 10 | 2 | header length |
| 12 | 2 | domain-set version |
| 14 | 2 | hash-suite identifier |
| 16 | 64 | profile digest |
| 80 | 4 | network identifier |
| 84 | 2 | action kind |
| 86 | 2 | action version |
| 88 | 64 | relation-manifest digest |
| 152 | 4 | statement length |
| 156 | 2 | section count |
| 158 | 2 | reserved flags, required zero |
| 160 | 4 | proof-body length |
| 164 | 4 | total envelope length |

The statement header is exactly 92 bytes: magic HGWHST01, statement version,
header length, network identifier, action kind, action version, domain-set
version, hash-suite identifier, 64-byte relation digest, and public-argument
length. It is followed by exactly that many public-argument bytes.

Each body record is an 8-byte header (role, per-role instance, payload length)
followed by exactly that many nonempty payload bytes. Roles are closed;
instances for each role begin at zero and increase without gaps. The exact
ordered section sequence is the message semantics and is transcript-bound.
Trailing bytes, alternate lengths, unknown roles, gaps, nonzero reserved
fields, duplicated outer/statement binding mismatches, and noncanonical
re-encodings are rejected.

Current limits are 65,536 public-argument bytes, 65,632 statement bytes,
8 MiB per section, 4,096 sections, 16 MiB body, and 17 MiB envelope. These are
research-profile parser limits, not measured proof sizes.

## Hash and transcript profile

Every hash call uses FIPS 202 SHAKE256 with 64-byte output and injective
framing:

    HGWHASH1 || u16le(domain length) || domain ||
    u16le(hash-role id) || u16le(frame count) ||
    for each frame: u64le(frame length) || frame

The domain is hegemon.hvzk-whir.strict-wire.source-profile.v1. Distinct fixed
roles cover the profile, source/relation manifests, statement, MMCS
leaf/node/root, transcript initialization/absorption/challenge/query/grinding/
retry, and final proof identifier. Challenge subroles and ordinals are
separately encoded. The transcript absorbs the complete canonical statement
before every ordered section. There is no Poseidon authority.

This source profile does not claim that the locally generic Plonky3 challenger
or MMCS instantiation already implements these bytes. A future adapter must
prove that exact correspondence.

## Byte accounting and claim boundary

For public-argument length P and section payload lengths L_i:

    statement_bytes = 92 + P
    proof_body_bytes = sum_i(8 + L_i)
    envelope_bytes = 168 + statement_bytes + proof_body_bytes

The retained 459-byte value is only a deliberately invalid
parser/transcript KAT envelope. It is not a proof, proof-size estimate, upper
bound, or benchmark. proof_bytes remains null.

All twenty composition terms remain explicitly missing, including exact
relation/compiler refinement, Section 11 IOR, Section 10 IOPP, WHIR/PCS
binding and proximity, complete HVZK, commitment hiding, QROM Fiat–Shamir,
concrete SHAKE loss, grinding/retry/RNG/hash/history unions, parser/native
verifier refinement, and consensus integration refinement. The overall
advantage and composed PQ bits are null, strict greater-than-128 status is
false, and production_authorized is false.
