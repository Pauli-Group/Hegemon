# Freeze a fail-closed HVZK-WHIR conventional-hash source profile

This ExecPlan is a living document under the isolated challenger-hardening
path. It follows .agent/PLANS.md. No shared design document or root ExecPlan is
modified.

## Purpose / big picture

The result lets a reviewer deterministically inspect and reject malformed
candidate CFW26 HVZK-WHIR envelopes without relying on generic serialization
or Poseidon, while preserving the decisive claim boundary: Plonky3 supplies
only PCS evidence and the Hegemon R1CS/IOR/full-proof composition is absent.
Success is a source-only checker PASS with every production/security/proof-size
claim still closed.

## Progress

- [x] (2026-08-22) Read AGENTS.md, DESIGN.md, METHODS.md, README.md,
  .agent/PLANS.md, the active proof ExecPlan, and the sealed architecture
  challenger report/ledger.
- [x] (2026-08-22) Audited the recorded Plonky3 pin boundary and the distinct
  local later source snapshot without compiling it.
- [x] (2026-08-22) Implemented the bounded outer statement/envelope parser,
  exact re-encoding check, SHAKE256-512 transcript/MMCS, field encoding, and
  fail-closed security ledger.
- [x] (2026-08-22) Added canonical retained manifests, mutation corpus, byte
  accounting, unit tests, and a dependency-free checker.
- [x] (2026-08-22) Independently audited the CFW26 Section 11 equations and
  retained the unresolved coefficient/type ambiguity as an admission blocker.
- [x] (2026-08-22) Ran the permitted source-only checks and recorded the
  results below. No build or proof command was invoked.

## Surprises & discoveries

- The sealed tournament revision
  3c84c158c0939345a3becba60a387643935593d2 is absent from the available
  shallow Plonky3 checkout. The local HEAD
  5df89eeadae18d6935bb874f8a92808dcc200c9d is useful later source evidence,
  but its ancestry from the recorded revision is not locally verifiable.
- CFW26 Construction 11.4 prints coefficient 1 in Step 3 and Step 8’s first
  equality, but coefficient 2 in the following equality and the HVZK value
  claim. Step 9 also supplies a pair state to an identity linear form whose
  definition accepts one state. No checked author erratum uniquely resolves
  the ambiguity.

## Decision log

- Decision: use FIPS 202 SHAKE256 with 64-byte output for every profile,
  transcript, MMCS, and identifier role.
  Rationale: it is a conventional standardized hash/XOF available in the
  Python standard library and permits one explicit primitive with injective
  length framing. This is a source profile, not a deployed QROM reduction.
- Decision: define a fixed binary outer envelope and treat each inner
  protocol message as a role-tagged opaque byte string.
  Rationale: the generic Plonky3 proof contains unbounded Vec fields and is not
  a consensus serializer. Opaque sections freeze transport and transcript
  semantics without falsely claiming an exact inner Plonky3 adapter.
- Decision: retain Goldilocks only as an odd-prime compiler screen and require
  canonical 8-byte encodings below its modulus.
  Rationale: this aligns with the sibling compiler screen but does not select
  a challenge extension field or PCS parameter set.
- Decision: do not select a repair for the CFW26 Section 11 ambiguity.
  Rationale: coefficient-1 plus scalar-multiplied identity is internally
  strongest, but no checked author source uniquely authorizes it.

## Context and orientation

The executable source is hvzk_whir_profile.py. check_profile.py verifies the
retained profile.json, source_evidence.json, mutation_corpus.json, and sealed
challenger report/ledger. test_profile.py exercises isolated invariants.
CFW26_SECTION11_SPEC_AUDIT.md records the primary-paper blocker. The optional
local Plonky3 checkout is read-only and outside this repository.

## Plan of work

First freeze constants, bounds, role identifiers, and an injectively framed
SHAKE256-512 function. Implement statement and envelope encoders whose parser
checks all lengths before slicing, exact-consumes input, rejects unknown roles
and instance gaps, validates duplicated consensus bindings, and requires exact
re-encoding. Bind canonical statement bytes and ordered sections into the
transcript. Implement only the conventional-hash MMCS and utility sampling
needed to make the source profile concrete.

Then retain canonical KAT/source manifests and a mutation corpus. Pin the
sealed architecture inputs and, optionally, the separate local Plonky3 source
snapshot by revision and per-file SHA-512. Make every absent security,
compiler, verifier, consensus, and measurement term explicit and keep the
production gate unconditional.

Finally run only Python source checks and formatting/diff checks. Do not invoke
Cargo, rustc, Lake, dependency installation, cloning, or proof generation
while the disk gate is closed.

## Validation and acceptance

Run:

    python3 -B .agent/hardening/hvzk-whir-strict-wire-profile/test_profile.py
    python3 -B .agent/hardening/hvzk-whir-strict-wire-profile/check_profile.py
    python3 -B .agent/hardening/hvzk-whir-strict-wire-profile/check_profile.py --local-plonky3 /Users/pldd/.cargo/git/checkouts/plonky3-7d8a3b21a665a86f/5df89ee
    git diff --check -- .agent/hardening/hvzk-whir-strict-wire-profile

Acceptance requires deterministic KATs, exact round trip, all declared
malformed mutations rejected with stable codes, the integrity mutation
changing the transcript, no internal parser errors across generated/truncated
inputs, source pins matching, all twenty security terms missing, proof_bytes
null, winner null, and production authorization false.

## Idempotence and recovery

All checks are read-only and deterministic. They can be rerun without cleanup.
No generated proof or build directory exists. If a retained JSON file drifts,
the checker fails before treating it as authority; update it only together
with an explicit reviewed profile version change.

## Outcomes & retrospective

The standard-library unit suite passed 13/13 tests. The retained checker
passed both without the optional checkout and with the read-only local
Plonky3 checkout: 34 structural mutations rejected, one integrity mutation
accepted only with a changed transcript, 1,227 generated/truncation inputs
handled without an internal parser error, seven local source hashes matched,
and zero R1CS source hits were found. The retained profile digest is
a505fee2df5c4b81f80f45cc04d75b6588581bf3a3a4ec9d1dcac2da1e297fd40637c202180203dada7ea57d73ec4d78fa977d895cf3988a0ece2ad9a6744f78.

The useful result is a strict outer-wire source target and a reproducible
negative admission decision. It does not advance the challenger through the
missing relation/compiler/IOR/IOPP/security/refinement gates, and it produces
no proof-size datum. The Section 11 ambiguity is an additional source-level
blocker that must be authoritatively or formally resolved before implementing
that reduction as consensus authority.
