# Certify the HX448C02 scalar-to-M4 source refinement

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must remain current while work proceeds. Maintain
this document in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

The repository has two implementations of the same test-only two-input/two-output transaction
relation. `circuits/transaction/src/full_blake2b448_relation.rs` is the scalar semantic oracle and
`prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs`
lowers the intended relation into native M4 Boolean constraints. A reviewer needs a deterministic,
dependency-free way to establish that both source files describe the same public bytes, private
bytes, 83 typed hash calls, hash frames, digest chains, and non-hash semantic predicates before a
disk-admitted compiled differential run is attempted.

After this work, running `python3 .agent/hardening/scalar-m4-parity-certificate/check_certificate.py`
from the repository root will either print a source-bound source-parity certificate or fail on
drift. It will not compile Rust, construct a proof, select a hash profile, allocate an identity, or
authorize production.

## Progress

- [x] (2026-08-22) Read `AGENTS.md`, `DESIGN.md`, `METHODS.md`, `README.md`, `.agent/PLANS.md`,
  `.agent/SMALLWOOD_SHAKE256_PRODUCTION_EXECPLAN.md`, the scalar relation, and the complete M4
  candidate directory before editing shared code.
- [x] (2026-08-22) Confirmed with the parent and stablecoin worker that the revised diagnostic is
  fresh `HX448C02`, grammar 2, and 869 bytes; retired `HX448C01` remains a rejected 893-byte
  grammar-one input.
- [x] (2026-08-22) Kept all work in this new hardening directory and removed preliminary
  grammar-one certificate drafts before any stale hash could be presented as current evidence.
- [x] (2026-08-22) Waited for the coordinated scalar and M4 stablecoin patch, its independent
  review, and the final rustfmt-only pass before pinning any source hash.
- [x] (2026-08-22) Added the exact machine-readable certificate, corpus specification,
  dependency-free checker,
  mutation self-tests, and claim-boundary README.
- [x] (2026-08-22) Ran only lightweight Python/source checks while the 28-GiB disk gate remained
  closed: certificate PASS, 19/19 mutation tests PASS, candidate source contract PASS, JSON parse
  PASS, and scoped diff-check PASS.
- [x] (2026-08-22) Recorded final source hashes, exact checker results, missing executed graph
  counts, and the
  disk-open parity command without choosing a winner or granting production authority.

## Surprises & Discoveries

- Observation: The original diagnostic cannot be edited in place without creating byte-identity
  ambiguity. Grammar one used three 56-byte opaque stablecoin values and an 893-byte statement;
  the live manifest uses three exact 48-byte values.
  Evidence: the revised scalar source allocates `HX448C02`, rejects `HX448C01`, and places the
  48-byte fields at offsets 485, 533, and 581 in an 869-byte statement.

- Observation: Independent review rejected an API that accepted a caller-selected detached
  manifest entry. The final scalar object retains the whole `ProtocolManifest` snapshot and
  mirrors native admission's existential search over entries plausible by asset id or
  kernel-derived policy hash; the first plausible failure cannot mask a later valid member.
  Evidence: scalar `StablecoinProtocolManifestView` and
  `validate_stablecoin_protocol_manifest_view`, plus native
  `native_stablecoin_policy_binding_authorized_by_entries`.

- Observation: Stablecoin admission is deliberately split across two boundaries. The statement
  publicly carries asset, version, issuance, policy hash, oracle commitment, and attestation
  commitment. The manifest entry and current height remain consensus-owned host inputs used to
  check lifecycle, dispute, staleness, and issuance limits; they are not aggregate M4 public or
  private wires.
  Evidence: scalar `validate_stablecoin_protocol_manifest_view` and the production blocker text both
  describe the missing compiled equality/admission graph.

- Observation: The 48-byte policy/oracle/attestation values close an exact compatibility bridge
  but provide exactly 128 generic quantum collision bits, not a positive strict composed margin.
  Evidence: both source implementations keep strict-stablecoin-PQ and production flags false;
  the certificate requires fresh wider bindings rederived from authoritative preimages, never
  padding or truncation.

- Observation: Source-static hash parity can be complete while executed aggregate parity remains
  zero. The scalar retained object re-runs host semantics and each local Boolean trace, and M4
  source can share wires across its aggregate relation, but neither fact proves that an emitted
  M4 constraint system has accepted all honest fixtures and rejected all mutations.
  Evidence: both sources keep aggregate-artifact and production flags false, and the differential
  tests remain disk-gated.

## Decision Log

- Decision: Bind the certificate to fresh `HX448C02` and treat `HX448C01` as a required negative.
  Rationale: a new width and field grammar must not reinterpret the previous diagnostic bytes.
  Date/Author: 2026-08-22 / Codex.

- Decision: Express source parity as an exact, executable manifest of mappings, not as a claim that
  scalar host checks are constraints.
  Rationale: the scalar oracle and the M4 aggregate have different enforcement mechanisms. The
  checker must pair each host predicate with its intended M4 source constraint family and count
  all still-unexecuted equality, call, frame, output, and mutation obligations explicitly.
  Date/Author: 2026-08-22 / Codex.

- Decision: Hash a canonical framed source inventory containing path length, path bytes, file
  length, and file bytes, in addition to per-file hashes.
  Rationale: simple concatenation does not distinguish all path/file boundaries and is unsuitable
  as an exact source manifest.
  Date/Author: 2026-08-22 / Codex.

- Decision: Do not modify `DESIGN.md`, `METHODS.md`, `README.md`, the scalar relation, or the M4
  candidate from this workstream.
  Rationale: the worktree is shared and those files are owned by concurrent workers. The source
  certificate can be additive and source-bound without overwriting their changes.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

The source-only certificate is complete for the post-format `HX448C02` snapshot. It pins 27
selected source files, the 688-file Binius tree, the Rust `source_digest()`, and both program
digests. It expands exactly 83 calls, freezes every field and source slice in 11 frame layouts,
counts 99 static frame nodes, 18,695 static frame bytes, and 170
named non-hash semantic edges across 22 mapping groups. The exhaustive shape corpus contains 33
accepted and 47 rejected mask/mode pairs per profile. The checker reports every compiled or
executed counter as zero and keeps winner, identity, strict-PQ, and production authority false.

Final canonical digests are:

    framed selected-source SHA-512 49b8e6ccb5bc99d910c9d9a82737a16ac2cce29130051fd636e5601612d7fd9977a76a25c45979acf7b5d733e6704f020363a594b22437cf82f770e9f31a3c4c
    Rust source_digest SHA-512      d6b5d6e265b427b89a32223d34957119e1710087b5c2f80069f98ce312f6866bad7227a20ea53b13605c78e706178b494d335f744e570fcc1300dd3a76c36ab6
    BLAKE program SHA-512           1c06088ac039f7cb4cf5e42285bd092ceda8e51cdbb879a2e9d9bdba920c9f2f8b55d8c6f16a3fba9bbb63b309dfcbfa002a400c64bd55909a0ae10104a67b42
    SHA3 program SHA-512            cb4b55418696ec8f90fed166aaa8d7902f6a5aabe1e091a263558d82a6c44cc0dcdb51f456c7a13c6c231850d357819b867f7d95e55d78ef4a4aa59a7b2a6339

The important negative outcome is unchanged: source parity is executable now, but aggregate
scalar/M4 parity is not executed while disk is below 28 GiB. The symlinked Binius tree is pinned
but not retained/self-contained. A later compiled run must preserve its artifacts and transcripts
before any execution counter can move from zero.

## Context and Orientation

`HX448C02` is a test-only public-statement codec. It carries 56-byte post-quantum diagnostic
digests for notes, nullifiers, commitments, Merkle roots, ciphertext hashes, the balance tag, and
activation identities, while the three stablecoin authority values use the live 48-byte width.
The scalar implementation packs the 869 bytes into consecutive little-endian seven-byte limbs.
The M4 implementation packs the same bytes into consecutive little-endian eight-byte words. Both
projections are injective only if the unused high bytes of their final padded element are zero.

The relation has two input slots and two output slots. A four-bit activity mask therefore has 16
values. The five authorization modes are single-key spend, accumulator initialization, approval
step, value-lock creation, and final threshold spend. Shape rules accept 33 mask/mode pairs and
reject 47 per hash profile. Two profiles share the same frames and semantics: mixed unkeyed RFC
7693 BLAKE2b-448 plus SHAKE256-448, and separately tagged SHA3-512 truncated to 448 bits plus
SHAKE256-448.

There are 83 physical hash calls. Calls 0--3 are note commitments, 4--5 are nullifiers, 6--69 are
two depth-32 Merkle paths, 70--73 are two separately tagged spend-key derivations for each input,
call 74 is the private authorization policy root, 75--78 are four authorization lanes, call 79 is
the public-statement intent, call 80 is the balance tag, and calls 81--82 hash the two full 2,147-
byte ciphertext lanes. Call 74 is not the stablecoin manifest policy hash.

The scalar relation is a differential oracle: its transaction rules are Rust host predicates and
its hash calls each carry independently verifiable Boolean traces. The M4 candidate is intended to
be one aggregate constraint graph. A static source certificate can establish that every scalar
field, predicate, frame source, and output has a named M4 counterpart. Only compilation plus
witness execution can establish that the emitted graph behaves that way.

## Plan of Work

First, wait for both source implementations and their focused fixtures to stop changing. Re-read
every changed function, especially the codec offsets, public packing, stablecoin word types,
manifest view, frame construction, constraint helpers, and disk-gated differential tests.

Second, write `certificate.json`. It will pin every source dependency by SHA-256 and SHA-512, pin a
canonical framed composite SHA-512, enumerate the codec fields, private transport, 83-call family
partition, primitive-core counts, frame lengths and source classes, authorization mux arms,
hash-to-hash chains, public output bindings, stablecoin external-admission boundary, and every
paired non-hash semantic family. It will carry explicit zero values for all execution evidence not
run under the closed disk gate.

Third, write `corpus.json`. It will enumerate all accepted and rejected mask/mode pairs, ordinary
and stablecoin positive cases, codec/hash/equality/semantic mutation classes, expected execution
cardinalities, and exact ignored Rust test names that realize the future disk-open differential
run.

Fourth, write `check_certificate.py`. The checker will use only the Python standard library. It
will reject source hash drift, symlinks, out-of-root paths, malformed JSON, overlapping or gapped
codec fields, wrong final padding, incomplete call-index coverage, inconsistent frame/core totals,
mask/mode partition drift, missing scalar/M4 source anchors, mismatched stablecoin widths, an
unframed or ambiguous source digest, non-false authority flags, and any mismatch between declared
and derived outstanding execution counts.

Fifth, write `test_check_certificate.py`. Tests will validate the live manifest and then mutate one
representative from each critical class in memory: source byte, field boundary, call index, core
count, stablecoin width, manifest edge, call-74 role, accepted/rejected mask partition, execution
count, and authority flag. The tests must prove fail-closed behavior without compiling Rust.

Finally, run the checker, its unit tests, the candidate's existing dependency-free source checker,
and `git diff --check` scoped to this directory. Recompute hashes immediately before reporting. If
the scalar or M4 files drift during validation, repeat the read and pinning pass.

## Concrete Steps

Run commands from `/Users/pldd/Projects/Reflexivity/Hegemon`. While free disk remains below 28 GiB,
the only permitted validations are:

    python3 .agent/hardening/scalar-m4-parity-certificate/check_certificate.py
    python3 .agent/hardening/scalar-m4-parity-certificate/test_check_certificate.py
    python3 prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/check_source.py
    git diff --check -- .agent/hardening/scalar-m4-parity-certificate

After at least 28 GiB is available, follow the exact ignored-test commands recorded by
`corpus.json`. Recheck disk immediately before those commands. Do not infer a proof-profile winner
from source-static results.

## Validation and Acceptance

The source-only milestone passes when the checker reports all 83 call indices exactly once, a
contiguous 869-byte mixed-width codec, exact scalar and M4 padding, an exhaustive 80-case mask/mode
partition per profile, complete source anchors for every declared semantic/equality family, stable
manifest byte and lifecycle boundaries, all authority flags false, and zero executed aggregate
comparisons. The mutation suite must reject every intentionally corrupted manifest.

The later executed milestone requires both profiles to run every accepted and rejected shape, all
per-call frame/digest comparisons, every authorization arm comparison, stablecoin live-view cases,
and the selected mutation corpus against actual emitted M4 constraint systems. A pass at that
later milestone still does not establish complete zero knowledge, composed PQ128/QROM security,
proof-system soundness, verifier refinement, a selected winner, or production authority.

## Idempotence and Recovery

All commands are read-only except for Python cache files; the tests avoid repository writes and use
in-memory mutations. If source changes after pinning, the checker fails and the certificate must be
reviewed and regenerated rather than relaxed. Never reset, clean, delete a build tree, or overwrite
another worker's edits. A future disk-open run must use the repository's explicit 28-GiB admission
gate and a separate retained-artifact process.

## Artifacts and Notes

The final directory will contain this ExecPlan, `README.md`, `certificate.json`, `corpus.json`,
`check_certificate.py`, and `test_check_certificate.py`. Source hashes describe the exact dirty
working-tree bytes, not a commit and not a retained dependency tree. The existing Binius revision
and local-tree digest remain separate dependency evidence and do not make the symlinked dependency
self-contained.

## Interfaces and Dependencies

The checker requires Python 3 and its standard `hashlib`, `json`, `pathlib`, `re`, and `unittest`
modules. It must not import project Rust code, Cargo metadata, or network packages. JSON is the
stable interface: `certificate.json` describes the source refinement and `corpus.json` describes
the future executable witnesses and mutations. The Rust sources remain the authority if the JSON
and sources disagree; disagreement makes the checker fail.

Revision note: Created and completed on 2026-08-22 after the fresh grammar-two stablecoin width,
whole-manifest existential admission repair, independent review, and final rustfmt-only pass.
