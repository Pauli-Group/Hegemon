# Build and audit the E256-by-two mixed-field IOP seam

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current while the work proceeds. This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon needs a compact algebraic interface that can test a possible alternative to the 384-bit challenge field without pretending that two repetitions are already a security theorem. After this prototype, a reviewer can execute dependency-free tests showing that one B128 table is evaluated under two genuinely separate 256-bit extension-field challenge streams, inspect an exact canonical opening wire for shared and independent query schedules, and run a fail-closed manifest audit. The prototype never enters consensus and cannot create a production-frontier point.

## Progress

- [x] (2026-08-21T19:26:50Z) Read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, the existing E384 scaffold, and pinned Binius `ghash_sq.rs`.
- [x] (2026-08-21T19:26:50Z) Confirmed that free disk is below the 28 GiB Cargo/build gate and selected temporary direct-`rustc` validation only.
- [x] (2026-08-21T19:34:26Z) Implemented exact pinned B128 and `GhashSq256b`-compatible E256 arithmetic, serialization, two transcript streams, table commitment/openings, query models, and wire counters.
- [x] (2026-08-21T19:34:26Z) Added 13 randomized differential, parser, schedule, Merkle, stream-separation, and product-ring negative-control tests.
- [x] (2026-08-21T19:34:26Z) Recorded the deterministic n15 cost artifact and independently reproduced its schedules and bytes with Python.
- [x] (2026-08-21T19:34:26Z) Ran formatting, temporary direct-Rust tests with warnings denied, manifest audit, SHA-256 inventory, and diff hygiene without leaving build products.

## Surprises & Discoveries

- Observation: pinned Binius already contains the desired real quadratic extension. It represents `a + b*Y` over GHASH and reduces with `Y^2 = X*Y + X`; low and high 128-bit words are exactly the `{1,Y}` coefficient lanes.
  Evidence: `/private/tmp/binius64-api-3f961630/crates/field/src/ghash_sq.rs` at pinned commit `3f96163049f680b2909f6545690bd929f1b48c44`.

- Observation: independent n15 schedules derived from the frozen context/root overlap at only three of 264 unique positions per stream. The canonical union is 525 positions. The root is rebuilt from a deterministic 32,768-symbol B128 table rather than chosen as an arbitrary digest.
  Evidence: Rust and independent Python derivations both rebuild the root and report shared `U=264`, independent `U=525`, and independent overlap `3`.

- Observation: the full-path KAT is not comparable to the optimistic strict mixed-PCS screen. It fixes 264 queries per stream on the unencoded n15 table and uses 64-byte full paths; the other screen derives 637/222/127/87/66 queries from rates 1/2 through 1/32, expands the oracle, packs four symbols, uses 56-byte compact frontiers, and prices a TensorSwitch first-level message floor.
  Evidence: `README.md` records the complete comparison boundary, and `n15-wire-costs.json` marks the fixed query count as non-security-authoritative.

## Decision Log

- Decision: Keep this as a new dependency-free crate under `prototypes/standalone-shake256-binius/strict-e256x2-iop/`.
  Rationale: An isolated crate makes the type and claim boundary executable without importing it into production or allocating a large workspace target.
  Date/Author: 2026-08-21 / Codex.

- Decision: Treat the two E256 repetitions as two typed protocol streams, never as the direct-product ring `E256 x E256` and never as one 512-bit field.
  Rationale: Componentwise pairs have zero divisors. A product soundness conclusion requires a reviewed theorem about conditional independence and composition, not a wider label.
  Date/Author: 2026-08-21 / Codex.

- Decision: Serialize one SHAKE256-512 table root, transcript-derived query indices, canonical B128 leaves, full 64-byte authentication paths, and two explicit 32-byte terminal claims.
  Rationale: This is a simple exact wire that exposes the shared-versus-independent query cost without inventing a compressed multiproof or hiding those bytes in a side channel.
  Date/Author: 2026-08-21 / Codex.

- Decision: Do not edit `DESIGN.md` or `METHODS.md` from this task.
  Rationale: Parallel work already updated the shared E256 screening paragraphs. The parent requested a frozen isolated artifact and will merge architectural conclusions centrally.
  Date/Author: 2026-08-21 / Codex.

## Outcomes & Retrospective

The isolated seam is complete. Direct `rustc --test -D warnings` reports 13/13 passing tests, and the independent Python audit prints `E256X2_MANIFEST_PASS`. At n15 with the declared fixed 264-query-per-stream full-path grammar, shared scheduling is exactly 257,808 bytes; independent scheduling has a 525-leaf union and is exactly 512,544 bytes. Both validators rebuild the frozen root from the same deterministic 32,768-symbol B128 table. These values validate only this wire grammar. The manifest preserves false capability flags for whole-table claim binding, PCS/proximity theorems, conditional independence, product soundness, complete zero knowledge, QROM composition, current 384-bit-policy compliance, strict PQ128, and production eligibility. No Cargo target, Python cache, consensus edit, or frontier mutation was created.

## Context and Orientation

`B128` means the pinned GHASH field `GF(2)[X]/(X^128 + X^7 + X^2 + X + 1)`. A committed table contains only these 16-byte symbols. `E256` means the same field as pinned Binius `GhashSq256b`: pairs `(a,b)` representing `a + b*Y`, with `Y^2 + X*Y + X = 0`. It serializes as the little-endian B128 coefficient `a` followed by `b`, exactly 32 bytes.

The two repetitions share one B128 Merkle root but use domain-separated SHAKE256 transcript states. A shared query schedule opens the same leaf indices for both repetitions. An independent schedule derives one unique index set from each stream and opens the canonical sorted union. In both modes the proof carries no query indices because the verifier re-derives them from public context and the committed root.

The canonical opening wire is a KAT for byte topology, not a complete polynomial commitment. It authenticates queried B128 leaves but does not prove that the E256 multilinear claims correspond to the whole table, does not prove proximity or degree, and does not hide the opened leaves.

## Plan of Work

Create `Cargo.toml`, `src/lib.rs`, `README.md`, `security-manifest.json`, `n15-wire-costs.json`, and `check_manifest.py` under the isolated prototype directory. Implement B128 without dependencies and implement E256 with the exact pinned quadratic relation. Implement a local SHAKE256 pinned to the standard empty-input vector, a binary SHAKE256-512 Merkle tree, two stream-specific transcripts, dual multilinear evaluation, deterministic query derivation, an exact parser/serializer, and checked byte counters.

Randomized tests use a deterministic local PRNG and compare the field and fold operations with structurally separate reference routines. Tests must also verify the quadratic irreducibility trace witness, canonical coefficient order, stream domain separation and order independence, one-root sharing, parser rejection of truncation/trailing/malformed headers, Merkle mutation rejection, exact n15 wire costs, and every fail-closed flag.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, inspect disk before any build:

    df -k .

If available space is below 29,360,128 KiB, do not invoke Cargo. Format the one Rust source with `rustfmt`, compile its tests directly to an exact temporary path, run them, and remove that path immediately:

    rustfmt --edition 2024 prototypes/standalone-shake256-binius/strict-e256x2-iop/src/lib.rs
    rustc --edition 2024 --test -C opt-level=1 -C debuginfo=0 -o /private/tmp/hegemon-e256x2-tests prototypes/standalone-shake256-binius/strict-e256x2-iop/src/lib.rs
    /private/tmp/hegemon-e256x2-tests
    rm /private/tmp/hegemon-e256x2-tests

Run the independent manifest checker without bytecode output:

    PYTHONDONTWRITEBYTECODE=1 python3 prototypes/standalone-shake256-binius/strict-e256x2-iop/check_manifest.py

Finally run `git diff --check` and confirm no `target` or `__pycache__` directory exists under the prototype.

## Validation and Acceptance

The Rust test binary must report all tests passed. Randomized field tests must compare at least 256 B128 products, 256 E256 products, and dual multilinear evaluations for arities zero through seven. The n15 test must assert the exact stored byte counts for 264 unique requested queries per stream under both schedule modes.

The Python audit must print `E256X2_MANIFEST_PASS`, independently reproduce the reference schedules with Python SHAKE256, recompute each byte total from the canonical formula, and reject any manifest that turns on an unproved capability. The SHA-256 manifest must cover every durable artifact in the prototype except itself.

## Idempotence and Recovery

All repository edits are additive and confined to the prototype plus this plan. Direct Rust output uses one exact `/private/tmp` path and is removed after execution. If the test command fails, remove that exact file and retry after patching source. Never run `cargo clean`, delete the repository target, or modify the production frontier.

## Artifacts and Notes

The canonical byte equation is:

    bytes = 16 header
          + 64 one SHAKE256-512 root
          + 32 * 2 explicit E256 terminal claims
          + U * (16 one B128 leaf + 64 * n full authentication nodes)

Here `n=15` and `U` is the number of distinct opened table indices: exactly the per-stream query count for shared scheduling and the union size for independent scheduling.

## Interfaces and Dependencies

The prototype has no external dependencies. `E256::from_coefficients`, `E256::to_le_bytes`, and multiplication must match pinned `GhashSq256b`. `DualE256Transcript::sample` must return one E256 per stream and feed a response back only into that stream. `evaluate_dual_multilinear_b128` must consume one B128 table and two equal-arity E256 points. `QuerySchedule::derive` must derive unique indices and expose the canonical sorted union. `CanonicalOpeningProof::encode` and `decode_exact` must use that union order and exact consumption. `WireCounters::serialized_bytes` must agree with the encoded length.

Revision note (2026-08-21): created the plan after source inspection and before implementation; fixed the disk gate, algebra, wire grammar, validation method, and fail-closed boundary.

Revision note (2026-08-21): completed the isolated implementation, recorded the exact n15 shared/independent costs and rate-model comparison boundary, validated 13 Rust tests plus the independent Python checker, and retained every security/production capability as false.
