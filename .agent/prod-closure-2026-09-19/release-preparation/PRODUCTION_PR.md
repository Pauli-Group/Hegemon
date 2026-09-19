# RP04 / q38 production cutover — security closure in progress

Draft while the remaining mathematical security arguments are completed.
This is not yet production-ready and does not activate a production capability.

## Proposed base and branch

- Base: `origin/main` (`86a6469f`); merge-base `b819911d`.
- Working branch: `codex/smallwood-pq128-experiment`.
- This includes the existing 55-commit SmallWood/native-proof workstream plus
  commit `c022de49`, which integrates the 48-file RP04/q38 change, and
  `3275af8c`, which packages the checked mathematical component source closure.
  The subsequent repair commit updates RP04 vectors and tests, fixes the TLS
  dependency advisory, and repairs existing CI checker integration.

## Summary

This PR packages the repaired RP04 implementation and q38 proof profile.
It includes the native SMZA profile-9/domain-5
fixture bindings, current-source artifact validation, wallet/native carrier
changes, and retained lifecycle preparation. The fresh RP04 bundle is retained
at `artifacts/smallwood-poseidon2-v8-smza/smza-rp04-native-refresh-20260919T180631Z`.
Its 18 proof payloads are byte-identical to the generated pair; the manifest
records a native-source-only refresh and `production_eligible: false`.

## Evidence boundary

- The retained RP04 bundle and native lifecycle evidence passed the repository
  checker for their recorded source snapshot. Subsequent dependency, test,
  formatting and recursive-replay helper changes require final affected-source
  validation; the retained passes are not represented as covering every later edit.
- Independently randomized proofs measure 163,409 and 163,281 bytes, both below
  the unchanged 164,113-byte cap. Inline carriers are 168,843 and 168,715 bytes,
  below the unchanged 169,547-byte cap. The query count remains 38.
- The source verifier, canonical readback, mutation controls, in-process
  lifecycle, actual-socket lifecycle, and software-evidence checker passed.
  These local receipts are retained separately, not bulk-uploaded in this PR.
- The PR includes 37 PASS-receipt-matched Lean component roots plus their80
  recursive custom dependencies, pinned by source hash. The portable source
  checker and reproduction instructions are included. The universal q38
  middle-support counting theorem and concrete field adapter now pass Lean;
  source-manifest validation is distinct from a new all-component Lean build.
  Components include actual factor coverage/degree ledgers, regular-start
  counting, primitive origin-root coverage, and initialized quantum routing.
  New roots add a joint four-role bound on one initialized quantum execution,
  canonical RP04 Merkle leaf injectivity/opening transport, and initialized
  privacy leaf overlap and initialized CMS boundedness. The actual140-column
  decoder's two local losses now compose below2^-265, with a standard-axiom-only
  audit; this is not a265-bit whole-system security claim.
  Actual accepted-event identification and full adaptive
  privacy remain separate obligations.
- The q38 work remains formal/source evidence, not an end-to-end deployed
  security proof. Adaptive privacy,
  accepted-transcript extraction, quantum/binding/lifetime composition, and
  existing release review remain open. Universal Rust/compiler/OS proofs are
  explicitly outside this task; no such prerequisite is added.
- `protocol/versioning` still returns no production capability. This PR does
  not activate production, claim a live deployment, or add an external host.

## Intended source scope

Include the changed protocol/circuit/native/wallet implementation and the
RP04-specific checker, tests, vectors, and release-preparation records. The
relevant source/evidence paths are under `circuits/transaction/`,
`circuits/block-recursion/`, `node/src/native/`, `protocol/shielded-pool/`,
`protocol/versioning/`, `wallet/`, `scripts/check_*smallwood*`,
`scripts/test_check_*smza*`, `testdata/formal_core_vectors/`, and the selected
`.agent/prod-closure-2026-09-19/release-preparation/` records.

Do not include the unrelated `.claude/skills/`, `.codex/skills/`, or `AGENTS.md`
edits. Do not bulk-add historical `.agent/artifacts/`, old checkpoints, or
unrelated hardening experiments; retain only evidence explicitly referenced by
the PR and reproducible from its source paths.

## Release posture

Checked CI repairs:

- Rust formatting and regenerated RP04 source-security report.
- rustls 0.23.45 and required webpki 0.103.15; dependency audit passes with
  zero unwaived advisories and zero unused waivers. The affected integration
  target compiles. This is not a live TLS handshake regression test.
- All three stale/missing native fixture tests, RP04 coinbase KAT/schedule,
  hash-kernel vector conformance, executable-ROM report, auxiliary geometry
  projection, and recursive verified-record mutation tests pass locally.
- Separately named RP04 Lean program/refinement and generated vectors pass;
  historical RP03 evidence remains separate and unchanged.
- Formal source hash, two module-parser regressions, 14 governance tests, and
  claims/active-progress and full blueprint policy checks pass. All 121 source
  reviews remain pending. These policy results do not close
  the mathematical security contract or approve pending source reviews.
- Successor-authorization tests pass after refreshing the non-authorizing
  current-report pin and separating the byte-pinned historical RP03 test
  report. No production flag, identity, or source registry entry is enabled.
- Formal-checker formatting passes. All seven PoW-rule tests pass after the
  three PoW/timestamp/subsidy fixtures stop introducing unrelated decoder-only
  transactions. Their original rejection assertions remain unchanged, with
  diagnostic messages added; no production validation or test is disabled.
- The subsequent transaction-core `manual_div_ceil` lint is repaired; focused
  `cargo clippy -p transaction-core --lib -- -D warnings` passes. The HX512
  persistence/restart test passes with a2-second reopen retry restricted to
  transient Sled `WouldBlock` errors and its original exact-byte assertions.
  The CI-observed governance hash is refreshed and all14 focused tests pass
  again; the claims checker passes without approving any pending source review.

The 37-root,117-source mathematical bundle now includes the checked global
counting theorem and concrete field specialization. Their axiom audit reports
only `propext`, `Classical.choice`, and `Quot.sound`; no count assumption remains.
The analysis-only support threshold65536 does not increase q38, degree405, or
proof bytes. Accepted-execution readout, actual sampler-event and RP04 arithmetic
instantiation, quantum/lifetime composition, and full adaptive privacy remain
open. Initialized leaf overlap and the initialized CMS boundedness prefix pass.
A further retained local per-basis collision lemma now passes, but is not yet
included in the117-source published bundle. The global resampling assembly
still fails Lean and is not counted as checked. All six local degree chunks
pass, but their combined certificate facade fails aggregation/flattening.
The whole-view interpreter's seven-constructor
initialized-purification/Born-average identity is written but unchecked; the
chronological application still needs the actual q38 coin dimensions.

Wallet multisig and release-profile checks report absent fresh-proof route
authority; their tests remain enabled. The app end-to-end coinbase timeout and
remaining full CI checks have not been resolved. No all-green CI, production
eligibility, or completed independent review is claimed.

The existing CI release workflow can build manifest-bound binaries and create a
draft GitHub release after its authorization/security jobs pass. It is not a
live deployment workflow. The requested deliverable is a production-ready PR,
not a live deployment. The open security contract must still be closed before
this change can honestly be presented as production-ready.
