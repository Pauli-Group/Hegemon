# Remove the component precommit functional with one grouped Phase-A relation

This ExecPlan is a living document maintained under `/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md`. It describes a source-only delta applied after the frozen coefficient-aware trace-mask patch. It is not a complete-zero-knowledge result, strict-security evidence, or a measured proof-size frontier point.

## Purpose / Big Picture

The coefficient-aware trace repair commits a fresh outer precommit segment `K`, while outer Spartan formerly sent the separate scalar `<K,T_precommit>` and proved the private relation `<V,T_private>` independently. Together with the shifted inner trace, that component scalar restores a clear witness functional. The repair is to expose only the required total

```text
<K,T_precommit> + <V,T_private> = batched_sum - public_eval
```

and prove it as one cross-oracle Phase-A sumcheck. Neither API nor transcript carries either term claim. The real BaseFold path aggregates the two independent mask inner products into one sigma, samples one shared gamma, pads each native-size term independently, and still emits one reduced alpha per committed oracle. Phase B is unchanged.

## Progress

- [x] (2026-08-21T18:42:00Z) Audited the pre-existing disposable draft and rejected its unrelated trace-key detour.
- [x] (2026-08-21T18:55:00Z) Rebased the implementation as a delta after coefficient patch SHA-256 `684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54` on revision `3f96163049f680b2909f6545690bd929f1b48c44`.
- [x] (2026-08-21T19:05:00Z) Implemented grouped sumcheck rounds, aggregate sigma/shared gamma, per-term padding, per-oracle alphas, symmetric Spartan calls, and fail-closed queue ownership.
- [x] (2026-08-21T19:14:00Z) Found and fixed the wrapper integration blocker: wrapped prover, concrete verifier, symbolic builder, and replay now carry exactly one aggregate bridge scalar and never materialize a term claim.
- [x] (2026-08-21T19:21:08Z) Froze the 49,656-byte delta at SHA-256 `37dfdee589e476c09fe5c955bd46942cd5aa293a3177d7a43d07f14aeb8ef9df`; clean coefficient-then-grouped `git apply --check`, `git diff --check`, rustfmt check, and the dependency-free static checker pass.
- [ ] Run compilation and targeted executable tests only after free disk reaches 28 GiB.
- [ ] Generate two clean full prove/verify artifacts, mutate the aggregate claim, exact-decode both transcripts, and establish the actual byte delta.
- [ ] Complete the joint PCS/Spartan/Libra/Fiat--Shamir simulator and the selected strict extension-field backend before any security or frontier promotion.

## Surprises & Discoveries

- Observation: The original grouped draft targeted the inner trace relation rather than the unique outer precommit functional.
  Evidence: its wrapper logic reserved a trace key instead of replacing the separate outer `<K,T_precommit>` and `<V,T_private>` calls.
- Observation: A BaseFold-only implementation was insufficient for the real wrapper path.
  Evidence: `ZKWrappedProverChannel`, `IronSpartanBuilderChannel`, `ReplayChannel`, and `ZKWrappedVerifierChannel` inherited the fail-closed grouped default, so the outer wrapper would reject before proving.
- Observation: One aggregate wrapper bridge is necessary even though individual term claims are forbidden.
  Evidence: the native BaseFold verifier needs the concrete aggregate claim, while the symbolic/replay circuit computes it as a circuit value. Builder, replay, prover, and concrete verifier now allocate/record exactly one matching aggregate value.
- Observation: Grouped masking cannot send the old per-oracle sigmas.
  Evidence: `<omega_K,T_precommit>` and `<omega_V,T_private>` would be the same component-function interface under fresh masks. The correct masked aggregate is `(1-gamma) total + gamma (sigma_K + sigma_V)`.
- Observation: The source API can remain generic over its field, but the present patch is only B128 weak/profile mechanics.
  Evidence: pinned BaseFold is `BinaryField`-bound, and strict extension-field masking requires independent coefficient/repetition coverage in the strict value domain. Same-field B128 masking is diagnostic only.

## Decision Log

- Decision: Keep individual term claims out of both grouped method signatures.
  Rationale: An optional or hidden component-claim parameter would make accidental transcript serialization easy and defeat the security boundary.
  Date/Author: 2026-08-21 / Codex.
- Decision: Aggregate independent mask inner products before serialization and use the existing single gamma for all hiding messages.
  Rationale: This preserves the exact linear masking identity without revealing either component sigma.
  Date/Author: 2026-08-21 / Codex.
- Decision: Pad each term from its own `log_msg_len` to the global maximum and add round polynomials coefficient-wise.
  Rationale: Precommit and private oracles need not have equal sizes; pretending they do changes the transparent relation.
  Date/Author: 2026-08-21 / Codex.
- Decision: Preserve Phase B byte-for-byte.
  Rationale: Grouping changes only the Phase-A relation proof. The same per-oracle alphas feed the already combined FRI/Merkle opening.
  Date/Author: 2026-08-21 / Codex.
- Decision: Reject grouped use on evaluation-masked wrapper oracles and reject unsupported channel implementations by default.
  Rationale: The coefficient-aware trace relation has a separate nonzero-coefficient contract; silently decomposing or mixing it would bypass both designs.
  Date/Author: 2026-08-21 / Codex.
- Decision: Do not update proof-size constants or claim any byte saving before execution.
  Rationale: The coefficient patch changes oracle layout and may cross padding/FRI tiers; source event counts are not an artifact measurement.
  Date/Author: 2026-08-21 / Codex.

## Outcomes & Retrospective

The frozen delta removes the direct precommit-only send from outer Spartan and replaces the two secret wiring relations with one aggregate relation on prover and verifier. The BaseFold prover creates one grouped sumcheck whose inner terms retain their own buffers and variable counts. Its aggregate round polynomial is serialized; term claims remain prover-local. The verifier reconstructs the reduced aggregate from one alpha and transparent evaluation per oracle. The wrapper stack bridges exactly one aggregate scalar, so builder, replay, prover, and verifier event schedules match.

Static evidence passes, including clean two-patch application, pinned source hashes, aggregate-mask and padding algebra KATs, Phase-B slice hashes, rustfmt, and whitespace checks. Compilation, executable roundtrip, proof bytes, complete ZK, strict security, and frontier eligibility remain false.

## Context and Orientation

The public grouped interfaces are in `crates/iop-prover/src/channel/mod.rs` and `crates/iop/src/channel/mod.rs`. The generic round-polynomial combiner is `crates/ip-prover/src/sumcheck/grouped.rs`. The real masking and opening implementation is split between the prover and verifier `crates/iop*/src/basefold/channel.rs`. Outer Spartan selects the exact two terms in `crates/spartan-prover/src/lib.rs` and `crates/spartan-verifier/src/lib.rs`.

The wrapper bridge spans four files: the wrapped prover records one native aggregate, the symbolic builder allocates one inout, replay consumes one event, and the concrete wrapped verifier reads one native aggregate then forwards the grouped relation. The earlier coefficient-aware evaluation-mask methods remain intact and grouped use of that special oracle is rejected.

## Plan of Work

Apply the frozen coefficient patch first and this grouped delta second. Source-audit the resulting tree with the included checker. Once the disk admission gate opens, compile the affected crates offline, run the grouped unit tests and existing wrapper integration, then generate and exact-decode proof artifacts. Only after executable symmetry passes should the proof-size regression constant be replaced with the measured value. Security work then requires a joint simulator over the BaseFold commitments, aggregate sigma, Phase-A sumcheck, per-oracle alphas, Phase-B FRI/Merkle view, outer Libra/Spartan endpoints, and Fiat--Shamir composition.

## Concrete Steps

From a clean checkout at the pinned revision:

```text
git apply --check prototypes/standalone-shake256-binius/m4-zk-coefficient-mask-patch/hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch
git apply prototypes/standalone-shake256-binius/m4-zk-coefficient-mask-patch/hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch
git apply --check prototypes/standalone-shake256-binius/m4-zk-grouped-relation-patch/hegemon-m4-zk-grouped-relation-after-coefficient-3f961630.patch
git apply prototypes/standalone-shake256-binius/m4-zk-grouped-relation-patch/hegemon-m4-zk-grouped-relation-after-coefficient-3f961630.patch
python3 prototypes/standalone-shake256-binius/m4-zk-grouped-relation-patch/check_grouped_relation_patch.py --tree "$PWD"
git diff --check
```

Do not run Cargo, a build, or a prover when `df -Pk` reports less than `29,360,128 KiB` free. A hard stop remains at 20 GiB during future executable work. When admitted, use a disposable target under `/private/tmp`, offline locked dependencies, and remove only that explicitly named target after recording hashes:

```text
CARGO_TARGET_DIR=/private/tmp/hegemon-grouped-target cargo +1.97.1 test --locked --offline -p binius-ip-prover grouped_
CARGO_TARGET_DIR=/private/tmp/hegemon-grouped-target cargo +1.97.1 test --locked --offline -p binius-iop-prover grouped_
CARGO_TARGET_DIR=/private/tmp/hegemon-grouped-target cargo +1.97.1 test --locked --offline -p binius-spartan-prover --test wrapper_integration_test
CARGO_TARGET_DIR=/private/tmp/hegemon-grouped-target cargo +1.97.1 test --locked --offline -p binius-spartan-prover --test proof_size_exactness_test
```

## Validation and Acceptance

Source acceptance requires all of the following:

1. No `precommit_claim` computation, send, receive, method argument, or transcript event remains.
2. The only outer secret wiring relation is `<K,T_precommit>+<V,T_private>=batched_sum-public_eval`.
3. Every multi-oracle grouped term is hiding, distinct, already committed/received, disjoint from ordinary relations, and owned by only one group.
4. One aggregate sigma is sent per hiding relation; every hiding message uses the same post-commitment gamma.
5. Each term uses its native variable count and exact `eq(0,padding)` factor; one reduced alpha is returned for every committed oracle with duplicate/missing checks.
6. Builder, replay, wrapped prover, and concrete wrapped verifier consume exactly one aggregate bridge and zero term bridges.
7. Phase B source slices match the coefficient-patched baseline hashes.
8. The clean two-patch stack passes `git apply --check`, rustfmt, `git diff --check`, source hashes, and the static KAT checker.

Executable acceptance additionally requires successful grouped and wrapper tests, honest proof verification, aggregate-claim mutation rejection, exact transcript consumption, two clean reproductions with identical structural counters, and an updated measured proof-size baseline. Security acceptance separately requires the complete simulator/composition and strict field-specific masking evidence. Source acceptance does not imply either.

## Idempotence and Recovery

The immutable base and ordered patch hashes make reconstruction deterministic. Applying either patch twice must fail rather than duplicate methods. The checker is read-only and safe to rerun. Work remains isolated in disposable `/private/tmp` checkouts; no production source tree or sealed frontier ledger is mutated by this archive.

## Artifacts and Notes

- coefficient prerequisite: `../m4-zk-coefficient-mask-patch/hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch`, SHA-256 `684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54`
- grouped delta: `hegemon-m4-zk-grouped-relation-after-coefficient-3f961630.patch`, SHA-256 `37dfdee589e476c09fe5c955bd46942cd5aa293a3177d7a43d07f14aeb8ef9df`
- static checker: `check_grouped_relation_patch.py`
- source manifest: `hegemon-m4-zk-grouped-relation-after-coefficient-3f961630.sha256`
- report: `hegemon-m4-zk-grouped-relation-report.md`

The 2026-08-21 disk sample was approximately 24.6 GiB free, below the 28 GiB admission gate. No Cargo command, compilation, test binary, proof, or measurement was run.

## Interfaces and Dependencies

`IOPProverChannel::prove_grouped_oracle_relation` and `IOPVerifierChannel::verify_grouped_oracle_relation` accept only `(oracle, transparent)` terms and one aggregate claim. Their defaults fail closed. `GroupedSumcheckProver` combines one-claim padded term provers with a common round count. No dependency is added.

The interface is field-generic at source level, but this artifact exercises the pinned B128 `BinaryField` BaseFold mechanics only. It must not be cited for E384, `GhashSq256b`, repeated-extension, strict-PQ, or complete-ZK claims. Any strict backend must separately prove full value-domain mask coverage, sound field algebra, PCS binding/hiding, and composed security.

Revision note (2026-08-21): Initial source-only plan frozen after correcting the draft's target and closing wrapper/replay/builder symmetry. The artifact remains rejected pending executable and simulator evidence.
