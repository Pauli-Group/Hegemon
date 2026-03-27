# Finish The Native Proof Line Or Kill It

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

This plan succeeds [`.agent/SUPERNEO_HARDENED_BACKEND_EXECPLAN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/SUPERNEO_HARDENED_BACKEND_EXECPLAN.md). That earlier plan finished the current hardening pass. It did not finish the native line itself. The purpose of this document is to close that gap with a hard result instead of another round of experimental drift. Future rewrite work now lives in [`.agent/REBUILD_NATIVE_BACKEND_EXECPLAN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/REBUILD_NATIVE_BACKEND_EXECPLAN.md); this document remains the historical closure record for the killed baseline.

## Purpose / Big Picture

After this change, Hegemon will no longer sit in the useless middle ground where the native line is “promising” but not decisive. A contributor will be able to start a node in a native-only experimental mode, produce and import blocks without `InlineTx` fallback on that mode, inspect one explicit security statement for the backend that is actually enforced by code, and run one benchmark package that ends with a keep-or-kill verdict.

The user-visible outcome is binary. Either the current small-field/lattice native line becomes Hegemon’s real proof-native mainline candidate, or the repository records that it failed and stops pretending otherwise. This plan is not allowed to end in “still a good research spike.” It must end in promotion or kill.

## Progress

- [x] (2026-03-26 21:46Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, and `.agent/SUPERNEO_HARDENED_BACKEND_EXECPLAN.md` to anchor this successor plan in the actual current branch state.
- [x] (2026-03-26 21:46Z) Confirmed the current unresolved gaps: the backend still has only a challenge-limited experimental security story, native import verification is still linear, and the real shipping path still remains `InlineTx`.
- [x] (2026-03-26 21:46Z) Authored this ExecPlan as the closure path for the current proof-native small-field/lattice line.
- [x] (2026-03-27 04:18Z) Froze the operator budget and keep/kill gates in this document before the closure pass, then held the implementation against those gates instead of relaxing them after the fact.
- [x] (2026-03-27 04:18Z) Implemented `NativeSecurityEnvelope`, exposed it in the canonical benchmark JSON, and added overclaimed-security regressions. The current honest envelope is `claimed_security_bits = 63`, `challenge_bits = 63`, `fold_challenge_count = 1`, `opening_randomness_bits = 16`, `soundness_floor_bits = 63`.
- [x] (2026-03-27 04:18Z) Closed the security question with a loss. The current line could not be raised from the 63-bit challenge-limited story to the required 96-bit floor without further redesign, so the closure verdict records that failure instead of rebranding it as a candidate.
- [x] (2026-03-27 04:18Z) Added `HEGEMON_REQUIRE_NATIVE=1` as a fail-closed native-only guard around authoring and import. The node now rejects non-canonical selectors, rejects `InlineTx` fallback outcomes, and rejects non-canonical block payloads in that mode.
- [x] (2026-03-27 04:18Z) Re-benchmarked the canonical lane, archived the JSON at `.agent/benchmarks/native_tx_leaf_receipt_root_finish_native_proof_line_20260326.json`, built a release node with `make node`, started `hegemon-node` under `HEGEMON_BLOCK_PROOF_MODE=receipt_root HEGEMON_REQUIRE_NATIVE=1 HEGEMON_MINE=1 --dev --tmp`, and recorded the final verdict below: `KILL`.

## Surprises & Discoveries

- Observation: the current line is much closer to a real candidate than it was before plan 4, but the unresolved gaps are now more concentrated and less deniable.
  Evidence: the repository already has one canonical native lane, one versioned parameter object, one artifact fingerprint, and one hardened commitment/opening/fold path; the remaining blockers are security closure, native-only end-to-end operation, and the acceptability of linear verification.

- Observation: the worst failure mode for this branch is no longer fake code. It is endless “candidate” language after the hardening work already landed.
  Evidence: `.agent/SUPERNEO_HARDENED_BACKEND_EXECPLAN.md` ended with a research keep verdict for what is now named `heuristic_goldilocks_baseline`, but the branch still had no answer to “can this replace `InlineTx`?”

- Observation: accumulation work is now background noise, not the main question.
  Evidence: `receipt_accumulation` remains warm-store-only and `receipt_arc_whir` remains diagnostic. Neither changes whether the current native line itself is finishable.

- Observation: once the benchmark JSON started exposing the real security envelope, the closure result became binary immediately.
  Evidence: the archived closure benchmark reports `soundness_floor_bits = 63`, which fails the `>= 96` security gate before any interpretation layer can soften it.

- Observation: wall-clock variability still matters even after the benchmark cleanups from the previous plans.
  Evidence: the archived closure rerun at `.agent/benchmarks/native_tx_leaf_receipt_root_finish_native_proof_line_20260326.json` missed the operator verify budget at `k=32` (`274.83 ms`) and `k=64` (`585.35 ms`) even though earlier same-tree reruns sometimes came in faster.

- Observation: native-only node startup is easy to prove, but native-only proof-path exercise is not.
  Evidence: the release node starts cleanly under `HEGEMON_REQUIRE_NATIVE=1`, but an empty `--dev --tmp` chain does not generate the 20 consecutive shielded `receipt_root` blocks needed to close the functional gate.

## Decision Log

- Decision: this plan is a closure plan, not another exploratory hardening pass.
  Rationale: the branch already has enough infrastructure and enough negative results. The next plan must force a promotion-or-kill answer.
  Date/Author: 2026-03-26 / Codex

- Decision: accumulation and residual verifier work are explicitly frozen out of scope here.
  Rationale: they are separate research topics and already consumed too much decision bandwidth. This plan is about finishing or killing the current native line itself.
  Date/Author: 2026-03-26 / Codex

- Decision: a native-only mode is mandatory before the line can be called finished.
  Rationale: if the line still requires `InlineTx` fallback in practice, it is not finished no matter how pretty the benchmark JSON looks.
  Date/Author: 2026-03-26 / Codex

- Decision: the backend must graduate from “challenge-limited experimental story” to an explicit claimed security envelope or die.
  Rationale: a fully PQ privacy chain cannot ship on a backend whose security statement still lives in apologetic prose instead of enforced code and testable parameters.
  Date/Author: 2026-03-26 / Codex

## Outcomes & Retrospective

KILL.

The current small-field/lattice native line is not Hegemon’s mainline proof-native candidate anymore. The closure pass produced three hard results:

- Security gate failed. `NativeSecurityEnvelope` now makes the backend say the quiet part out loud: `soundness_floor_bits = 63` under the assumption label `single transcript-derived fold challenge over Goldilocks; commitment binding remains heuristic for this in-repo backend`. The plan required `>= 96`.
- Performance gate failed on the archived closure rerun. `.agent/benchmarks/native_tx_leaf_receipt_root_finish_native_proof_line_20260326.json` kept bytes per tx inside budget (`18,073..18,552 B/tx`) but missed the verify budget at `k=32` (`274.83 ms > 250 ms`) and `k=64` (`585.35 ms > 500 ms`). `k=128` stayed below `1 s` (`945.22 ms`), but the gate was conjunctive.
- Native-only proof-path gate remains uncleared. The node now has a real fail-closed native-only mode, focused tests prove it rejects fallback, `make node` succeeds, and a release `--dev --tmp` node starts under `HEGEMON_BLOCK_PROOF_MODE=receipt_root HEGEMON_REQUIRE_NATIVE=1 HEGEMON_MINE=1`. But that empty dev chain did not exercise 20 consecutive shielded native `receipt_root` blocks, so the functional acceptance condition was not met.

What survives from this plan is narrower:

- keep `heuristic_goldilocks_baseline` in tree as a bounded experimental baseline
- keep the explicit `NativeSecurityEnvelope` and benchmark exposure
- keep the fail-closed native-only guard and its tests
- stop describing this line as Hegemon’s future shipping proof-native mainline

This plan succeeded at closure, not promotion. It replaced “candidate language” with an explicit no.

## Context and Orientation

The current native line lives in four main places.

The backend lives in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). This file defines `NativeBackendParams`, the commitment/opening code, the fold proof code, and the backend setup path. The killed in-tree baseline is now named `heuristic_goldilocks_baseline`; its current post-manifest fingerprint is `bd223455a9f9f3157fedd0d6d4c8da3526c9f5cc81fffa00e3c2fd0898398c0bb1d0a91288bb2a3c584b45806ad08424`.

The Hegemon-specific relation and native artifacts live in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs). This file defines `NativeTxValidityRelation`, native `TxLeaf` artifacts, and native `ReceiptRoot` artifacts.

The proof-routing boundary lives in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs). This file routes block artifacts by `ProofArtifactKind`, verifies native receipt-root artifacts, and still exposes the experimental warm-store and diagnostic accumulation lanes.

The node authoring and import path lives in [node/src/substrate/service.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs). This file selects `HEGEMON_BLOCK_PROOF_MODE`, prepares native artifacts, and currently falls back to `InlineTx` when the native lane is unavailable or invalid.

The benchmark harness lives in [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs). It already treats `native_tx_leaf_receipt_root` as the canonical experimental lane and keeps all other lanes behind `--allow-diagnostic-relation`.

Two terms matter for this plan.

A **native-only mode** means a node mode where authoring and import are not allowed to silently fall back to `InlineTx`. The node must either build and verify the native artifacts successfully or fail loudly.

A **security envelope** means an explicit, machine-derived statement of what the backend is actually claiming: challenge width, number of independent transcript challenges, fold composition count, commitment opening randomness, and the resulting claimed soundness floor. This is not documentation fluff. It is a type, tests, and benchmark output.

At the time this plan starts, the current branch has one important strength and one important weakness. The strength is that the native line is finally coherent. The weakness is that it still is not the active chain architecture in practice.

## Target Envelope

This plan uses one operator budget and one security budget. These are not suggestions. They are the promotion gates.

The security budget is:

- the backend must expose a claimed security floor of at least 96 bits for the promoted parameter set, derived from explicit code rather than prose
- if the current small-field/lattice line cannot clear that floor without unacceptable cost, the line is killed as a shipping candidate

The operator budget for the canonical benchmark on the target host is:

- bytes per tx must remain below `32 KiB` across `k = 1,2,4,8,16,32,64,128`
- `total_active_path_verify_ns` must stay below `250 ms` at `k = 32`, below `500 ms` at `k = 64`, and below `1 s` at `k = 128`
- the benchmark note and archived JSON must expose those numbers honestly as local wall-clock outputs, not as a fabricated canonical curve

The native-only functional budget is:

- a native-only dev-node scenario must seal and import at least `20` consecutive blocks without `InlineTx` fallback or local sidecar dependencies

If the line misses any of these budgets after the security and native-only milestones are complete, the line is not promoted. The plan must then record a kill verdict and disable the mode as a mainline candidate.

## Plan of Work

The first milestone is security closure. The current `heuristic_goldilocks_baseline` parameter set still exposes only a challenge-limited experimental story. That is no longer acceptable. In [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), add a `NativeSecurityEnvelope` that is derived from `NativeBackendParams` and the actual transcript construction. This type must state the backend’s claimed security floor in bits and the assumptions that produce it. The code must reject any parameter set whose advertised security target exceeds what the envelope can justify. If clearing 96 bits requires multiple independent challenges, multiple fold checks, or a larger transcript schedule, that work happens here. If the line cannot clear 96 bits without blowing up constants, the plan must stop and record that loss.

The second milestone is backend closure. The backend is still described in `DESIGN.md` and `METHODS.md` as an in-repo approximation rather than the papers’ full construction. The next pass must narrow that gap from both sides. In [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), make the parameter object fully security-relevant and self-describing. Add any missing norm, decomposition, or opening checks needed so malformed witnesses, malformed openings, and malformed fold rows fail for explicit reasons. Add tests that mutate each piece independently. This milestone is complete only when the benchmark JSON, artifact versioning, and verifier-profile derivation all flow from one explicit parameter and security envelope pair.

The third milestone is native-only operation. In [node/src/substrate/service.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs) and [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs), add a native-only operating mode for the current lane. This may be a new `HEGEMON_BLOCK_PROOF_MODE` value or an explicit “require native” guard alongside `receipt_root`. The crucial rule is that authoring and import must fail loudly instead of falling back to `InlineTx`. The point is to prove that the current line can operate as a real chain mode. This milestone is not satisfied by tests alone. It must include an end-to-end dev-node run that produces and imports blocks without fallback.

The fourth milestone is decision benchmarking. Run the canonical release benchmark on the promoted native parameter set, archive the JSON, and compare it to the operator budget above. Then run the native-only dev-node scenario and capture the observable proof mode. If the line clears the security, benchmark, and native-only gates, promote it in `DESIGN.md`, `METHODS.md`, and this plan as the mainline proof-native candidate. If it misses any gate, record a kill verdict and state exactly why this line is not the answer.

This plan must not drift into new accumulation work, new wrapper proofs, or new bridge surfaces. If verification remains linear but still clears the operator budget, that is an acceptable result. If linear verification misses the operator budget, the result is a kill, not a side quest.

## Concrete Steps

From the repo root `/Users/pldd/Projects/Reflexivity/Hegemon`, execute this plan in the following order.

1. Add `NativeSecurityEnvelope` and the explicit security-floor checks in `circuits/superneo-backend-lattice/src/lib.rs`, then run:

       cargo test -p superneo-backend-lattice -p superneo-hegemon

2. Complete the missing parameter-bound backend checks, add negative tests for malformed openings, malformed fold rows, mixed parameter sets, and overclaimed security targets, then run:

       cargo test -p superneo-backend-lattice -p superneo-hegemon -p consensus receipt_root_ -- --nocapture

3. Add the native-only mode in `node/src/substrate/service.rs` and `consensus/src/proof.rs`, together with focused tests that prove fallback is forbidden in that mode, then run:

       cargo test -p hegemon-node receipt_root -- --nocapture

4. Build the release node and run a native-only dev chain from the repository root:

       make node
       HEGEMON_BLOCK_PROOF_MODE=receipt_root HEGEMON_REQUIRE_NATIVE=1 HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

   The observable success condition is that the node starts, seals blocks, and never logs an `InlineTx` fallback reason.

5. Run and archive the canonical benchmark:

       cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx

6. Update `DESIGN.md`, `METHODS.md`, and this ExecPlan with one of two explicit verdicts:

       KEEP: native-only candidate, gates cleared

   or

       KILL: native line failed one or more closure gates

## Validation and Acceptance

Acceptance is explicit and observable.

The backend acceptance conditions are:

- `cargo test -p superneo-backend-lattice -p superneo-hegemon` passes
- the tests include failures for malformed openings, wrong randomness, mixed parameter sets, malformed fold rows, and overclaimed security targets
- the promoted parameter set exposes a computed `NativeSecurityEnvelope` with a claimed floor of at least 96 bits

The native-only mode acceptance conditions are:

- `cargo test -p hegemon-node receipt_root -- --nocapture` passes with coverage for “native-only mode rejects fallback”
- a dev node started with `HEGEMON_REQUIRE_NATIVE=1` seals and imports at least 20 consecutive blocks without `InlineTx` fallback

The performance acceptance conditions are:

- the canonical benchmark remains `native_tx_leaf_receipt_root`
- bytes per tx stay below `32 KiB` for all tested `k`
- verification stays below `250 ms` at `k=32`, below `500 ms` at `k=64`, and below `1 s` at `k=128`
- the benchmark JSON includes the parameter fingerprint and the explicit security envelope fields

If all three acceptance groups pass, the line is promoted.

If any one fails, the line is killed as a shipping candidate and the docs must say so plainly.

## Idempotence and Recovery

The security and benchmark steps are safe to rerun. The native-only dev-node step uses `--dev --tmp`, so it does not mutate persistent state. If the native-only mode fails, do not weaken it by reintroducing fallback. Fix the native line or record the kill verdict. If the security envelope cannot justify the claimed target, do not patch the docs. Lower the target honestly or kill the line.

## Artifacts and Notes

The most important outputs of this plan are not code snippets. They are:

- one archived canonical benchmark JSON for the promoted or killed parameter set
- one short native-only dev-node log excerpt showing either successful native-only sealing/import or the explicit blocker
- one explicit verdict paragraph in `DESIGN.md`, `METHODS.md`, and this plan

Expected benchmark JSON fields after implementation include:

    "parameter_fingerprint": "<48-byte hex>",
    "native_backend_params": { ... },
    "native_security_envelope": {
      "claimed_security_bits": ...,
      "challenge_bits": ...,
      "fold_challenge_count": ...,
      "opening_randomness_bits": ...,
      "soundness_floor_bits": ...
    }

Expected native-only log language should include either:

    native-only receipt_root lane selected

or a fatal startup/import failure that clearly states why the native line cannot be used.

## Interfaces and Dependencies

In [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), define:

    pub struct NativeSecurityEnvelope {
        pub claimed_security_bits: u32,
        pub challenge_bits: u32,
        pub fold_challenge_count: u32,
        pub opening_randomness_bits: u32,
        pub soundness_floor_bits: u32,
        pub assumption_label: &'static str,
    }

    impl NativeBackendParams {
        pub fn security_envelope(&self) -> anyhow::Result<NativeSecurityEnvelope>;
    }

The exact field names may grow, but the type must answer the only question that matters: what security claim is this parameter set honestly making?

In [node/src/substrate/service.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs), define one explicit native-only selector or guard. Preferred names are:

    const HEGEMON_REQUIRE_NATIVE: &str = "HEGEMON_REQUIRE_NATIVE";

or

    enum BlockProofStrictness {
        AllowInlineFallback,
        RequireNative,
    }

In [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs), extend the canonical JSON output with the security envelope and keep the relation default unchanged.

Revision note (2026-03-26 / Codex): created this successor plan because the hardening pass in `.agent/SUPERNEO_HARDENED_BACKEND_EXECPLAN.md` ended with a credible experimental candidate but not a closure verdict. This plan exists to force that verdict.
