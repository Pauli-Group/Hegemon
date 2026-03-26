# Harden The Native PQ Folding Backend Into A Credible Production Candidate

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

The current native folding branch proves the topology and measures useful scaling, but it still relies on an experimental in-repo backend. That means Hegemon cannot honestly claim production-strength post-quantum security from it yet. After re-checking the literature, this plan also needs a narrower research footing than it originally had: the accessible concrete backend guidance comes primarily from `Neo`, `LatticeFold+`, and lattice-PCS work such as `HyperWolf`, while `SuperNeo` remains important but still partially provisional here because we can verify its existence and title from the 2026 ePrint listing more easily than its full construction details. After this plan, the branch should have a hardened native folding backend candidate: real commitment randomness, real opening proofs, real parameter discipline, a versioned verifier profile derived from those parameters, and a test story strong enough that the experimental lane can be judged on security and performance rather than on faith.

The user-visible result is a backend that a contributor can benchmark and inspect without having to mentally subtract “toy backend” from every chart. The goal is not paper worship. The goal is a working, optimized, plausibly secure production candidate that preserves Hegemon’s small-field and PQ direction.

## Progress

- [x] (2026-03-26 02:02Z) Re-read `.agent/PLANS.md`, `.agent/SUPERNEO_EXPERIMENT_EXECPLAN.md`, `DESIGN.md`, `METHODS.md`, and the current `circuits/superneo-backend-lattice` implementation.
- [x] (2026-03-26 02:02Z) Confirmed from the current docs that the backend remains an experimental Ajtai-style approximation and does not justify a production 128-bit PQ claim.
- [x] (2026-03-26 02:02Z) Authored this ExecPlan as the hardening roadmap for the SuperNeo backend candidate.
- [ ] Introduce a versioned backend parameter object and a reproducible verifier-profile derivation from those parameters.
- [ ] Replace deterministic commitment projection with randomized hiding/binding commitments and explicit opening proofs.
- [ ] Replace digest-style fold proofs with real algebraic fold verification under the chosen parameter set.
- [ ] Add malformed-proof, wrong-opening, wrong-randomness, and cross-profile rejection tests.
- [ ] Add benchmark and memory captures for the hardened backend at `k=1,2,4,8,16,32,64,128`.
- [ ] Decide whether the hardened backend remains good enough to be the primary PQ candidate or whether Hegemon should pivot to a different backend line.

## Surprises & Discoveries

- Observation: the accessible research support is strongest for `Neo` and `LatticeFold+`, not for every specific `SuperNeo` implementation detail.
  Evidence: `Neo` is easy to verify from public snippets and the ePrint record as a lattice-based folding scheme for CCS over small fields with pay-per-bit commitments; `LatticeFold+` is easy to verify from the ePrint record as a faster/simpler lattice-based folding line; `SuperNeo` is verifiable as a 2026 ePrint entry and title, but the fine construction details are not as directly inspectable from the sources available in this environment.

- Observation: the current branch already answered the topology question without answering the security question.
  Evidence: the native `TxLeaf -> ReceiptRoot` path is wired and benchmarked, but the current docs still state that the branch does not justify a production 128-bit PQ claim.

- Observation: the most dangerous gap is not missing code volume; it is missing cryptographic binding between the proof object, the commitment randomness, the parameter set, and the verifier profile.
  Evidence: the current backend is explicitly described as an approximation in [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md#L952).

- Observation: Hegemon’s architecture now gives the backend room to evolve without another consensus rewrite.
  Evidence: the proof-neutral verifier registry and block-artifact boundary already exist in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L188).

## Decision Log

- Decision: harden the existing native PQ folding direction rather than replacing it immediately with another experimental backend.
  Rationale: the accessible literature still supports the direction strongly enough to justify hardening work, but the plan should no longer pretend that every concrete step is already nailed down by `SuperNeo` alone. The concrete reference stack is `Neo` plus `LatticeFold+` plus lattice commitment work, with `SuperNeo` treated as an important but still partially provisional upgrade line.
  Date/Author: 2026-03-26 / Codex

- Decision: treat parameter discipline and verifier-profile derivation as part of the cryptographic implementation, not as paperwork.
  Rationale: without a stable parameter fingerprint, the node cannot tell one security regime from another, and benchmark numbers become meaningless across revisions.
  Date/Author: 2026-03-26 / Codex

- Decision: keep the backend swap boundary intact while hardening.
  Rationale: if hardening reveals unacceptable costs, Hegemon must still be able to replace the backend without reopening consensus surgery.
  Date/Author: 2026-03-26 / Codex

## Outcomes & Retrospective

This plan is design-only at creation time. The hardened backend does not exist yet. The expected outcome is a versioned, parameterized native folding backend that can be judged honestly on both security posture and performance. If it fails that judgment, the result should still be useful because the proof-neutral boundary survives and the hardening work will have made the failure explicit.

After re-checking the literature on 2026-03-26, the correction is that this remains the right hardening plan, but the title and rationale need to be narrower. The plan should be read as “harden the native PQ folding candidate” rather than “implement known-good SuperNeo details line by line.” The accessible basis for the hardening work is strongest around `Neo`, `LatticeFold+`, and lattice PCS/opening work. `SuperNeo` remains a watch item, not a fully inspectable spec in this environment.

## Context and Orientation

The current backend lives in `circuits/superneo-backend-lattice/src/lib.rs`. It handles witness commitment, leaf proof generation, and fold proof generation for the experimental native lane. “Hardening” here means replacing approximation shortcuts with cryptographically meaningful constructions and a stable parameter story. A “parameter set” means the exact security-relevant constants that define the backend, such as matrix dimensions, challenge widths, ring profile, decomposition widths, norm bounds, randomness widths, and opening schedules. A “verifier profile” is the 48-byte digest that tells consensus which backend rules are in force for an artifact.

This plan assumes the architecture from the existing SuperNeo experiment remains in place: `NativeTxValidityRelation` is the canonical native relation, `TxLeaf` is the tx-level artifact, `ReceiptRoot` is the block-level native aggregate, and `InlineTx` remains the shipping fallback. The hardening work therefore focuses on `circuits/superneo-backend-lattice`, `circuits/superneo-hegemon`, and the verifier-profile glue in `consensus/src/proof.rs`.

The research behind this direction now needs to be stated carefully.

- `Neo` (`2025/294`) is the clearest accessible anchor for small-field CCS folding with pay-per-bit commitments.
- `LatticeFold+` (`2025/247`) is the clearest accessible anchor for a faster and simpler lattice-based folding line than older lattice folding.
- `SuperNeo` (`2026/242`) is verifiable as an ePrint entry and title, and it clearly stays relevant, but its detailed claims should be treated as provisional here unless the full construction is directly available during implementation.
- `HyperWolf` and adjacent lattice commitment work remain relevant as commitment/opening references rather than direct folding specifications.

This plan therefore does not require implementing any one paper literally line by line. It requires arriving at a working backend whose security and performance claims can be stated with a straight face and whose design choices are anchored in the accessible literature rather than in unverified summaries.

## Plan of Work

Start by making the backend parameter set explicit and versioned. Add a single public parameter object in `circuits/superneo-backend-lattice` that records all security-relevant values, and derive the verifier profile digest from that object rather than from ad hoc code state. This parameter object should be serializable, printable in benchmark outputs, and stable enough that two nodes can agree whether they are verifying the same backend.

With parameters explicit, harden the commitment layer. Replace the current deterministic projection-style commitment logic with commitments that include explicit randomness, documented norm or range bounds, and verifiable openings. The implementation should expose a proof object that can be independently malformed in tests and rejected by the verifier. If the current manual wire format for native `TxLeaf` needs to change to accommodate proper randomness and openings, change it deliberately and version it.

Next, harden fold proofs. Today’s fold path must evolve from a digest-consistency object into a real algebraic fold proof under the parameter set above. The implementation target here should be expressed in the accessible language of `Neo` / `LatticeFold+`: small-field folding over an explicit parameter set with proper binding between parent and child commitments. Whether the final implementation resembles one explicit sum-check instance or another exact fold relation, the important requirement is that parent commitments and child commitments are bound through verifiable algebra, not just through re-derived digests.

Then, strengthen the verifier-profile and artifact-boundary integration. `experimental_native_tx_leaf_verifier_profile()` and `experimental_native_receipt_root_verifier_profile()` must derive from the parameter set and the exact relation shape, not from ambient code assumptions. Add negative tests that deliberately mix artifacts and profiles across parameter sets and show that verification fails.

Finally, benchmark and decide. Re-run the native lane at the same `k` values now used for planning. If the hardened backend keeps bytes and verifier cost in the same ballpark while materially improving the security story, it remains the primary PQ candidate. If the hardened backend explodes constants, record that clearly and reevaluate the backend choice rather than hiding the regression.

## Concrete Steps

From the repo root `/Users/pldd/Projects/Reflexivity/Hegemon`, implement this plan in the following order.

1. Introduce the parameter object and versioned verifier-profile derivation in `circuits/superneo-backend-lattice` and `circuits/superneo-hegemon`, then run:

       cargo test -p superneo-backend-lattice -p superneo-hegemon

2. Replace the commitment layer with randomized commitments plus explicit openings and add negative tests for malformed openings.

3. Replace digest-style fold proofs with real algebraic fold proofs and re-run:

       cargo test -p superneo-backend-lattice -p superneo-hegemon -p consensus receipt_root_ -- --nocapture

4. Benchmark the hardened backend:

       cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx

5. Record parameter-set fingerprints, artifact sizes, and benchmark outputs in `METHODS.md` and `DESIGN.md`.

## Validation and Acceptance

Acceptance requires both security-facing and performance-facing evidence.

On the security side, tests must prove that wrong randomness, wrong openings, wrong parameter sets, and wrong verifier profiles are rejected. On the performance side, the hardened backend must remain close enough to the current experimental scaling that the native lane stays strategically attractive. If the hardened backend becomes too heavy to matter for Hegemon’s global vision, that is still a valid outcome, but it must be demonstrated with numbers and recorded plainly.

The minimum acceptance commands are:

    cargo test -p superneo-backend-lattice -p superneo-hegemon
    cargo test -p consensus receipt_root_ -- --nocapture
    cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx

## Idempotence and Recovery

This plan changes the native artifact format and verifier profile, so version everything. Do not overwrite the current experimental profile in place without keeping a compatibility path for local benchmarks and explicit failure messages for mixed artifacts. If a hardening milestone fails, keep the parameter object and rejection tests even if the commitment or fold implementation is rolled back.

## Artifacts and Notes

The benchmark outputs for the hardened backend must include the parameter-set fingerprint. A contributor reading a JSON result months later should be able to tell which backend regime produced it.

Any new artifact format should carry an explicit version field and a verifier-profile digest that can be checked before deep decoding. This is as much an operational hardening requirement as a cryptographic one.

## Interfaces and Dependencies

This plan should introduce explicit backend parameter types. Preferred names are:

    pub struct NativeBackendParams {
        pub security_bits: u32,
        pub ring_profile: RingProfile,
        pub matrix_rows: usize,
        pub matrix_cols: usize,
        pub challenge_bits: u32,
        pub decomposition_bits: u32,
        pub opening_randomness_bits: u32,
        pub version_tag: &'static str,
    }

    pub trait NativeCommitmentScheme {
        type Commitment;
        type OpeningProof;

        fn commit(
            &self,
            params: &NativeBackendParams,
            witness: &PackedWitness<Goldilocks>,
        ) -> Result<(Self::Commitment, CommitmentOpening), anyhow::Error>;

        fn verify_opening(
            &self,
            params: &NativeBackendParams,
            commitment: &Self::Commitment,
            opening: &Self::OpeningProof,
        ) -> Result<(), anyhow::Error>;
    }

The verifier-profile derivation should be exposed as a stable function that takes the explicit parameter object as input rather than reading global defaults.

Revision note: this ExecPlan was created on 2026-03-26 to turn the current native folding branch from a topology proof into a hardening program. The branch already has enough architecture to justify this investment; what it lacks is a backend whose security claims and benchmark numbers can be stated honestly together.

Revision note (2026-03-26, research pass): corrected the research framing after re-checking the literature. The plan still stands, but it now treats `Neo` and `LatticeFold+` as the primary accessible anchors, treats `SuperNeo` as a relevant but still partially provisional upgrade line, and narrows the title from “production-grade SuperNeo backend” to “credible production candidate.”
