# Audit and repair the joint M4 zero-knowledge mask rank

This ExecPlan is a living document maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

The coefficient-aware trace shift fixes the scalar equation `M = s + k*c`, but production cannot call the resulting proof zero knowledge until every witness-dependent transcript value is jointly simulatable. This isolated audit inventories the pinned wrapper by protocol phase, checks exact linear mask-span conditions over the pinned GHASH field, produces adversarial controls, and emits a fail-closed certificate. It also evaluates a narrow repair for the outer Spartan precommit claim: one fresh unused blinder for each independent clear precommit functional.

## Progress

- [x] (2026-08-21) Read the pinned wrapper, M4, BaseFold, Libra, and outer Spartan source paths.
- [x] (2026-08-21) Identified the clear outer precommit claim as a joint-correlation leak when it contains only OTP keys already used by inner transcript messages.
- [x] (2026-08-21) Implemented the executable GHASH-field rank model, inventory checks, grouped repair, rank-one control, and adversarial negative controls.
- [x] (2026-08-21) Emitted and validated the fail-closed certificate and schema.
- [x] (2026-08-21) Ran 15 source-only Python tests; all passed without Cargo, proof generation, or material disk use.

## Surprises & Discoveries

- Observation: BaseFold hiding of the precommit oracle does not by itself hide `precommit_claim = <K,T_K>`, because outer Spartan sends that scalar in the clear before the combined opening.
  Evidence: `crates/spartan-prover/src/lib.rs` computes the claim at lines 299--306 and calls `channel.send_one(precommit_claim)` at line 307 in the pinned checkout.
- Observation: One clear functional of fresh OTP keys becomes a witness functional when the OTP ciphertext stream is observed.
  Evidence: from `E=m+K` and `P=a*K`, the verifier obtains `a*E+P=a*m` in characteristic two.
- Observation: Existing BaseFold combines oracles only after Phase A has already required one component claim per oracle.
  Evidence: the pinned prover/verifier queues relations by oracle, constructs one padded sumcheck prover per oracle, and only the later FRI MLE-check forms the piecewise combined oracle.

## Decision Log

- Decision: Separate unconditional algebraic closure from computational PCS and outer-Spartan assumptions.
  Rationale: A rank calculation can prove that fresh masks cover clear linear messages, but it cannot manufacture a BaseFold, Merkle, FRI, Fiat--Shamir, QROM, or nonlinear Spartan simulator theorem.
  Date/Author: 2026-08-21 / Codex.
- Decision: Treat the 83-Keccak relation as source-bound but not compile-bound.
  Rationale: disk availability remains below the 28 GiB admission gate, so no Cargo build or prover run is permitted.
  Date/Author: 2026-08-21 / Codex.
- Decision: Select the grouped precommit+private relation over the unused-blinder control.
  Rationale: grouping removes the component leak and one 16-byte scalar with no new abort gate; `h` closes only rank one, retains the component message, and requires a new constrained coordinate with guaranteed nonzero coefficient.
  Date/Author: 2026-08-21 / Codex.

## Outcomes & Retrospective

The source-bound audit is executable and its 15 tests pass. It rejects the current patch with an exact rank counterexample, proves the clear-layer grouped repair for every nonzero `c`, and verifies the rank-one/rank-two controls. CompleteZK remains false: the BaseFold group is not implemented, exact compiled multiplicities are absent, and BaseFold/Libra/FRI/Merkle/nonlinear/QROM simulators remain open.

## Context and Orientation

The frozen coefficient patch is `prototypes/standalone-shake256-binius/m4-zk-coefficient-mask-patch/hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch`, based on upstream revision `3f96163049f680b2909f6545690bd929f1b48c44`. The prospective maximum relation is `prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs` and fixes 83 inline Keccak-f calls in one main circuit. The wrapper commits an early random precommit vector `K`; its first scalar shifts the private trace, and later scalars encrypt inner prover messages. Outer Spartan later proves the replay circuit and the single BaseFold channel opens all inner and outer oracles together.

For a transcript written as `view = W*witness + R*randomness`, perfect witness-independence of this linearized view holds exactly when every column of `W` lies in the column span of `R`. The executable audit checks the equivalent rank identity `rank(R) = rank([R | W])` over the exact GHASH field `GF(2^128)`.

## Plan of Work

Add a dependency-free Python program that implements GHASH arithmetic, Gaussian rank, constructive mask witnesses, a protocol-class inventory, source fingerprints, negative controls, and certificate generation. Model the ideal trace/OTP layer for every nonzero trace coefficient `c`, then add the actual clear precommit claim and show its counterexample. Add a proposed unused blinder `h` with a nonzero coefficient `d`; verify that it closes exactly one clear functional, that `d=0` fails, and that two independent clear claims require blinder rank two. Keep BaseFold mask inner products, Libra messages, outer endpoint evaluations, FRI commitments, and Merkle openings in the inventory and list their simulator theorems as open rather than treating the linear model as a proof of them.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, run:

    python3 -m unittest discover -s prototypes/standalone-shake256-binius/m4-zk-joint-simulator-audit -p 'test_*.py'
    python3 prototypes/standalone-shake256-binius/m4-zk-joint-simulator-audit/joint_simulator_rank_audit.py

The test suite must pass. The audit command must exit successfully because it successfully detects the rejection, print `complete_zk=false`, identify the clear precommit correlation blocker, and report that the one-blinder repair closes only the isolated clear-linear layer.

## Validation and Acceptance

Acceptance requires exact GF(2^128) arithmetic self-tests; constructive closure for many deterministic accepted challenge vectors; rank-pass for arbitrary nonzero `c` and repair coefficient `d`; rank-fail for `c=0`, `d=0`, reused OTP keys, missing BaseFold vector masks, and insufficient blinder rank; pinned source hashes and required source anchors when the pinned checkout is present; and schema validation of a certificate that cannot promote CompleteZK.

## Idempotence and Recovery

The audit is read-only except when explicitly asked to print a certificate. It creates no Cargo target, proof, cache, or large artifact. Re-running it is safe. If the maximum-relation source hash changes, the source-binding check must fail until the audit configuration and certificate are deliberately regenerated after review.

## Artifacts and Notes

The primary algebraic blocker is:

    E = m + K
    P = a*K
    a*E + P = a*m

The proposed rank-one repair is:

    P' = a*K + d*h,  d != 0

where `h` is fresh, unused by every other message, and committed before challenges. This only solves the isolated clear functional. It does not establish the BaseFold or outer Spartan simulators.

## Interfaces and Dependencies

`joint_simulator_rank_audit.py` uses only the Python standard library. It exposes `gf_mul`, `gf_inv`, `rank`, `columns_contained`, scenario builders, `run_audit`, and `validate_certificate`. `certificate.schema.json` defines the persisted evidence surface. No network, Cargo, or third-party package is permitted.

Revision note (2026-08-21): Initial source and audit plan created after locating the clear outer-precommit correlation leak.

Revision note (2026-08-21): Completed the executable audit, selected the grouped relation, froze the fail-closed certificate, and recorded 15 passing source-only tests.
