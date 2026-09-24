# Disqualify or close complete ZK for retained M4

This isolated ExecPlan is complete as a disqualification. It does not change production sources or shared documentation.

## Purpose

Determine whether the retained M4/Boolean/BaseFold proof admits a public-only simulator for its exact serialized proof view. If not, provide a concrete counterexample, executable checks, exact E384/E512 byte arithmetic, and a theorem-valid replacement boundary.

## Progress

- [x] Read repository instructions, architecture/method documents, living ExecPlan, M4/BaseFold/SmallWood sources, and prior hardening artifacts.
- [x] Trace the committed/opened codeword topology through pinned Binius revision `3f961630`.
- [x] Reuse and audit `complete_zk.rs` rather than duplicating its 17-class view inventory.
- [x] Construct an exact same-public Boolean counterexample with conditional TV distance one.
- [x] Implement dependency-free GF(2^3)/GF(2^4), rank, affine-distribution, view, SHA-512-frame mutation, byte, and rational-QROM checks.
- [x] Quantify E384 and E512 one-level and retained maximum-shape projections.
- [x] Audit CFW26/Plonky3 Hiding-WHIR as a replacement and pin the characteristic/two-adicity/R1CS theorem boundary.
- [x] Keep every authority flag false and seal a canonical certificate.

## Decision log

- A raw opened message-codeword projection is a complete-ZK impossibility; no additional independently opened mask lane can repair it.
- E384 is conditionally sufficient at q=318 for the stated ideal CMS envelope. E512 is not structurally required and does not repair topology.
- Hiding-WHIR is the minimal known *security pattern*, but not a minimal source change. Its full stack and relation must replace the current opening/folding/base-case pipeline.
- CFW26's ready-made full-ZK R1CS clause requires characteristic not equal to two. Therefore the next theorem-valid route is an odd-field Boolean/R1CS compiler or a new characteristic-two theorem.

## Validation

The standard-library suite has 15 passing tests. Source-contract checks pass against the repository and pinned Binius checkout. No build, proof, or dependency command was run.

