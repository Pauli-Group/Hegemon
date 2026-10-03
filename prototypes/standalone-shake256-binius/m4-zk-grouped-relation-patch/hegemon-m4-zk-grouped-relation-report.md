# Grouped outer-relation source audit

Status: `SOURCE_STATIC_PASS`, `COMPILED=false`, `ROUNDTRIP=false`, `COMPLETE_ZK=false`, `STRICT_SECURITY=false`, `PROOF_BYTES=null`, `FRONTIER_ELIGIBLE=false`.

## Exact construction

Outer Spartan formerly computed and sent `p=<K,T_precommit>`, then proved `p` and `<V,T_private>=total-p` as two oracle relations. The patch deletes that component scalar and queues one relation:

```text
total = batched_sum - public_eval
<K,T_precommit> + <V,T_private> = total
```

The grouped interfaces accept only oracle/transparent pairs and `total`; there is no place to supply a component claim. Unsupported channels fail closed.

For hiding messages `K,V` with independent masks `omega_K,omega_V`, the prover sends one relation sigma

```text
sigma = <omega_K,T_precommit> + <omega_V,T_private>
```

then samples the existing shared gamma and proves the masked aggregate

```text
<(1-gamma)K+gamma*omega_K,T_precommit>
+ <(1-gamma)V+gamma*omega_V,T_private>
= (1-gamma)total + gamma*sigma.
```

Each term is represented by its own bivariate product prover at its native `log_msg_len`. `PaddedSumcheckDecorator` raises it to the maximum relation size with `eq(0,padding)`; `GroupedSumcheckProver` adds round polynomials coefficient-wise and folds every term on the same challenges. Term claims are computed only inside the prover to initialize those provers and are never sent. The finish values are mapped back to exactly one alpha per oracle with duplicate and missing checks. Verifier reduction independently adds `alpha_i*T_i(r_i)*eq(0,padding_i)`.

Phase B still receives the same ordered alpha vector and performs the same combined FRI/Merkle opening. Its post-coefficient source slices are byte-identical:

- prover SHA-256 `5574d4f4077f5ce57900834bbebd861f6e1a5c4f81dc9864d83909a78871b5fe`
- verifier SHA-256 `8c44d38b32a51db49505d3a3e3973aea9aa327374adf4a750ea617adeefeaab0`

## Wrapper symmetry

The first implementation failed static integration because the real wrapper channels inherited the unsupported grouped default. The frozen patch closes all four paths:

1. `ZKWrappedProverChannel` sends and records one aggregate native claim, then forwards one grouped relation.
2. `IronSpartanBuilderChannel` allocates one inout bridge and constrains the circuit-computed aggregate to it.
3. `ReplayChannel` consumes one matching event and applies the same constraint.
4. `ZKWrappedVerifierChannel` reads one native aggregate, binds it to the wrapper circuit, converts both public transparent closures, and forwards one grouped relation.

No path allocates or records an individual term claim. Grouped use of the special coefficient-aware evaluation-masked trace oracle is rejected; that oracle retains its separate nonzero-coefficient relation.

## Fail-closed scope

The real BaseFold queues require at least two distinct oracle handles, all commitments/receipts completed before grouping, every grouped oracle configured with hiding, no ordinary relation on a grouped oracle, and no oracle in multiple groups. Ordinary-after-group and group-after-ordinary orderings both reject. Duplicate or missing Phase-A alphas reject. Default channel methods reject rather than decomposing. The naive diagnostic and setup channels implement the aggregate interface without introducing component claims; the cryptographic checks remain in the real BaseFold channel.

## Ordered patch identity

1. Base revision: `3f96163049f680b2909f6545690bd929f1b48c44`.
2. Apply coefficient patch SHA-256 `684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54`.
3. Apply grouped delta SHA-256 `37dfdee589e476c09fe5c955bd46942cd5aa293a3177d7a43d07f14aeb8ef9df`, 49,656 bytes, 15 files, 854 insertions and 100 deletions.

A clean disposable checkout passed `git apply --check` for both patches in that order, applied both, passed `git diff --check`, and passed `rustfmt --edition 2024 --check` over all 15 grouped files. Stable rustfmt printed only the repository's existing warnings for nightly-only formatting options.

The dependency-free checker returned:

```json
{"aggregate_bridge_scalars":1,"cargo_admitted":false,"compiled":false,"complete_zk":false,"frontier_eligible":false,"phase_b_unchanged":true,"profile_scope":"field_generic_API_B128_weak_profile_evidence_only","proof_bytes":null,"roundtrip":false,"source_files_pinned":15,"status":"SOURCE_STATIC_PASS","strict_security":false}
```

The checker also executes independent finite-field KATs for aggregate sigma/shared gamma and unequal-size zero padding. These establish only the stated algebra identities, not Rust execution or cryptographic security.

## Added but unexecuted source tests

- grouped sumcheck roundtrip with native sizes 4 and 7;
- wrong aggregate claim fail-closed case;
- full BaseFold grouped roundtrip with oracle sizes 5 and 8;
- aggregate-claim mutation rejection;
- naive grouped prover/verifier symmetry.

The existing wrapper integration test now exercises builder, replay, wrapped prover, concrete verifier, and raw BaseFold grouped forwarding once compiled. It was not run.

## Claim boundary and strict field scope

This patch is an implementation-level B128 weak/profile repair for one direct linear leak. It does not prove that A/B/C mulcheck messages, Libra endpoints, BaseFold commitments/openings, Merkle paths, nonlinear correlations, or the whole Fiat--Shamir transcript are simulatable. A complete joint simulator and composition proof remain mandatory.

The API is generic, but pinned BaseFold is binary-field constrained and this archive uses B128 masks. A strict extension-field backend must independently cover every hidden value in the actual challenge/claim domain: for an E384 design that means three independent B128 coefficient symbols per uniform mask; a true quadratic extension or repeated construction has its own independent-coverage and composition obligations. This B128 patch cannot be promoted into either route by relabeling it.

No Cargo command, compilation, verifier, prover, proof artifact, or byte measurement was run. The final disk sample was about 24.6 GiB free, below the 28 GiB admission gate. The apparent removal of source events is not a measured byte result because the prerequisite coefficient patch can change padded oracle/FRI geometry.
