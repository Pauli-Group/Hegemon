# Theorem and interface map

| Required statement | Exact scope | Evidence | Status |
|---|---|---|---|
| Full-view simulator | All 17 canonical M4 proof-view classes; input is public statement and verifier coins only | `complete_zk.rs:1608-1624` defines only the trait | Missing |
| Raw-opening hiding | Adaptive selected leaves and terminal vector under exact serializer | BaseFold opens every leaf scalar and all terminal scalars | Refuted; TV=1 counterexample |
| Local E384/E512 affine hiding | Every same-public witness image lies in random-mask image | Executable GF(2^3)/GF(2^4) rank and distribution enumeration | Current masks refuted; full coordinate masks close local span only |
| M4 HVZK composition | Simulator for every committed sumcheck, fold, OOD value, terminal value, root, path, retry, and abort | No implementation or reduction | Missing |
| RBR or special soundness | Exact retained M4 relation and transcript order, including chip calls | No theorem attached to production verifier | Missing |
| PCS extraction/proximity | Exact distinct-query additive BaseFold schedule | No theorem map for transformed topology | Missing |
| CFW26 interactive HVZK/RBR | Paper's constrained interleaved-code IOPP | ePrint 2026/391 | Proven in paper scope; not instantiated for M4 |
| CFW26 full-ZK R1CS application | Paper's R1CS clause over characteristic not equal to two | ePrint 2026/391 | Excludes B128 |
| Plonky3 Hiding-WHIR pipeline | `TwoAdicField` multiplicative DFT, parallel carried relation | merged PR #1767 | Implemented upstream; incompatible with retained additive B128 stack without a new bridge |
| BCS/CMS QROM transfer | Exact RBR/special-sound IOP plus exact conventional-hash transcript | CMS19 Theorem 8.6 / Block et al. Corollary 1.6 envelope used conditionally | Premises absent for M4 |
| Strict 128-bit accounting | `t=k=2^64`, each of 12 components at most `2^-264` | exact `Fraction` computation | Conditional arithmetic passes at q=318; not a protocol theorem |
| Rust/parser refinement | Accepted bytes iff mathematical verifier accepts under the same transcript | No refinement artifact | Missing |

## Computational assumptions that would remain after construction

Even a completed interactive simulator/extractor would still need these clearly external assumptions:

1. adaptive position binding/collision resistance of the exact SHA-512 Merkle commitment;
2. SHA-512/SHAKE256-512 random-oracle or ideal-QROM programmability under exact domain separation;
3. CSPRNG indistinguishability for prover masks and opening tapes;
4. a BCS/CMS QROM theorem whose RBR/special-soundness and query/arity premises exactly match M4;
5. compiler/refinement correctness from Boolean or R1CS semantics to the accepted Rust proof bytes.

None is discharged by the current executable algebra checks.

