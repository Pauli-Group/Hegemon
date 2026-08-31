# Hegemon formal cryptography research

This Lake package isolates proof-system research from Hegemon's production semantics under
`formal/lean`. The dependency direction is deliberate: `formal/crypto` may import `formal/lean`,
but production Lean and Rust code must never import `formal/crypto`.

The package contains:

- canonical customizable constraint system (CCS) definitions, an executable checker, adversarial
  examples, and a statement-specific quadratic compiler;
- an exact adapter to the bounded production SmallWood relation;
- canonical grammars for the inner SmallWood proof, candidate wrapper, transaction wrapper, and
  ordered transcript inputs, with generated Rust conformance vectors;
- exact SHA-512 counter-mode field expansion, canonical rejection sampling, transcript
  reconstruction, and query accounting for the active V4/Gamma profile;
- production PIOP, DECS, LVCS, compact-Merkle, accumulated-oracle, and round-by-round extraction;
- finite compressed-oracle quantum semantics, state restoration, adaptive database claims, and an
  ideal logical-oracle CMS/QROM extraction theorem;
- a type-indexed security-claim authority API with no deployed end-to-end constructor;
- the Goldilocks rejection-sampling proof, additive and zero-sum masking couplings, and explicit
  proof-shape and network-unlinkability boundaries;
- accepted-byte parser models plus a caller-supplied modeled-verifier evidence record;
- a supply-chain theorem conditional on caller-supplied extraction success, canonical semantic
  refinement, and Poseidon2 output-security assumptions; and
- compressed-relation lemmas for dense range rows and Poseidon2 S-box wire substitution.

The production prover now rejection-samples 64-bit words until they are canonical Goldilocks
elements. `SmallWoodZeroKnowledge.lean` proves why the previous one-subtraction map was biased and
why the accepted machine-word domain has exactly one representative per field element.

`SmallWoodProofWire.lean`, `SmallWoodSmz8ProofWire.lean`, `SmallWoodSmz9ProofWire.lean`,
`TransactionProofWire.lean`, and
`SmallWoodNativeRefinement.lean` model exact consumption, canonical field encodings, wrapper
versions, backend selection, and active-artifact parsing. The dedicated SMZ8 model additionally
fixes 19 compact authentication paths, permits aggregate-multiproof zero-length paths, consumes
exactly 19 independent 64-byte leaf tapes, bounds every path at depth 23, and enforces the
131,072-byte inner-proof cap before parsing collections. Verifier acceptance separately enforces
the canonical compact-path ceiling of 355 serialized nodes, so the authentication section is at
most 22,741 bytes and authentication plus tapes is at most 23,957 bytes. The generated vectors in
`testdata/formal_crypto_vectors/smallwood_proof_wire.json` and
`testdata/formal_crypto_vectors/smallwood_smz8_proof_wire.json` are checked against the Rust parser.
The fresh, additive SMZ9 codec instead fixes 20 paths and 20 tapes, mode-1 opened rows with zero
auxiliary counts, depth 23, the 372-node aggregate ceiling, and the same pre-allocation cap. Its
separate generated vector is `testdata/formal_crypto_vectors/smallwood_smz9_proof_wire.json`;
SMZ8 remains historical and is not reinterpreted.

`SmallWoodZeroKnowledge.lean` also exposes the exact conditional theorem boundary for the SMZ8
whole-view simulator. It requires a nonempty compiled relation identity refining the 120-word
semantic target and seven binding limbs, universal canonical SMZ8 and Rust/Lean verifier replay,
and separate SHA-512 transcript, adaptive-QROM, whole-view hybrid, target-loss, and independent
review receipts. It does not derive those receipts from the classical-ROM calculation, and the
source-owned release gate requires an `adaptive_qrom_whole_view_zk_receipt` before authorization.

`SmallWoodV8QromAccounting.lean` separately instantiates the exact V8 ideal arithmetic at
`R=686`, `C=368`, `N=2^23`, and `q=19`. It proves a 273-bit interactive aggregate and a 141-bit
ideal-CMS envelope at `Q=2^64`, but also proves that its deployment premise record is unavailable
while the full relation, transcript, concrete SHA-512/Poseidon2, complete-ZK, history, approved
global-query-budget, and review receipts remain absent. This remains the historical SMZ8/open-5
ledger. `SmallWoodV8Smz9QromAccounting.lean` adds the fresh profile-6/open-6/q-20 identity without
relabeling SMZ8: it proves 288 interactive bits, 157 ideal-CMS bits at `Q=2^64`, and 136 bits after
the exact `522 * 4096` canonical-`PendingAction` history union, all before external deployment
losses. It retains `523 * 4096` only as a stricter conservative overcount. Its deployed
premise record is independently unavailable for the same explicit receipt reasons. That first
ledger preserves the historical distinct/outside-only opening model.
`SmallWoodV8Smz9AdaptiveFiniteAccounting.lean` separately matches the executable sampler's
additional nonzero degree-six linear-correction predicate with the conservative denominator
`(p-64)_6 - 414*p^5` and nonce-abort term `813^16/p^16`. It retains the 288/157/136 integer floors,
proves the exact 2,138,112-proof outcomes for four 152-bit and four 151-bit external terms, checks
the prior 2,142,208-proof overcount separately, and proves the exact maximum 128-bit interaction
counts. Its concrete sampler, SHA-512,
Poseidon2, relation/transcript, whole-view, lifetime-budget, and review bridge premises have no
constructors.

`SmallWoodV8Smz9ZeroKnowledge.lean` isolates the fresh profile's algebraic hiding from its QROM
boundary. It proves exact random-coin transport couplings for the six-opening PIOP view, the
zero-sum 64-lane linear mask, the 12-by-20 LVCS tail view, the five DECS coefficient vectors split
into 20 evaluations plus 368 high coefficients, and the empty auxiliary-witness view. A separate
receipt must still show that the executable Rust prover uses those exact invertible maps. The
SMZ9 whole-view theorem remains conditional on that refinement, exact relation and parser replay,
adaptive SHA-512 programming/composition, a target loss bound, and independent review.

`SmallWoodCompressedRelation.lean` preserves only the reusable mathematics from the compression
work. It proves equivalence of the old and dense range encodings and proves that constrained
external and internal S-box input wires preserve the corresponding Poseidon2 rounds. The active
runtime relation is `DirectPacked64CompressedLevel5`; version dispatch and its exact generated
constraint map are checked separately.

## Security boundary

The active research formalization proves substantial internal mathematics, with its authority scope
encoded in the exported record and theorem names:

- `SmallWoodProductionAcceptanceClosure.lean` defines
  `CallerSuppliedVerifierEvidence`, containing exact parser, transcript, reconstruction,
  authenticated-row, and verifier-equation facts, then proves that this caller-supplied evidence
  reaches the fourth-round interactive accepting state;
- `SmallWoodCmsQrom.lean` proves, for every finite quantum adversary computation and adaptive final
  selector in the ideal logical-oracle game, that acceptance without a valid extracted witness is
  bounded by `idealLogicalQromFailureBound`; and
- `SmallWoodV8QromAccounting.lean` checks the exact V8 interactive and conditional ideal-CMS
  integer inequalities for historical SMZ8 without constructing any deployed premise;
- `SmallWoodV8Smz9QromAccounting.lean` checks the fresh SMZ9/profile-6 interactive, ideal-CMS, and
  explicit proof-history-union inequalities without constructing any deployed premise; and
- `SmallWoodV8Smz9AdaptiveFiniteAccounting.lean` checks the executable sampler's conservative
  correction-aware finite-proof ledger and leaves every concrete adaptive bridge premise
  constructor-free; and
- `SmallWoodV8Smz9ZeroKnowledge.lean` proves the fresh profile's exact algebraic couplings and the
  whole-view conclusion only from explicit executable-map, transcript, adaptive-QROM, and review
  receipts; and
- `SmallWoodZeroKnowledge.lean` proves the exact SMZ8 whole-view indistinguishability conclusion
  only given an adaptive-QROM release receipt that includes executable refinement and every
  explicit loss term; and
- `SmallWoodProductionSupplyChain.lean` proves the accepted-block supply relation only conditional
  on a caller-supplied negation of `NoValidExtraction` and canonical semantic refinement for every
  transaction, plus separately supplied Poseidon2 output-security assumptions.

The three credited boundary theorems additionally return
`SecurityAuthority.ScopedSecurityClaim`. Its constructors cover only `idealLogicalQrom`,
`callerSuppliedVerifier`, and `conditionalSupply`. The `deployedEndToEnd` scope intentionally has no
constructor, so production authority cannot be obtained by retagging one of these results without a
review-visible API change.

Rust exposes a candidate active V4/Gamma trace through
`smallwood_production_verifier_evidence_v1`, which reuses the canonical wrapper decoder, generated
runtime-contract check, SHA-512 transcript selection, production soundness-floor check, and
production verifier. There is no Lean constructor theorem from that Rust result to
`CallerSuppliedVerifierEvidence`. The Rust/compiler refinement assumption is the statement that an
arbitrary successful compiled execution discharges every field of the Lean evidence record; finite
conformance vectors are not substituted for that universal statement.

No generic BCS/QROM theorem is postulated by these final theorems. The remaining cryptographic
assumptions are explicit:

- the deployed domain-separated SHA-512 counter-mode construction realizes the modeled quantum
  random oracle with a caller-supplied instantiation loss;
- SHA-512 and Poseidon2 provide the required collision/preimage resistance in their exact deployed
  domains; and
- the checked parser/verifier/refinement surfaces correspond to the compiled Rust execution,
  compiler, CPU, and operating environment.

`SmallWoodBcsQrom.lean` reflects those boundaries in
`conditionalDeploymentSecurityLedger`: only the three ideal-model CMS terms have status
`provedIdealModel`. Commitment binding and SHA-512/QROM instantiation are caller-supplied
cryptographic assumptions; transcript compatibility and native-verifier refinement are
unquantified implementation assumptions with no numeric loss. The ledger therefore has no numeric
total, and a theorem checks that `quantifiedLedgerTotal` returns `none`. The ideal 128-bit envelope
explicitly excludes all deployment losses and boundaries. No theorem uses this ledger to transfer
the ideal logical-QROM probability bound to deployed SHA-512.

Consequently, this package exports and credits no theorem labeled as deployed end-to-end SmallWood
soundness. Its final credited roots explicitly say `caller_supplied`, `ideal_logical_qrom`, or
`given_caller_extraction_semantic_refinement_and_output_security`.

The package does not prove primitive cryptanalysis, implementation correctness for arbitrary Rust
or machine code, proof zero knowledge in the QROM, global network unlinkability, storage
durability, or data availability. A passing kernel build is strong internal evidence, not an
independent cryptographic review or authorization to overstate those assumptions.

## Validation

Run the complete package gate from the repository root:

```bash
bash scripts/check_formal_crypto.sh
```

The gate:

- rejects imports from production authority surfaces;
- rejects source symlinks and Lean trust bypasses;
- pins the Lean toolchain and dependency revisions;
- builds the complete package;
- regenerates and compares proof-wire vectors (not the full caller-supplied verifier evidence
  record); and
- audits representative, explicitly scoped theorem roots against the kernel axiom allowlist.

The credited declaration list is intentionally a small set of transitive proof roots rather than
an exact theorem-count or source-file-count gate. Adding legitimate modules does not require
pretending that inventory churn is a cryptographic result.
