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
- finite compressed-oracle quantum semantics, state restoration, adaptive database claims, and the
  complete CMS/QROM extraction theorem;
- the Goldilocks rejection-sampling proof, additive and zero-sum masking couplings, and explicit
  proof-shape and network-unlinkability boundaries;
- accepted-byte parser and verifier refinement for the current production artifact;
- the accepted proof-bytes to exact transaction relation to accepted-block supply chain; and
- compressed-relation lemmas for dense range rows and Poseidon2 S-box wire substitution.

The production prover now rejection-samples 64-bit words until they are canonical Goldilocks
elements. `SmallWoodZeroKnowledge.lean` proves why the previous one-subtraction map was biased and
why the accepted machine-word domain has exactly one representative per field element.

`SmallWoodProofWire.lean`, `TransactionProofWire.lean`, and
`SmallWoodNativeRefinement.lean` model exact consumption, canonical field encodings, wrapper
versions, backend selection, and active-artifact parsing. The generated vectors in
`testdata/formal_crypto_vectors/smallwood_proof_wire.json` are checked against the Rust parser.

`SmallWoodCompressedRelation.lean` preserves only the reusable mathematics from the compression
work. It proves equivalence of the old and dense range encodings and proves that constrained
external and internal S-box input wires preserve the corresponding Poseidon2 rounds. The active
runtime relation is `DirectPacked64CompressedLevel5`; version dispatch and its exact generated
constraint map are checked separately.

## Security boundary

The active research formalization is no longer an interface-only sketch:

- `SmallWoodProductionAcceptanceClosure.lean` defines the exact parser, transcript,
  reconstruction, authenticated-row, and verifier-equation evidence that one accepted execution
  must discharge, then proves that evidence reaches the fourth-round interactive accepting state;
- `SmallWoodCmsQrom.lean` proves, for every finite quantum adversary computation and adaptive final
  selector in the modeled oracle game, that acceptance without a valid extracted witness is bounded
  by `activeQromFailureBound`; and
- `SmallWoodProductionSupplyChain.lean` composes extraction with the exact Hegemon transaction and
  accepted-block supply relations.

Rust constructs the corresponding active V4/Gamma trace through
`smallwood_production_verifier_evidence_v1`, which reuses the canonical wrapper decoder, generated
runtime-contract check, SHA-512 transcript selection, production soundness-floor check, and
production verifier. The remaining Rust/compiler refinement assumption is the statement that this
compiled execution discharges every field of the Lean evidence record for arbitrary accepted
inputs; finite conformance vectors are not substituted for that universal statement.

No generic BCS/QROM theorem is postulated by these final theorems. The remaining cryptographic
assumptions are explicit:

- the deployed domain-separated SHA-512 counter-mode construction realizes the modeled quantum
  random oracle with the charged instantiation loss;
- SHA-512 and Poseidon2 provide the required collision/preimage resistance in their exact deployed
  domains; and
- the checked parser/verifier/refinement surfaces correspond to the compiled Rust execution,
  compiler, CPU, and operating environment.

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
- regenerates and compares proof-wire vectors; and
- audits representative theorem roots against the kernel axiom allowlist.

The credited declaration list is intentionally a small set of transitive proof roots rather than
an exact theorem-count or source-file-count gate. Adding legitimate modules does not require
pretending that inventory churn is a cryptographic result.
