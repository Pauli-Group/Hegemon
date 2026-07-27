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
- field-generic honest-prover algebra and completeness from an explicit production-oracle
  refinement contract;
- typed extraction interfaces, named failure events, and finite union-bound arithmetic;
- classical random-oracle and finite standard quantum-random-oracle semantics;
- an applicability audit for the deployed Fiat-Shamir transcript;
- partial adaptive BCS/QROM extraction interfaces and exact conditional loss arithmetic;
- the Goldilocks rejection-sampling proof, additive and zero-sum masking couplings, and explicit
  proof-shape and network-unlinkability boundaries;
- accepted-byte parser refinement for the current production artifact; and
- compressed-relation lemmas for dense range rows and Poseidon2 S-box wire substitution.

The production prover now rejection-samples 64-bit words until they are canonical Goldilocks
elements. `SmallWoodZeroKnowledge.lean` proves why the previous one-subtraction map was biased and
why the accepted machine-word domain has exactly one representative per field element.

`SmallWoodProofWire.lean`, `TransactionProofWire.lean`, and
`SmallWoodNativeRefinement.lean` model exact consumption, canonical field encodings, wrapper
versions, backend selection, and active-artifact parsing. The generated vectors in
`testdata/formal_crypto_vectors/smallwood_proof_wire.json` are checked against the Rust parser.

`SmallWoodCompressedRelation.lean` preserves only the reusable mathematics from the compression
experiment. It proves equivalence of the old and dense range encodings and proves that constrained
external and internal S-box input wires preserve the corresponding Poseidon2 rounds. It does not
activate a compressed runtime relation or claim a secure parameter set.

## Security boundary

This package does **not** prove end-to-end SmallWood knowledge soundness and does not authorize a
production security claim.

The extraction and BCS/QROM modules expose conditional interfaces and no-go results. In
particular, they do not prove that every accepted native Rust execution supplies all hypotheses of
a round-by-round extractor, do not instantiate a reviewed adaptive online BCS theorem with concrete
losses, and do not prove the cryptographic security of Poseidon2 or the commitment scheme.

The exact integer calculations prove only the stated arithmetic consequences of their supplied
failure terms. They do not establish that an unproved term applies to the implementation.

Remaining boundaries include:

- a complete production-verifier-to-interactive-transcript refinement;
- a production round-by-round extractor;
- commitment binding and multi-opening extraction;
- an adaptive online BCS/QROM theorem with explicit constants;
- primitive hash and commitment security;
- complete native implementation refinement;
- proof zero knowledge in the QROM; and
- global network unlinkability.

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
