# Hegemon formal cryptography research

This Lake package isolates probabilistic proof-system research from Hegemon's dependency-free
production semantics under `formal/lean`. Its dependency direction is deliberate:
`formal/crypto` may import `formal/lean`; `formal/lean` and the shipped Rust workspace must never
depend on `formal/crypto`.

The package currently provides:

- a canonical finite customizable constraint system (CCS) definition;
- a separately executable CCS checker and a proof that it matches the declarative relation;
- adversarial examples for changed coefficients, omitted and duplicated factors, and changed
  witnesses;
- an exact adapter to the bounded SmallWood production constraint relation;
- a probabilistic knowledge-soundness target using ArkLib's standard verifier definition; and
- an exhaustive open-obligation inventory that prevents this research state from authorizing a
  production cryptographic security claim.

It does **not** prove SmallWood knowledge soundness. Exact production-to-CCS refinement, protocol
completeness, extraction, commitment binding, Fiat-Shamir security in ROM and QROM, primitive hash
security, concrete parameter composition, canonical serialization, Rust verifier refinement, and
prover randomness/secret handling remain open.

The architecture and threat analysis are recorded in
[`docs/FORMAL_CRYPTO_ARCHITECTURE.md`](../../docs/FORMAL_CRYPTO_ARCHITECTURE.md). Run the complete
sanity gate from the repository root with:

```bash
bash scripts/check_formal_crypto.sh
```

The gate pins every Git dependency, rejects local trust bypasses, builds the package, audits the
transitive axioms of all credited declarations, executes the kernel-checked mutation cases, and
checks that no production authority imports this package. A cold build creates a large untracked
`formal/crypto/.lake` tree; it can be removed independently when the research environment is no
longer needed.
