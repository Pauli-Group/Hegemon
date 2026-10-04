# RP05: public ZK, single-spend history and independent-review resolutions

## Summary

Update the RP05 SmallWood Poseidon2 V8 independent transaction-proof path and
publish its checked formal source package for review. The self-contained proof
continues unchanged through wallet/RPC, relay, mempool, mining, blocks, sync,
restart, reorg and fresh-node verification. No proof-format or size increase,
alternate backend, or authorization bypass is introduced.

The public package distinguishes its claims:

- `Rp05.zero_knowledge` compares initialized adaptive real execution with a
  witness-independent public simulator. Loss is `12*T^2/2^279`, at most
  `(27/64)*2^-143` for `T <= 3*2^64`. The earlier two-witness theorem remains
  available separately as `privacy_two_witness`.
- The new single-spend endpoint bounds failure of a literal generated-history
  credential/opening/unspent predicate for **positive native spends**, on the
  original Born measure, below `2^-130` plus six explicit induced primitive-game
  advantages. Extraction loss is charged once. A supplementary all-active
  theorem classifies occupied historical openings, legitimate known-empty
  openings, or path collisions, including all seven owner coordinates when
  occupied.
- Accepted-invalid-proof soundness and initialized native-history conservation
  retain their existing checked reductions and explicit cryptographic premises.

## Evidence and reproduction

The affected Lean dependencies, public wrappers and proof bodies are checked;
the source package has 1,471 modules, 108 external imports and four public roots.
Only `propext`, `Classical.choice` and `Quot.sound` are admitted by the endpoint
body audit. The public [evidence summary](https://github.com/Pauli-Group/Hegemon/blob/codex/smallwood-pq128-experiment/docs/crypto/rp05_review_evidence.json)
records final source and receipt digests and separates retained local evidence
from clean-checkout reproduction.

Both retained independently generated proofs are **163,665 bytes**, below the
unchanged 164,113-byte ceiling. In-process and real HTTP/PQ socket lifecycle
checks passed in 23.793s and 69.438s respectively. These are retained
development-only passes, not newly repeated runs or deployment evidence. The
verified test-only source delta preserves every runtime byte, proof and relation
pin; immutable historical receipts have not been rewritten as fresh passes.
The eight focused implementation-boundary Rust tests pass on the final source.

See [review reproduction](https://github.com/Pauli-Group/Hegemon/blob/codex/smallwood-pq128-experiment/docs/crypto/RP05_REVIEW_REPRODUCTION.md)
for source hash/closure checks, a reproducible Lean build and the exact Rust
test filters. Raw local compiler objects, host-path receipts and the private
review transcript are excluded; their retained digests are evidence identifiers,
not independent authentication. A fresh checkout must reproduce its own checks
and does not inherit release authority from the summary.

## Independent review and precise trust boundary

The independent Daybreak review found no false theorem, project-specific axiom,
circular endpoint premise or arithmetic counterexample in its four inspected
model endpoints. Its actionable findings and the implemented resolutions are
recorded in [the disposition](https://github.com/Pauli-Group/Hegemon/blob/codex/smallwood-pq128-experiment/docs/crypto/RP05_INDEPENDENT_REVIEW_RESOLUTIONS.md).
The new exports are subsequent resolutions, not a second independent Daybreak
review of this final patch.

The [implementation-boundary review](https://github.com/Pauli-Group/Hegemon/blob/codex/smallwood-pq128-experiment/docs/crypto/RP05_IMPLEMENTATION_BOUNDARY.md)
traces the Rust carrier, decoder, context and local-audit path. Rust-to-Lean
semantic refinement, compiler/platform execution and BLAKE2b implementation
correctness remain trusted. BLAKE2b-384's exact framed ciphertext digest is
projected into six Goldilocks limbs: binding of that **projected commitment** is
a separate assumption, not an automatic consequence of raw-digest collision
resistance. The ideal SHA-512 QROM and six explicit Poseidon2 induced-game
advantages remain theorem premises.

The authorization result does **not** establish an unrestricted all-asset or
zero-value chronological unspent theorem, human ownership, or a complete
threshold approval-registry history. Known-empty inputs are deliberately kept
separate from occupied notes. No universal Rust/compiler/OS proof is claimed.

## Review handoff

This publication is PR review, not network deployment. Activation identity,
release-reviewer trust-root provisioning and production selection are deferred.
`production_authorized = false`; the production capability remains fail-closed.
No fresh CI success, merge approval or mainnet readiness is inferred from local
proof, source, size or lifecycle checks.
