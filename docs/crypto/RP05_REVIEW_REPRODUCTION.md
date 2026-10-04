# RP05 review reproduction

This page gives a clean-checkout workflow for checking the selected RP05 Lean
source package and the focused Rust parser/semantic-boundary tests. It is a
reproduction guide, not release authorization, an independent review, or a
proof that every Rust execution refines the Lean model. The accompanying
[`rp05_review_evidence.json`](rp05_review_evidence.json) records the currently
retained local evidence by hash, separates verified local source checks from
independent or production authorization, and states the precise claim limits.
To reproduce the public checks, use the commands below from a clean checkout.

## Prerequisites

Run commands from the repository root. Use the checked-in Rust and Lean
toolchains and locked dependencies. The Lean package needs its ordinary Lake
dependencies available; a fresh environment may need the repository's normal
dependency/cache setup. Do not change compiler versions or dependency pins to
make a check pass. These focused tests do not generate proofs or require the
retained-artifact feature.

## Lean source package

Run the following in order:

```sh
python3 -B scripts/rp05_proof_package.py check-source
python3 -B scripts/rp05_proof_package.py build
python3 -B scripts/rp05_proof_package.py check
```

`check-source` verifies the staged source hashes, transitive source closure,
and external import boundary. `build` compiles or reuses only objects that
match the package's source, import, compiler, and retained-receipt rules.
`check` is read-only and verifies the resulting package objects and state. A
successful package check does not by itself establish a cold compile on a new
machine or authorize a production capability.

## Focused Rust tests

Run each focused filter separately so Cargo reports the exact test name and
package. These cover the wire profile and historical identity boundary, the
bounded ZK decoder, the ciphertext projection and activity masks, and the
separation of the legacy semantic receipt from the current RP05 source-local
receipt.

```sh
cargo test -p transaction-circuit smza_profile_codec_projection_and_historical_rejection_are_exact
cargo test -p transaction-circuit strict_zk_wire_rejects_arbitrary_opening_counts_before_proving
cargo test -p transaction-circuit inline_ciphertexts_roundtrip_and_bind_all_sixteen_masks
cargo test -p transaction-circuit inline_ciphertext_shape_and_length_mutations_fail_closed
cargo test -p transaction-circuit lean_generated_semantic_adequacy_receipt_matches_rust_status
cargo test -p transaction-circuit current_rp05_source_receipt_remains_separate_and_fail_closed
cargo test -p protocol-shielded-pool smza_framing_rejects_cross_profile_context_and_noncanonical_fields
cargo test -p protocol-shielded-pool smza_framing_roundtrip_maximum_all_activity_masks
```

The evidence summary distinguishes strict compilation, package source
validation, and post-package body auditing. Do not treat an earlier receipt as
validation of a later hash. Strict checks passed for the single-spend
authorization endpoint at source SHA-256
`e017109611231ef273fef3991d98a6207f3da105e2064e5f56aed95b708617c1`, the
all-active classifier at `d5ae87d0326fa4773da18cd2f6c5f20150ef4b27a6112f9929afa8a8aef7f1ab`,
and the public facade at
`ee34a25f77c6189a06a1de98dd57da10497690109bba8f9d1779cb607f247fbd`. The
1,471-module / 108-external-import package build and read-only check passed at
source-manifest SHA-256
`86006c594efa330685f23485081495b2a600856d53b783bb57a995136a10351a`.
The final retained validation passes all four public-facade strict and
body-audit lanes: Soundness (45,282 declarations), zero knowledge (36,399),
Authorization (49,927), and Conservation (49,876). Each body traversal reports
only the standard axioms and no missing bodies or kernel constants; pre/post
object maps were stable. Strict outputs for Soundness, zero knowledge, and
Conservation match their canonical package objects. Authorization reuses its
exact-compatible strict receipt. Its final body audit covers both the
positive-native authorization theorem and the all-active historical credential
classifier. The historical two-witness witness-indistinguishability (WI) audit is
separate and is not used as evidence for the zero-knowledge (ZK) facade.

The final affected-package build and read-only package check passed across the
1,471-module / 108-external-import source closure. The eight focused Rust
implementation-boundary tests passed on the pinned final Rust
semantic-refinement source. The release-status helper's 13 focused Python
tests also passed, including nested-module output-object receipt matching.
Earlier cache-matcher misses are historical diagnostics only and are not
credited as passes or left as open gates after the final source/object maps
and body audits passed.

The public evidence summary carries SHA-256 digests of the final local strict,
body-audit, package, and focused-test receipts, but deliberately omits their
raw paths and contents. These digests identify retained local records; they
are not independent authentication or cold-fresh validation. The summary also
pins the exact public source and proof payload bytes used for this review.

## Claim boundaries

The Lean endpoint is a native-quantum statement under its stated random-oracle
and primitive-game assumptions. It starts from the checked formal relation and
does not establish universal refinement from every serialized native Rust
acceptance into the Lean post-parser model. The
[implementation-boundary map](RP05_IMPLEMENTATION_BOUNDARY.md) records the
concrete parser and finite correspondence tests separately.

Keep two authorization conclusions separate. The quantitative single-spend
failure bound and its unspentness conclusion are for the positive-native spend
consumer. A different source endpoint gives all-active pointwise five-word
credential/seven-word owner facts and historical
occupied/known-empty/path-collision classification; the known-empty exception
remains. That pointwise result proves neither generic nullifier freshness nor
unspentness, and it does not lift the positive-native quantitative bound to
every asset or value. It also does not establish unrestricted all-asset
chronology or construct the complete threshold approval registry/history.
Freshness of a local Approval signer slot is a separate source-local property,
not a generic fresh-nullifier theorem. A pairwise same-note, same-position
replay can use the existing pairwise failure result, but that does not prove
the full threshold-history claim.
The [independent-review dispositions](RP05_INDEPENDENT_REVIEW_RESOLUTIONS.md)
record the formal endpoint and implementation-review boundaries.

The retained four-public-endpoint Std-axiom body audit is not part of the clean
checkout workflow: its local harness and raw receipts are deliberately not
included in the public source package. Its retained result is summarized only
by receipt hashes and is not independently authenticated. Production
activation remains fail-closed unless separate release authority supplies and
validates the required activation identity and evidence.
