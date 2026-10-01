# RP05 independent proof review and disposition

The independent Daybreak Blue review of the frozen October 1 RP05 proof package
found no false theorem, project-specific axiom, circular endpoint premise or
arithmetic counterexample in the four inspected endpoints. It did identify
claim and implementation boundaries. Kernel checking establishes the stated
model theorems; it does not establish that their model captures every native
Rust execution.

This disposition accompanies PR #205. Activation identity, reviewer trust-root
provisioning and network deployment are not part of this review publication.
The review publication keeps `production_authorized = false`.

The Daybreak review precedes the new public ZK and single-spend exports below.
Their later strict/body checks and focused source-composition review are
resolution evidence, not a claim that Daybreak independently re-reviewed the
final patch. PR review remains the external handoff for those changes.

| Finding | Action and exact boundary |
|---|---|
| F1: serialized native acceptance is not formally refined into the Lean post-parser model | The focused implementation review traces the exact carrier/parser/context/preamble/local-audit path and its rejection tests. The concrete Rust implementation, serialization interpretation, compiler and platform remain trusted. No Rust-to-Lean universal refinement theorem is claimed. |
| F2: the public privacy name exported two-witness indistinguishability rather than ZK | A new public `Rp05.zero_knowledge` endpoint composes the existing initialized adaptive real-versus-public-simulator proof. A separate equality proves the compiled public simulator independent of witness fields. The old result remains explicitly available as `privacy_two_witness`. The new endpoint passes strict checking; validation is recorded below. |
| F3: the public authorization result was pairwise nullifier/source consistency | Retain that precise pairwise result and add a literal current-credential/historical-note single-spend success predicate, same-outcome failure inclusion, and initialized mass bound for positive native spends. Add an asset-independent active-input historical classification with an explicit known-empty arm. Its checked roots are recorded below; neither result is unrestricted ownership or complete threshold approval-history reconstruction. |
| F4: the BLAKE2b computation is opaque in Lean | Name the RFC 7693 BLAKE2b-384 implementation/interpretation trust boundary and the separate binding assumption for the exact framed, six-field-limb ciphertext commitment. Finite KAT/parser correspondence is not a universal primitive refinement. |
| F5: the numerical security claims are conditional and endpoint-specific | Preserve exact charged-query bounds and induced primitive-game advantage terms. Do not turn those hypotheses into an unconditional implementation-level 128-bit claim. |

## Public theorem scope

The new ZK theorem uses the current generated RP05 relation certificates, a
normalized initial quantum state fixed before the random-oracle draw, the
actual adaptive real-query budget and the same public strategy. The simulator
program does not depend on the private witness representative. Its rounded
loss is `12*T^2/2^279`; at `T <= 3*2^64` it is at most
`(27/64)*2^-143`. The earlier two-witness bound remains
`24*T^2/2^279`.

The current ownership representation is the repaired five-field-word secret
and full seven-word owner digest, not the older RP03 four-word typed
authorization specification. Single-spend credential binding must use the
same extracted packed rows, selected mode-specific framed credential,
nullifier preimage and recorded historical note. The positive-native-value
history consumer's success/failure split must retain extraction loss and the
actual path/authorization primitive events on the original execution measure.
A complete source-history constructor for the separate threshold approval
registry is not implied by credential binding.

The single-spend failure event is accepted execution plus source-chain public
admission plus failure of credential/opening/unspent success for the exact
generated history. Its proved quantitative bound is below `2^-130` plus the six
explicit induced-game advantages, using the original Born measure and one
global extraction charge. This chronological event covers positive native
spends. The supplementary all-active theorem is pointwise and applies to
every asset: occupied historical opening, exact known-empty opening, or path
collision, with all seven owner coordinates when occupied. It does not
silently supply an all-asset/zero-value chronological unspent theorem.

Known-empty is not a failed hash assumption. It is the deliberate public-key
zero-value placeholder, and a position empty at an earlier admitted anchor
may later receive a real appended note. Merely changing the chronological
filter from positive-native to active would incorrectly spend those positions.

## Implementation and cryptographic trust

See [RP05_IMPLEMENTATION_BOUNDARY.md](RP05_IMPLEMENTATION_BOUNDARY.md) for the
concrete acceptance path, reproducible focused tests and exact ciphertext
commitment game. The remaining primitive advantages include the current
Poseidon2 note commitment, ordered Merkle compression, twelve-word nullifier,
five-word SingleKey, accumulator Compress14 and mixed-domain claw games. The
SHA-512 oracle is modeled as an ideal quantum-accessible random oracle.
BLAKE2b correctness and binding of the projected ciphertext commitment are
explicitly separate from those six Poseidon2 games. Whole-product note
encryption and network authentication additionally rely on their ML-KEM,
ML-DSA, symmetric encryption and randomness assumptions; the transaction
proof theorem alone is not a proof of these independent components.

## Contract-status correction

The artifact adapter deliberately emits
`complete_q38_security_contract_satisfied=false`; it is conservative software
metadata, not a failed contract theorem. The separate source-owned RP05 review
packet checker invokes the complete contract validator. Its retained current
technical result is `PASS_PR_ONLY`, with contract status
`PASS_SOURCE_PINNED_AND_SEMANTICALLY_VALIDATED`. Neither result authenticates
release authority or selects a production capability.

## Validation record

The public-simulator ZK source `5c020d63` has passed strict compilation and
its 36,386-declaration proof-body audit, with no missing bodies or nonstandard
axioms. The eight focused Rust filters pass on the test-only source freeze
`b99bd732`; their receipt digest is `5433e536`. The staged source closure
contains 1,471 modules and 108 external imports and passes source-pin checking.

The new single-spend source `e0171096`, supplementary all-active classification
`d5ae87d0`, and public authorization facade `ee34a25f` pass strict kernel
checking. The initial BUILD-first authorization body audit traverses 49,946
declarations with only the three standard Lean axioms and no missing bodies.
Earlier failed or timed-out attempts are retained and are not credited.

The 1,471-module package initially compiled five modules and reused 1,466.
Canonical proof-body checking exposed two unchanged cached dependency variants
referring to a missing internal matcher. Both owners were strictly rebuilt
against the package imports and individually body-audited; affected-importer
rebuilds compiled 18 and then 22 modules, reusing 1,453 and 1,449 respectively.
The final read-only package check passes across all 1,471 modules, 108 external
imports and four roots. The retained failed cache audits are not credited.

All four final public-facade strict receipts and actual-body audits pass against
the repaired canonical imports, with stable pre/post fingerprints and only the
three standard Lean axioms. The audits traverse 45,282 declarations for
soundness, 36,399 for the new ZK export and its witness-independence/loss/lifetime
roots, 49,927 for authorization plus all-active classification, and 49,876 for
conservation. Fresh tiny-facade objects for S/P/C are byte-identical to the
canonical package objects; A reuses its exact-import compatible strict receipt.
No BUILD-first dependency shadow or older WI root is substituted for public ZK.

The portable evidence summary records the exact final source and receipt
digests. Raw local objects and host-path records remain local; independent
reviewers must reproduce their own checks from the published source snapshot.
