# Close the authoritative-action composition boundary

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be maintained while this work proceeds. This plan follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

The raw IronSpartan verifier correctly proves whatever 478-byte public statement it is given, but ciphertext hashes, the network binding, and the balance tag are externally derived fields rather than private-relation outputs. A node must therefore exact-decode the full `HGSP` envelope, reconstruct the one canonical statement from its authoritative action and network identity, then verify the proof against exactly that statement. After this change, one composed entry point performs all three operations and fails closed before proof verification when the envelope route, action route, or projection is invalid.

The observable result is a negative-control test in which a fresh valid proof over each forged external-field class passes the unchanged raw verifier, while the composed verifier rejects that same proof against the original authoritative action and network. Additional tests demonstrate that invalid kernel, route, shape, byte-size, native-slot, monetary, stablecoin, candidate-artifact, and binding-digest projections reject before the proof verifier is called.

## Progress

- [x] (2026-08-19 13:30Z) Re-read `DESIGN.md`, `METHODS.md`, and `.agent/PLANS.md`; preserve the raw-verifier and prototype-only security boundaries.
- [x] (2026-08-19 13:30Z) Asked the statement-adapter owner to freeze the prospective V5/Delta action-projection API before integration.
- [x] (2026-08-19 13:36Z) Added the existing 12-byte exact-envelope boundary to the design: magic/version/backend/profile/length/full consumption precede action projection and proof work.
- [x] (2026-08-19 13:38Z) Added exact `HGSP` plus authoritative V5/Delta action/network composition without changing raw IronSpartan verification semantics.
- [x] (2026-08-19 13:40Z) Added three fresh-forgery proofs, seven pre-projection envelope rejects, and fifteen pre-proof action rejects with invocation counters.
- [x] (2026-08-19 13:42Z) Ran formatting, clippy with warnings denied, locked tests, and a real corrected rate-three proof; proof size remains 380,496 bytes.
- [x] (2026-08-19 13:43Z) Froze the four source hashes and final process-tree harness report.
- [x] (2026-08-19 13:45Z) Removed only `/private/tmp/hegemon-pay1x2-composed-target`; 33,280,136 KiB remained free.

## Surprises & Discoveries

- Observation: old-proof/new-public-byte mutation tests prove transcript binding, but cannot show that externally derived bytes came from the node-owned action and network.
  Evidence: a prover can generate a fresh proof for arbitrary Boolean ciphertext-hash, network-binding, and balance-tag bytes because the circuit intentionally does not recompute them.

- Observation: the backend's fixed public prefix still encoded the superseded circuit/crypto/profile tuple `2/1/2/1/2` after the statement route froze at `2/5/4/1/1`.
  Evidence: correcting `FIXED_ADAPTER_PREFIX` was required before the new authoritative proof would satisfy the circuit. Constraint geometry stayed at 1,883,192 rows and the regenerated rate-three proof stayed at 380,496 bytes.

- Observation: fresh-forgery controls materially distinguish raw transcript binding from protocol composition.
  Evidence: fresh raw proofs for forged ciphertext-hash, network-binding, and balance-tag bytes all verify, while composition against the original action/network rejects all three.

## Decision Log

- Decision: Keep raw verification available and unchanged, and add composition as a separate fail-closed API.
  Rationale: raw verification is the correct cryptographic primitive; authoritative action projection is a caller-owned protocol boundary and must not be silently conflated with circuit semantics.
  Date/Author: 2026-08-19 / Codex.

- Decision: Require the statement crate's frozen V5/Delta projection rather than locally duplicating action parsing or invariants.
  Rationale: one canonical adapter must own versions, routes, sizes, native slots, balance policy, and network reconstruction; duplicate logic would reintroduce drift.
  Date/Author: 2026-08-19 / Codex.

- Decision: Accept a complete `HGSP` envelope at the composed boundary and keep loose proof-byte verification private.
  Rationale: magic, version, backend, profile, declared length, and full consumption are protocol routing authority and must fail before action reconstruction or cryptographic work.
  Date/Author: 2026-08-19 / Codex.

- Decision: Keep envelope version/backend/profile as fail-closed routing inputs and do not absorb `ProofBinding::shake256_512` into the already-measured IronSpartan transcript.
  Rationale: the only admitted route is fixed before backend dispatch; adding a second transcript digest would silently define a different raw proof format and invalidate the measured backend semantics.
  Date/Author: 2026-08-19 / Codex.

## Outcomes & Retrospective

The composed verifier now exact-parses `HGSP`, reconstructs and exact-checks the 478-byte HGS2 statement from the prospective Kernel V5/Delta family-1/action-7 projection plus authoritative network, rebuilds the padded Binius public vector, and exact-consumes the proof. The corrected real rate-three proof is 380,496 bytes, its envelope is 380,508 bytes, composed verification measured 172 ms, and process-tree peak RSS was 5,524,226,048 bytes. All requested negative controls pass. This closes the prototype composition bug but does not register the route in consensus, bind the production ciphertext parser, qualify upstream's 96-bit/SHA-256/GF(2^128) profile, prove composed PQ128, or establish end-to-end zero knowledge.

## Context and Orientation

`src/lib.rs` defines the fixed full native Pay1x2 binary relation. `src/main.rs` constructs the deterministic witness, compiles the relation, proves it, and exact-verifies the transcript through `VerifierTranscript::finalize`. The sibling crate `circuits/standalone-pay1x2-statement-prototype` owns the canonical statement encoding and the authoritative action/network projection. `circuits/standalone-proof-envelope-prototype` owns the exact 12-byte `HGSP` header and parser. The public statement is observed by Fiat-Shamir, but several bytes are deliberately only Boolean inside the circuit because they are projections of public action data.

Here, “raw verifier” means Binius verification against caller-supplied canonical statement bytes. “Composed verifier” means first exact-decoding and reconstructing those bytes from the node-owned action and network, then invoking the raw verifier with the reconstructed bytes. “Fresh forgery” means proving a newly chosen, structurally valid public statement whose external derived field differs; it is stronger than mutating the public input under an old proof.

## Plan of Work

Wait for the statement owner to freeze the V5/Delta API. Import its authoritative action type and canonical verification function through the existing path dependency, and add a path dependency on the isolated envelope crate. Factor current verifier setup/public-input construction/exact transcript consumption into reusable private helpers without altering the raw verifier. Add a composed result/error type that distinguishes envelope, projection, and cryptographic rejection, and a test-only observation hook or counter so pre-proof rejection is demonstrated rather than inferred.

For each externally derived field class, construct a forged canonical statement, generate a fresh proof for it, confirm raw verification accepts it, then call the composed verifier with the original authoritative action/network and confirm rejection. Exercise every frozen action-projection invariant with one mutation and assert the proof verifier was not entered. Do not weaken or add semantic constraints to the circuit merely to compensate for adapter mistakes.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`. Build only with `CARGO_TARGET_DIR=/private/tmp/hegemon-pay1x2-composed-target` and `CARGO_INCREMENTAL=0`. Run:

    cargo +1.97.1 fmt --manifest-path prototypes/standalone-shake256-binius/pay1x2-backend/Cargo.toml -- --check
    cargo +1.97.1 clippy --manifest-path prototypes/standalone-shake256-binius/pay1x2-backend/Cargo.toml --offline --all-targets -- -D warnings
    cargo +1.97.1 test --manifest-path prototypes/standalone-shake256-binius/pay1x2-backend/Cargo.toml --offline --locked

The HGS2 fixed prefix changed from a stale tuple to `2/5/4/1/1`, so the real deterministic rate-three executable was rerun. Public-vector and constraint geometry did not change, so the prior inverse-rate size sweep was retained while the authoritative rate-three row and harness were regenerated.

## Validation and Acceptance

Acceptance requires the unchanged raw verifier to accept honest proofs and freshly generated proofs for three forged canonical statements: altered ciphertext hash, network binding, and balance tag. The composed verifier must reject those three proof envelopes against the original action/network. It must reject bad `HGSP` magic/version/backend/profile, wrong declared length, and trailing bytes before statement projection. It must also reject wrong kernel binding, wrong route, wrong counts, wrong ciphertext sizes, wrong native slots, nonzero value balance, present stablecoin data, present candidate artifact, and wrong binding digest before invoking Binius verification. Changed proof and proof-internal trailing bytes must continue to reject through `VerifierTranscript::finalize`.

Formatting, clippy with warnings denied, locked tests, JSON parsing, and `git diff --check` must pass. The final report must keep the upstream 96-bit/SHA-256/GF(2^128), incomplete composed-PQ128, and incomplete end-to-end zero-knowledge limitations explicit.

## Idempotence and Recovery

The tests use deterministic fixtures and can be repeated. The statement crate is treated as read-only from this workspace once frozen. If its API changes before freeze, update this plan before editing code. Delete only `/private/tmp/hegemon-pay1x2-composed-target` after validation; never delete the repository-wide target directory or another agent's temporary path.

## Artifacts and Notes

The regenerated circuit measurement confirms host-only verifier composition adds no proof bytes or circuit rows. Frozen source hashes are recorded in `measurements/composed-verifier-v5-delta-2026-08-19.json`.

## Interfaces and Dependencies

Use the statement crate's frozen authoritative action type and `verify_canonical_action_statement` function, plus the envelope crate's exact decoder and fixed Binius/Pay1x2 route. The backend will internally use one raw exact verifier over canonical bytes and proof bytes, plus one composed verifier over authoritative action, network identity, full envelope bytes, and the compiled verifier context. The composed function must reconstruct its public vector only after envelope and statement verification succeed.

Revision note (2026-08-19): Initial plan created to close the P1 authoritative-action composition gap identified by adversarial review.

Revision note (2026-08-19): Expanded the boundary to the exact `HGSP` envelope after parent review required route and consumption checks ahead of action projection.

Revision note (2026-08-19): Completed implementation, recorded the stale-prefix correction and negative-control evidence, and froze the authoritative rate-three measurement.
