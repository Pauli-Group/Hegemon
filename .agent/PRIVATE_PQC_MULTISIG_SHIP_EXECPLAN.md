# Ship Private PQC Multisig

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon needs private multisig for shielded spends without public signer metadata, reusable approval secrets, action-layer authorization envelopes, MPC, trusted setup, or per-transaction on-chain proof bloat. The product route is a stateful shielded accumulator: each signer submits a private approval transaction themselves, consuming a signer capability note and the current accumulator note, then creating a new accumulator note for one exact spend intent. The final spender consumes the value note plus the threshold accumulator note and learns no signer long-term secret.

The user-visible result is not a wallet-only cosigning wrapper. It is a proof-native custody primitive: a threshold spend succeeds only when private accumulator state proves enough distinct statement-bound signer approvals for the exact spend statement, and fails otherwise. The chain must see the normal shielded transaction public surface; signer set, threshold, approval count, policy root, approval leaves, and approval nullifiers remain private.

## Progress

- [x] (2026-06-26) Confirmed the current branch is `codex/private-predicate-threshold-spend` and clean at `7170c003`.
- [x] (2026-06-26) Re-read `DESIGN.md`, `METHODS.md`, and `.agent/PLANS.md` before making main-branch edits.
- [x] (2026-06-26) Killed the reusable leaf-secret predicate relation as no-ship: coordinator/prover would learn reusable signer material.
- [x] (2026-06-26) Killed hidden ML-DSA-in-current-SmallWood as no-ship for production: native ML-DSA verification works, but the current proof relation has no private lattice-verifier lane.
- [x] (2026-06-26) Validated the standalone SmallWood authorization-certificate spike locally: focused test passes and the sample proof is about 95 KiB, but it is not a product path until folded.
- [x] (2026-06-26) Validated the block/batch carrier seam as carrier binding only: it binds ordered transaction statement hashes and an opaque authorization root without changing transaction/action payloads.
- [x] (2026-06-26) Killed hosted authorization-certificate folding through the current SmallWood/block-recursion lane: `auxiliary_witness_words` are serialized into proof bytes, so carrying `policy_root`, `signer_tag`, or certificate verifier material there would make it chain-visible.
- [x] (2026-06-26) Rejected raw inline certificate rows as a product replacement without MPC: if the final prover receives reusable signer leaf secrets, the spender can authorize later transactions.
- [x] (2026-06-26) Killed the raw inline private-authorization fold after implementation inspection: empty auxiliary words are not enough because the final prover still receives reusable signer secrets and policy membership preimages.
- [x] (2026-06-26) Narrowed the surviving product path to hidden statement-bound signature verification inside the private spend proof. Threshold ML-DSA can be used only as the signer-side producer of a standard ML-DSA signature; the spend proof must privately verify the resulting `vk/signature/message` without publishing signer metadata.
- [x] (2026-06-26) Hardened the outer SmallWood candidate wrapper so it refuses nonempty `auxiliary_witness_words`, with a Lean-modeled rejection and a Rust regression. This does not remove or privatize the inner SmallWood opened-witness auxiliary channel; private authorization data must not use either channel.
- [x] (2026-06-26) Identified the repo-native receipt-note route and its first hard prerequisite: the current transaction AIR has one global spend-key derivation and `MAX_INPUTS = 2`, so true m-of-n receipt-note authorization needs per-input authorization derivations and a larger fixed input shape before it can be productized.
- [x] (2026-06-26) Dispatched formal/Rust, circuit/proof, and wallet/protocol worker threads for the stateful accumulator route:
  - formal/Rust: `019f01e7-7c36-7433-9753-fa45add24b4a`, worktree `/Users/pldd/.codex/worktrees/3446/Hegemon`, branch `codex/private-multisig-accumulator-formal`.
  - circuit/proof: `019f01e7-7c35-7833-b330-ce10f83ea6d0`, worktree `/Users/pldd/.codex/worktrees/13d1/Hegemon`, branch `codex/private-multisig-accumulator-circuit`.
  - wallet/protocol: `019f01e7-7c30-7152-a418-4cee8eebdf52`, worktree `/Users/pldd/.codex/worktrees/9c47/Hegemon`, branch `codex/private-multisig-accumulator-wallet-flow`.
- [ ] Integrate or reject the hidden policy-binding commit `714a693c` after confirming it matches the accumulator note model.
- [ ] Implement or precisely kill the accumulator relation in the SmallWood transaction relation, including row/proof-size accounting and no public mode/policy/count leakage.
- [ ] Implement or precisely kill the wallet accumulator flow without provisional proof hooks.
- [ ] Update Lean/formal targets to match the implemented path, including public-leak sentinels and exact statement-hash binding.
- [ ] Run focused Rust and Lean checks.
- [ ] Run the full formal-core gate.
- [ ] Validate live transactions/mining between the laptop and `native-devnet-host`.
- [ ] Commit and push only after the implementation is coherent and verified.

## Surprises & Discoveries

- The old leaf-secret relation had a transaction-bound approval nullifier, but that did not make it safe: anyone who learns the reusable leaf secret can authorize a later transaction with a fresh nullifier.
- A standalone authorization certificate can be a useful proof primitive, but host-side duplicate tag checks are not proof soundness. Threshold count and distinctness must be enforced inside the final proof.
- SmallWood proof bytes include opened witness row evaluations. For the certificate relation these are randomized polynomial evaluations, not direct row values, but the product path must document the witness-hiding assumption and should eventually have a formal proof-system claim.
- The existing recursive proof code dispatches over known hosted relation kinds. Folding authorization certificates requires adding a hosted relation path or inlining the certificate relation into the spend proof; proof-byte digests alone are not authorization.
- Hosted recursion's auxiliary witness channel is public proof material. It is suitable for block-prefix recursion, where previous proof metadata is not private, but it cannot carry shielded multisig policy roots, signer tags, verification keys, signatures, or certificate statements.
- The term "inline certificate relation" is unsafe unless the signer witness is a per-transaction signature or a private child proof. Inlining reusable signer leaf secrets into a final proof generated by the spender recreates the original reusable-secret failure.
- A private fold relation whose witness rows contain `signer_secret`, signer leaf preimage limbs, membership siblings, or direction bits is still a disclosure to the final prover. SmallWood row hiding protects against chain observers, not against the party assembling the final witness.
- The release proof emitter already encodes the outer SmallWood candidate wrapper through the legacy empty-auxiliary form. The hardening closes accidental or future use of the current wrapper's outer `auxiliary_witness_words` field; inline-Merkle auxiliary material remains inside the inner SmallWood proof surface and is public proof material.
- The stateful accumulator route is stronger than raw receipt-note finalization: it keeps the final transaction at two inputs, because approvals are folded ahead of time by signer-submitted private approval transactions. The hard circuit work moves to approval-step and final-step private note semantics rather than hidden PQC signature verification.
- The final spender can only use the accumulator for the exact intent committed into it. Signer approvals are one-shot because the approval transaction consumes a signer capability or used-signer state and advances the accumulator; the final spender never receives signer secrets.

## Decision Log

- Decision: Treat statement-bound authorization certificates as a primitive, not a product route by themselves.
  Rationale: A certificate proof can avoid reusable signer-secret exposure only if the signer produces it independently and the final proof verifies the certificate without receiving the signer's reusable witness. Raw inline certificate rows in the final spend proof are unsafe if the spender learns signer leaf/preimage material.
  Date/Author: 2026-06-26 / Codex

- Decision: Do not merge leaf-secret predicate spends as a product path.
  Rationale: The coordinator/prover would receive reusable signer material.
  Date/Author: 2026-06-26 / Codex

- Decision: Treat the block/batch authorization object as carrier binding only until a real proof backend consumes the same statement.
  Rationale: Consensus must not accept host-provided private data as proof of authorization.
  Date/Author: 2026-06-26 / Codex

- Decision: Do not use the current hosted SmallWood recursion path to fold private authorization certificates.
  Rationale: `SmallwoodProofTraceV1` serializes `auxiliary_witness_words`, and the hosted block-recursion verifier reconstructs prior proof material from that public channel. A private authorization fold through this path would leak inner certificate verifier material in on-chain proof bytes.
  Date/Author: 2026-06-26 / Codex

- Superseded decision: Treat hidden standard-signature verification as a candidate product target.
  Rationale: It avoids reusable approval secrets and lets threshold ML-DSA remain off-chain signer-side machinery that outputs an ordinary statement-bound ML-DSA signature. The unresolved hard part is proving ML-DSA verification privately and succinctly enough in Hegemon's proof stack.
  Date/Author: 2026-06-26 / Codex

- Decision: Replace hidden standard-signature verification as the target with stateful shielded accumulator notes.
  Rationale: Hidden ML-DSA/SLH-DSA verification risks proof-size and engineering blowup. A shielded accumulator uses the existing note/proof model: signers prove authorization in their own transactions, and the final spender receives a non-reusable accumulator state for one exact spend intent. This avoids MPC, trusted setup, public signer metadata, and reusable signer-secret disclosure.
  Date/Author: 2026-06-26 / Codex

- Decision: Kill raw inline private-authorization folds that require the final prover to know reusable signer or membership material.
  Rationale: Empty `auxiliary_witness_words` prevents public proof-byte leakage only. It does not prevent the final prover from retaining reusable authorization material and spending again.
  Date/Author: 2026-06-26 / Codex

- Decision: Treat the outer SmallWood candidate wrapper as an empty-auxiliary release envelope.
  Rationale: The current wrapper's `auxiliary_witness_words` field is public serialized proof material and is not needed by the production emitter, which passes `&[]`. Rejecting nonempty outer auxiliary words prevents private authorization material from being routed through that field.
  Date/Author: 2026-06-26 / Codex

- Decision: Investigate private authorization receipt notes as the repo-native non-signature route.
  Rationale: Receipt notes can make signer approval transaction-bound and non-reusable without proving ML-DSA/SLH-DSA verification inside the spend, but the deployed single-global-key transaction relation must first be generalized to per-input authorization and enough fixed input slots to hide the approval count.
  Date/Author: 2026-06-26 / Codex

## Outcomes & Retrospective

Pending. This plan is not complete until the folded private proof path is either shipped and validated, or precisely killed with a concrete implementation blocker.
