# Integrate random unused B128 tail symbols into the one-main n15 trace

This ExecPlan is a living document maintained under `/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md`. It describes a source-only delta after the coefficient-mask and grouped-relation patches. It does not authorize compilation below the disk gate or any ZK, strict-security, proof-size, or frontier claim.

## Purpose / Big Picture

The maximum one-main M4 relation commits an n15 B128 trace but does not use every high symbol. After this change, a caller can request that every whole unused symbol contain fresh cryptographic prover randomness while the active circuit prefix and verifier dimensions remain unchanged. The call returns the exact compiled active/tail geometry. The complete clear-observation matrix remains unavailable, so this is integration mechanics rather than a hiding proof.

## Progress

- [x] (2026-08-21T19:35:00Z) Read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, the maximum M4 source, random-padding audit, and pinned Binius trace/shift/ring-switch/BaseFold/FRI paths.
- [x] (2026-08-21T19:43:00Z) Reconstructed revision `3f96163049f680b2909f6545690bd929f1b48c44` with coefficient patch SHA-256 `684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54` and grouped patch SHA-256 `37dfdee589e476c09fe5c955bd46942cd5aa293a3177d7a43d07f14aeb8ef9df`.
- [x] (2026-08-21T19:50:00Z) Implemented the shared random-tail buffer, exact geometry export, and one-main n15 fail-closed admission in a disposable checkout.
- [x] (2026-08-21T19:56:00Z) Added the full-word-domain equality guard after finding that an n15 symbol buffer is n16 words and must not change verifier sumcheck dimensions.
- [x] (2026-08-21T20:02:00Z) Froze the five-file patch and dependency-free source checker; patch application, source hashes, scope, selector KATs, rustfmt, and `git diff --check` pass.
- [ ] Compile and run targeted tests only when free disk is at least 28 GiB.
- [ ] Add a transcript-synchronized linear-observation sink spanning shift phase 2, ring switch, BaseFold, and adaptive FRI; audit the exact union matrix.
- [ ] Prove adaptive BCS/ROM ZK and strict SHAKE256-512/mixed-field/QROM security before promotion.

## Surprises & Discoveries

- Observation: Randomizing only `pack_witness` is inconsistent.
  Evidence: shift phase 2 originally folded `witness.non_public()` while ring switch opened `witness_packed`; different tails produce different trace evaluations.
- Observation: Filling an n15 B128 message creates an n16 word slice.
  Evidence: B128 packs two 64-bit words. The patch now requires `key_collection.log_witness_words() == log_witness_elems + 1` before extending the slice.
- Observation: Selector exclusion is already structural.
  Evidence: phase 1 zips words with declared key ranges, the monster buffer zero-resizes after `segment.n_words()`, the verifier cuts at `cs.n_private`, and constraint validation rejects out-of-range indices.
- Observation: The current channel cannot export a rank matrix.
  Evidence: `IPProverChannel::send_one/send_many` receive only field values; tail coefficient rows are discarded before shift, ring-switch, BaseFold, and FRI messages reach the transcript.

## Decision Log

- Decision: Randomize only complete unused B128 symbols and retain zero in an odd active symbol's high 64 bits.
  Rationale: The field coefficient containing an active word is part of the active prefix; a half-random coefficient is not the uniform high-coefficient pad required by the rank theorem.
  Date/Author: 2026-08-21 / Codex.
- Decision: Feed one shared padded word buffer to both commitment packing and shift reduction.
  Rationale: This keeps the opened trace identical to the trace used by the PIOP.
  Date/Author: 2026-08-21 / Codex.
- Decision: Reject chips, witness tables, IntMul, multiple oracles, masked oracle specs, wrong tiers, wrong word-domain dimensions, prefix mismatches, and empty whole-symbol tails before transcript creation.
  Rationale: Each case falls outside the single maximum-trace security model or would alter protocol shape.
  Date/Author: 2026-08-21 / Codex.
- Decision: Do not fabricate a coefficient-row export by logging scalar values.
  Rationale: Rank requires exact B128 rows after the actual adaptive Fiat--Shamir schedule; values alone cannot reconstruct them.
  Date/Author: 2026-08-21 / Codex.
- Decision: Leave verifier and maximum relation source unchanged.
  Rationale: Dimensions remain constraint-system-derived, and the requested deliverable is an isolated upstream seam.
  Date/Author: 2026-08-21 / Codex.

## Outcomes & Retrospective

The source delta provides a real runtime API, not a mock geometry constant. It preserves active words, samples one uniform `u128` per whole tail symbol from a `CryptoRng`, commits and folds the identical buffer, and returns exact counts. Static checks bind the maximum source and relation-exclusion chain. Compilation, proof roundtrip, exact observation rank, adaptive ZK, strict security, and bytes remain false. The correct next architectural change is an observation-provenance API, not a proof-size claim.

## Context and Orientation

The selected base is Binius revision `3f96163049f680b2909f6545690bd929f1b48c44`. Apply the coefficient patch, then the grouped patch, then this random-tail delta. `crates/prover/src/prove.rs` owns the ordinary Binius64 trace commitment and shift call. `crates/m4-prover/src/composite.rs` owns the composite one-main/chip orchestration. `crates/prover/src/protocols/shift` builds the relation selector. `crates/prover/src/ring_switch.rs` and `crates/iop-prover/src/basefold` reduce and open the trace. The maximum Hegemon relation remains in `prototypes/standalone-shake256-binius/m4-full-production-prototype/src/` and is not modified.

A B128 symbol is one element of the pinned GHASH field and contains two consecutive 64-bit trace words. “Active prefix” means the shortest prefix of B128 symbols containing every declared private word. “Random tail” means all complete B128 symbols after that prefix through the fixed n15 boundary.

## Plan of Work

Preserve the frozen patch and source checker. Above the disk gate, reconstruct the exact stack in a disposable checkout and first compile the affected prover crates offline. Add unit tests covering even and odd active word counts, reused/deterministic test RNGs, each admission rejection, honest proof verification, random-tail proof diversity, and mutation rejection. Compile the maximum relation and record `RandomTraceTailGeometry` directly.

Then add `LinearObservationSink` as a separate reviewed interface. It must receive phase/kind, oracle identity, exact B128 coefficient rows, values, and challenge/index provenance from every tail-dependent shift phase-2 send, all 128 ring-switch coordinates, BaseFold Phase-A sends, and FRI query/terminal sends. Bind or replay the same schedule on the verifier side, expand extension-field values into B128 coordinates, and audit one union matrix. Keep adaptive BCS/ROM proof work separate from the realized-matrix calculation.

## Concrete Steps

From a clean pinned Binius checkout, apply the three patches in the order documented in `README.md`. From the Hegemon root run:

    PYTHONDONTWRITEBYTECODE=1 python3 prototypes/standalone-shake256-binius/m4-random-tail-integration-patch/check_random_tail_integration.py --tree /path/to/post-stack-binius

Expect JSON containing `SOURCE_STATIC_PASS`, `active_prefix_exported: true`, and `complete_linear_observation_union_exported: false`. Run `git diff --check` in both trees. Do not run Cargo while `df -Pk` reports less than `29,360,128 KiB` free.

When admitted, use an explicitly named disposable target under `/private/tmp`, locked offline dependencies, and targeted packages only. The first compile/test sequence should cover `binius-prover` and `binius-m4-prover`; a maximum-relation prover run comes only after those pass. Remove only the explicitly named disposable target after hashes and logs are recorded.

## Validation and Acceptance

Source acceptance requires exact base/prerequisite/patch hashes, exactly five changed files, no verifier or maximum-source edit, randomization over `active_symbols..total_symbols`, preservation of an odd partial symbol, identical commitment/shift buffers, exact word-domain equality, and every high-level admission check before transcript creation. The selector anchors and algebra KAT must pass.

Executable acceptance additionally requires compilation, targeted tests, honest verify, active/public/proof mutation rejection, exact transcript exhaustion, two fresh-tail proofs, and a runtime geometry record from the maximum relation. Security acceptance separately requires a complete observation union, rank audit, adaptive BCS/ROM simulator, strict 64-byte SHAKE256-512 commitment backend, mixed-field soundness, and composed QROM analysis. Source acceptance implies neither executable nor security acceptance.

## Idempotence and Recovery

The ordered immutable patches reconstruct the same source. Reapplying a patch must fail. The checker is read-only and creates no cache when `PYTHONDONTWRITEBYTECODE=1` is set. Work in disposable checkouts; never delete a shared target or mutate the sealed ledger. If the base or prerequisite hashes drift, stop and re-audit rather than forcing the patch.

## Artifacts and Notes

The random-tail patch changes `crates/m4-prover/Cargo.toml`, `crates/m4-prover/src/composite.rs`, `crates/m4-prover/src/lib.rs`, `crates/prover/src/protocols/shift/segment_words.rs`, and `crates/prover/src/prove.rs`. Free disk during source validation was roughly 25.0 million KiB, so no Cargo/build/prover command ran. Downstream strict commitments require 64-byte SHAKE256-512 digests; hashing is deliberately outside this patch.

## Interfaces and Dependencies

The stable new low-level interfaces are `IOPProver::log_witness_elems`, `IOPProver::random_trace_tail_geometry`, `IOPProver::prove_with_random_trace_tail`, and `RandomTraceTailGeometry`. The high-level interfaces are `ProverM4::random_trace_tail_geometry`, `ProverM4::prove_main_with_random_trace_tail`, `RandomTraceTailError`, and `RANDOM_TAIL_LOG_TRACE_SYMBOLS`. `rand` becomes a normal `binius-m4-prover` dependency so the public method can require `CryptoRng`.

The missing interface is a protocol-wide `LinearObservationSink`; it cannot be implemented as a channel-only wrapper because the existing channel receives values after coefficient provenance has been erased.

Revision note (2026-08-21): Initial source-only integration frozen after correcting shared-buffer consistency and full-word-domain admission. Executable and security milestones remain open.
