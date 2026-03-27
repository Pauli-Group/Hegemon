# Make The Native Backend Defensible At 128-Bit PQ Security

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

This plan starts after [`.agent/REBUILD_NATIVE_BACKEND_EXECPLAN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/REBUILD_NATIVE_BACKEND_EXECPLAN.md) rebuilt the native backend into the current `goldilocks_128b_rewrite` candidate. That earlier plan was allowed to stop at “keep this in tree as the live experimental candidate.” This plan does not stop there. Its job is to turn that candidate into a cryptographic package that can either support the core design claim of 128-bit post-quantum security with a straight face or get killed explicitly. No middle ground remains acceptable.

## Purpose / Big Picture

After this change, the repository will no longer rely on benchmark JSON and a hand-written assumption label as the whole security story for the native backend. A contributor will be able to read one exact specification, generate fixed test vectors, verify those vectors with two independent verifier implementations, inspect a code-derived security claim that enumerates every assumption and loss term, run parser/fold/opening fuzzers, run a timing-discipline harness for secret-bearing prover code, and build one reproducible external-review package with fixed claims and attack targets.

The user-visible outcome is direct. From the repository root, a novice can now run one command to emit the native backend review package, one command to verify that package with the reference verifier, and one command to print the current security claim. If any piece of the package is incomplete or if the computed floor falls below the claimed level, setup and verification fail closed. If the full package clears every gate, the core design documents may state the backend as a serious 128-bit PQ candidate under external review instead of a vague hopeful target.

## Progress

- [x] (2026-03-27 16:34Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, and `.agent/REBUILD_NATIVE_BACKEND_EXECPLAN.md` to anchor this plan in the current `goldilocks_128b_rewrite` state instead of inventing a new abstract target.
- [x] (2026-03-27 16:34Z) Confirmed that the repo currently has a 128-bit-target candidate, not a finished 128-bit package: the docs still describe the backend as an in-repo approximation rather than a paper-equivalent commitment stack.
- [x] (2026-03-27 16:34Z) Confirmed the scale of the new homebrew crypto surface versus `main`: `git diff --stat main...HEAD -- circuits/superneo-backend-lattice circuits/superneo-ring circuits/superneo-hegemon circuits/superneo-core circuits/superneo-ccs consensus/src/proof.rs node/src/substrate/service.rs` reports `11,357` inserted lines and `463` deletions across the backend, relation layer, and integration surface.
- [x] (2026-03-27 16:34Z) Authored this successor ExecPlan to turn the current candidate into a full security package with a forced keep-or-kill end state.
- [x] (2026-03-27 17:08Z) Completed milestone 1: added [docs/crypto/native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md), added manifest-owned `spec_label` plus `spec_digest` in the backend, threaded that spec identity through native `TxLeaf` and `ReceiptRoot` artifacts, bound it into verifier profiles and benchmark JSON, and added regressions that reject tampered spec digests.
- [x] (2026-03-27 20:12Z) Completed milestone 2: replaced `NativeSecurityEnvelope` with `NativeSecurityClaim`, added `ReviewState`, made setup reject overclaims against the computed floor, added `cargo run -p superneo-bench -- --print-native-security-claim`, and added [docs/crypto/native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md) plus [docs/crypto/native_backend_attack_worksheet.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_attack_worksheet.md).
- [x] (2026-03-27 20:33Z) Archived a fresh current-tree release benchmark at [native_tx_leaf_receipt_root_security_claim_m2_20260327.json](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/benchmarks/native_tx_leaf_receipt_root_security_claim_m2_20260327.json), confirming the post-claim-model byte curve at `18,137..18,604 B/tx` and the live claim object in benchmark JSON.
- [x] (2026-03-27 21:24Z) Completed milestone 3: added [tools/native-backend-ref](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref), added deterministic vector emission and the fixed `11`-case bundle at [testdata/native_backend_vectors/bundle.json](/Users/pldd/Projects/Reflexivity/Hegemon/testdata/native_backend_vectors/bundle.json), and added a production/reference agreement test in `superneo-bench`.
- [x] (2026-03-27 23:08Z) Completed milestone 4: added transcript-domain regressions, added the `fuzz/` package, ran `cargo +nightly fuzz run native_tx_leaf_artifact -- -max_total_time=60` and `cargo +nightly fuzz run receipt_root_artifact -- -max_total_time=60`, and wired the same native-backend security smoke gate into [ci.yml](/Users/pldd/Projects/Reflexivity/Hegemon/.github/workflows/ci.yml).
- [x] (2026-03-27 23:11Z) Completed milestone 5: added [docs/crypto/native_backend_constant_time.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_constant_time.md), added [tools/native-backend-timing](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-timing), and validated the current deterministic tx-leaf build path with `welch_t_statistic = 1.2463`, below the fail threshold `10.0`.
- [x] (2026-03-27 23:16Z) Completed milestone 6: added the audit/break-it bundle under [audits/native-backend-128b](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b), added [package_native_backend_review.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/package_native_backend_review.sh) and [verify_native_backend_review_package.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/verify_native_backend_review_package.sh), built the reproducible tarball, and verified final hash `31ce04299b6c35e198de72211ba8fc4254dfd8db1e95b19b443db3c1b4f2216e`.
- [x] (2026-03-27 23:27Z) Completed milestone 7: archived the final current-tree release benchmark at [native_tx_leaf_receipt_root_security_package_final_20260327.json](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/benchmarks/native_tx_leaf_receipt_root_security_package_final_20260327.json), reran the focused backend/consensus/node validation set, rebuilt the release node, and confirmed a native-only `receipt_root` dev node boots and mines under `HEGEMON_REQUIRE_NATIVE=1`. Final verdict: `KEEP`, with `review_state = candidate_under_review`.

## Surprises & Discoveries

- Observation: the current branch already knew it was not done; the contradiction was in the package boundary, not in the benchmark surface.
  Evidence: before milestone 2, [DESIGN.md](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md) reported a full `128`-bit target through `NativeSecurityEnvelope` while still warning that the backend was not paper-equivalent. Milestone 2 fixed that mismatch by moving the live story to `NativeSecurityClaim` with explicit `assumption_ids` and `review_state = candidate_under_review`.

- Observation: the missing work is not “tune the numbers harder.” It is “turn a cryptographic candidate into a cryptographic package.”
  Evidence: the current repo already has explicit manifest identity, fingerprinting, parameter ownership, artifact-bound checks, and benchmark archives, yet it still lacks an exact spec, a second verifier implementation, a reduction worksheet, and an outside-review package.

- Observation: the homebrew surface is large enough that a casual “we can probably audit it later” posture is not serious.
  Evidence: the current diff from `main` adds `2,388` lines in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), `4,336` lines in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs), `355` lines in [circuits/superneo-ring/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-ring/src/lib.rs), `414` lines in [circuits/superneo-ccs/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-ccs/src/lib.rs), `150` lines in [circuits/superneo-core/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-core/src/lib.rs), plus `2,172` and `1,909` lines in consensus and node integration.

- Observation: the cleanest way to freeze the exact protocol surface was to let `spec_digest` follow the full parameter regime under a distinct domain tag rather than inventing a completely separate handwritten version field.
  Evidence: the code now derives `spec_digest()` from the manifest and active parameter fields in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), and native artifact verifiers reject both parameter-fingerprint drift and spec-digest drift independently.

- Observation: the claim model is only useful if operators can print it without running a benchmark and if the docs mirror the exact same fields.
  Evidence: milestone 2 added `cargo run -p superneo-bench -- --print-native-security-claim`, converted benchmark JSON from `native_security_envelope` to `native_security_claim`, and added the matching prose/docs under `docs/crypto/`.

- Observation: the fuzz package had to be treated as a first-class workspace member to make nightly sanitizer builds reuse the repo's locked dependency graph.
  Evidence: the initial standalone fuzz workspace pulled a mismatched `ml-kem`/`kem` graph under nightly and would not build until `fuzz/` joined the main workspace and reused the root lockfile.

- Observation: the native-only node path is stable at boot, but the txpool background task still reports an essential-task failure on shutdown after manual interrupt.
  Evidence: the final dev-node rerun stayed alive, mined work, and served RPC under `HEGEMON_BLOCK_PROOF_MODE=receipt_root HEGEMON_REQUIRE_NATIVE=1 HEGEMON_MINE=1`; the `txpool-background` error only appeared during teardown after `Ctrl-C`.

## Decision Log

- Decision: keep this work in one successor plan instead of scattering it across more “hardening” or “review” subplans.
  Rationale: the missing pieces form one package. Splitting them again would recreate the same drift that previously allowed fake progress to survive.
  Date/Author: 2026-03-27 / Codex

- Decision: treat `goldilocks_128b_rewrite` as a candidate under proof, not as an accepted 128-bit PQ backend.
  Rationale: the repo currently encodes a 128-bit target in code, but it still lacks the exact spec, second verifier, and outside-review package required to make that target a serious cryptographic claim.
  Date/Author: 2026-03-27 / Codex

- Decision: require a truly independent verifier implementation inside the repo.
  Rationale: reusing production verification helpers would not catch the class of bugs that a reference implementation is supposed to catch. The reference verifier may share only plain-data vector files and, if unavoidable, a minimal artifact schema that contains no arithmetic or validation logic.
  Date/Author: 2026-03-27 / Codex

- Decision: move immediately from the old envelope to a claim object with explicit `assumption_ids` and `review_state` rather than preserving two parallel “security summary” surfaces.
  Rationale: leaving both `NativeSecurityEnvelope` and `NativeSecurityClaim` live would recreate the exact ambiguity this plan is supposed to kill.
  Date/Author: 2026-03-27 / Codex

- Decision: block any future “128-bit PQ” language in docs or code unless the code-derived claim model, the reference verifier, the negative/fuzz suite, and the review package all exist.
  Rationale: a single benchmark archive and a single security-envelope struct are not a security package.
  Date/Author: 2026-03-27 / Codex

- Decision: make external cryptanalysis and a public break-it phase part of the implementation plan, not a vague future wish.
  Rationale: this branch introduced a large new cryptographic subsystem. Treating external review as optional would be unserious.
  Date/Author: 2026-03-27 / Codex

- Decision: make `spec_digest` a deterministic code-derived digest over the manifest and active parameter regime rather than a hand-managed integer.
  Rationale: the repo already has one explicit parameter object. Using a distinct hash domain lets the code freeze the exact surface without reintroducing another ad hoc version namespace.
  Date/Author: 2026-03-27 / Codex

## Outcomes & Retrospective

The plan is complete. The repo now has one exact protocol document at [docs/crypto/native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md), one manifest-owned `spec_label`, one code-derived `spec_digest`, one explicit `NativeSecurityClaim`, one fixed vector bundle, one independent verifier, local and CI fuzz-smoke discipline, one timing harness, and one reproducible external-review package. The closure verdict is `KEEP`, but not as “done cryptography.” The kept line is `goldilocks_128b_rewrite` with `review_state = candidate_under_review`: serious enough to keep and review, still not paper-equivalent, and still awaiting external cryptanalysis plus the public break-it phase.

## Context and Orientation

The current native backend lives in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). That file owns the backend manifest, parameter object, commitment and opening logic, transcript challenge schedule, fold verification, and the current `NativeSecurityClaim`. The active family is `goldilocks_128b_rewrite`. It is a candidate, not a final package.

The Hegemon-specific artifact layer lives in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs). That file defines the byte-level `NativeTxLeafArtifact` and `ReceiptRootArtifact` objects and binds backend parameters into verifier profiles and artifact versions. If the spec is vague here, everything above it is vague.

The benchmark and evidence surface lives in [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs). This file is the current place where the repo prints backend fingerprints and security-envelope data. It must grow into a reproducible evidence surface, not remain only a timing harness.

The runtime and import integration lives mainly in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs) and [node/src/substrate/service.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs). Those files already know how to route `receipt_root`, fail closed under `HEGEMON_REQUIRE_NATIVE=1`, and reject mismatched parameter profiles. This plan does not redesign those paths. It makes the underlying cryptographic package good enough that those paths can rely on it honestly.

The current design and methods state is captured in [DESIGN.md](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md) and [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md). Both documents currently say, in plain language, that the active family is `goldilocks_128b_rewrite` and that the backend is still an in-repo approximation. This plan must keep those documents synchronized with the actual implementation and must not let either file overclaim.

In this plan, a **message space** means the exact bytes or field elements that are committed, hashed into the transcript, folded, or serialized into an artifact. A **transcript** means the exact ordered byte string that the backend hashes to derive challenges. A **domain-separation label** means a fixed tag inserted into the transcript so two different protocol steps cannot accidentally share the same challenge material. A **security claim** means a code-derived statement of what the backend can honestly claim, broken into transcript soundness, opening hiding, commitment binding, composition loss, and the final floor. A **reference verifier** means a second implementation that parses and verifies the same artifacts without calling the production verifier logic. A **negative vector** means a deliberately malformed artifact that must fail verification. A **break-it phase** means a public, fixed-claims review period where outside reviewers are given a reproducible package, explicit targets, and a way to report breaks.

This plan concerns the cryptographic package itself. It does not promise to solve cold import, replace the shipping `InlineTx` path, or make the linear native verifier disappear. Those are separate system-level problems. The point here is narrower and harsher: either the native backend becomes a defensible 128-bit PQ package, or it stops being described that way anywhere in the repo.

## Plan of Work

Milestone 1 freezes the exact protocol surface in prose and in code. Add a new document at [docs/crypto/native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md). This document must define, in plain language and exact byte order, every object the backend consumes or emits: `BackendManifest`, `NativeBackendParams`, `PackedWitness`, `LatticeCommitment`, `CommitmentOpening`, `NativeTxLeafOpening`, `NativeTxLeafArtifact`, `ReceiptRootLeaf`, `ReceiptRootFoldStep`, `ReceiptRootArtifact`, `NativeSecurityClaim`, and every transcript input. The spec must include the message space, serialization width, domain-separation labels, challenge derivation order, canonical seed truncation rule, rejection conditions, and failure semantics for each object. At the same time, add one code-level `spec_digest` or `spec_id` constant to the backend manifest and surface it in benchmark JSON so the repo can prove which exact spec the current artifacts follow. The native artifact builders and verifiers must reject artifacts whose embedded spec identity does not match the active backend manifest.

Milestone 2 replaced the old loose “assumption label” with a real claim model. In [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), `NativeSecurityEnvelope` is now superseded by `NativeSecurityClaim`, which records transcript challenge contribution, opening hiding contribution, commitment binding contribution, fold-composition loss, the final floor, explicit `assumption_ids`, and `review_state`. Setup now rejects any parameter set whose requested claim exceeds the computed floor, and the bench exposes a direct claim-print command. In parallel, milestone 2 added [docs/crypto/native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md) and [docs/crypto/native_backend_attack_worksheet.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_attack_worksheet.md). The first document explains the algebraic and heuristic assumptions in plain language. The second document is the concrete attack ledger: each plausible break class, what code and vectors exercise it, and what claim it would invalidate.

Milestone 3 builds the independent verifier and fixed vectors. Add a new standalone workspace crate at [tools/native-backend-ref](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref) with its own `Cargo.toml` and `src/` tree. This crate must implement its own artifact parsers, transcript builder, challenge derivation, commitment-opening check, tx-leaf verification, and receipt-root verification. It must not call `superneo_backend_lattice::verify_opening`, `derive_fold_challenges`, `fold_commitments`, `verify_fold_proof`, or the production artifact decoders. It may share only a plain-data test-vector schema and non-executable constant tables if those tables are frozen in the spec. Add a fixed vector directory at [testdata/native_backend_vectors](/Users/pldd/Projects/Reflexivity/Hegemon/testdata/native_backend_vectors). The production backend must emit vectors there through one explicit command, and the reference verifier must consume them through one explicit command. The vector set must contain valid `NativeTxLeafArtifact` and `ReceiptRootArtifact` examples plus deliberately invalid companions that exercise each rejection rule.

Milestone 4 hardens the negative path and the parser boundary. Add exhaustive negative tests in the backend crates and reference verifier for truncated encodings, malformed length prefixes, noncanonical randomness seeds, mixed manifests, wrong `spec_digest`, wrong `fold_challenge_count`, domain-label drift, transcript-order drift, opening tampering, fold-row tampering, statement-commitment mismatch, and mixed parent/child parameter fingerprints. Add property tests that production and reference verifiers agree on all valid and invalid vectors. Add fuzz targets for every artifact boundary: native tx-leaf decode, receipt-root decode, commitment opening decode, reference verifier tx-leaf path, and reference verifier receipt-root path. Because cryptographic collisions are not the thing a local fuzz target can realistically find, the transcript-related fuzzing must focus on aliasing bugs: cases where two semantically different transcripts accidentally serialize to the same byte string because of missing separators, width drift, or tag reuse. This milestone is complete only when the fuzzers can run locally and in CI without false passes and when the negative vectors prove the rejection surface is real.

Milestone 5 makes the constant-time and canonicality story explicit. Add [docs/crypto/native_backend_constant_time.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_constant_time.md), which inventories every secret-bearing value on the prover side: witness data, spend secret material, Merkle witnesses, and opening randomness. Refactor the backend so secret-bearing code lives in narrow helper functions with fixed-iteration loops and explicit canonicality checks. Use constant-time equality where secret comparisons still exist. Then add a small statistical timing harness in [tools/native-backend-timing](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-timing) that runs two classes of secret inputs through the secret-bearing commitment/opening path and prints a Welch-style t-statistic for timing separation. This harness does not prove perfect constant-time behavior, but it gives the repo a mechanical check against gross secret-dependent timing drift. The plan is not satisfied by prose alone; it needs both the doc and the harness.

Milestone 6 builds the external-review package and the break-it kit. Add a new directory [audits/native-backend-128b](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b) with `CLAIMS.md`, `THREAT_MODEL.md`, `REVIEW_QUESTIONS.md`, `REPORT_TEMPLATE.md`, `KNOWN_GAPS.md`, and `BREAKIT_RULES.md`. Add one packaging script at [scripts/package_native_backend_review.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/package_native_backend_review.sh) that collects the exact spec, the current claim model, the valid and invalid vectors, the benchmark evidence, the current code fingerprint, and the reference verifier into one reproducible tarball. Add one verification script at [scripts/verify_native_backend_review_package.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/verify_native_backend_review_package.sh) that checks the tarball hash and reruns the reference verifier against the bundled vectors. The break-it rules must state exactly what counts as a win for a reviewer: forging an accepting artifact, violating binding or hiding assumptions under the claimed parameter model, producing diverging results between production and reference verifiers, finding an unguarded noncanonical encoding, or finding a transcript/domain-separation alias that changes semantics without changing the transcript bytes. This milestone is not the external review itself. It is the repository work required to make external review real instead of fictional.

Milestone 7 closes the loop. Rerun the native benchmark, rerun the reference verifier over the fixed vectors, rerun the negative suite and fuzz smoke tests, regenerate the review tarball, and then update [DESIGN.md](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md), [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md), [README.md](/Users/pldd/Projects/Reflexivity/Hegemon/README.md), and this plan. If the package now has an exact spec, a real claim model, a second verifier, the negative/fuzz/timing discipline, and an external-review package, then the docs may say “128-bit PQ candidate under external review” or “accepted 128-bit PQ package” depending on the review-state file. If any part is missing, the docs must say so plainly. If the claim model or outside review finds the construction wanting, the backend is killed instead of being softly rebranded.

## Concrete Steps

From the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`, execute the work in this order.

1. Write the exact spec and add the spec identity to the manifest and benchmark JSON.

       cargo test -p superneo-backend-lattice -p superneo-hegemon -p superneo-bench

2. Replace the current security envelope with the explicit claim model, add the security-analysis and attack-worksheet docs, and rerun:

       cargo test -p superneo-backend-lattice -p superneo-hegemon

3. Add the reference verifier crate and fixed vector generator/consumer, then prove cross-verifier agreement:

       cargo run -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1 --emit-review-vectors testdata/native_backend_vectors
       cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors
       cargo test -p native-backend-ref -p superneo-backend-lattice -p superneo-hegemon

4. Add negative vectors, parser tests, and fuzz targets, then run:

       cargo test -p native-backend-ref -p superneo-backend-lattice -p superneo-hegemon
       cargo +nightly fuzz run native_tx_leaf_artifact -- -max_total_time=60
       cargo +nightly fuzz run receipt_root_artifact -- -max_total_time=60

5. Add the constant-time/canonicality document and timing harness, then run:

       cargo run -p native-backend-timing --release

6. Build the external-review tarball and verify it:

       ./scripts/package_native_backend_review.sh
       ./scripts/verify_native_backend_review_package.sh

7. Rerun the final benchmark and native-only proof path, then update the docs with the final verdict:

       cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx
       cargo test -p consensus receipt_root_ -- --nocapture
       cargo test -p hegemon-node receipt_root -- --nocapture
       make node
       HEGEMON_BLOCK_PROOF_MODE=receipt_root HEGEMON_REQUIRE_NATIVE=1 HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

## Validation and Acceptance

Milestone 1 is accepted when the repo contains one exact spec document, benchmark JSON includes a `spec_digest` or equivalent identity field, and the native artifact path rejects mismatched spec identities.

Milestone 2 is accepted when the code can print one exact claim object that lists every assumption and loss term, when setup rejects any overclaim above the computed floor, and when the security-analysis and attack-worksheet docs describe the same claim model in plain language.

Milestone 3 is accepted when valid vectors pass in both verifiers, invalid vectors fail in both verifiers, and the reference verifier does not call the production verification helpers.

Milestone 4 is accepted when the negative vectors cover every documented rejection rule, when the fuzz targets run without crashes or silent acceptance of malformed artifacts, and when transcript-alias tests prove the domain-separation and width rules are not accidentally collapsing distinct transcripts into the same byte string.

Milestone 5 is accepted when the repo contains both the constant-time/canonicality document and a runnable timing harness, and when the harness does not show gross secret-dependent timing separation on the exercised prover-side paths. If the harness shows separation, the milestone fails until the code or claim is corrected.

Milestone 6 is accepted when the review package tarball can be reproduced locally, verified locally, and includes fixed claims, fixed vectors, fixed code fingerprints, and explicit break conditions.

Milestone 7 is accepted only when one of these two outcomes is written plainly into the docs:

- `KEEP`: the repo has the exact spec, exact claim model, exact vectors, exact reference verifier, negative/fuzz/timing discipline, and an external-review package ready or closed, so the docs may present the backend as a serious 128-bit PQ package with the appropriate review-state qualifier; or
- `KILL`: one or more of those requirements failed or the external-review state found a critical problem, so the docs must stop treating the line as the future path.

No other ending is allowed.

## Idempotence and Recovery

The documentation work is additive and safe to rerun. The vector directory and review-package scripts must be written so regenerating them replaces files deterministically instead of appending duplicates. If the spec changes in a way that changes artifact bytes, the spec identity must rotate, all vectors must be regenerated, and both verifiers must reject the old identity unless the old identity is intentionally preserved as a separate historical baseline. Never leave the repo in a state where docs, vectors, and claim code describe different protocol surfaces.

If the reference verifier disagrees with the production verifier, stop and resolve the discrepancy before doing more benchmark work. If fuzzing or the timing harness finds a serious issue, mark the review state as blocked immediately and update this plan, `DESIGN.md`, and `METHODS.md` before any further promotional language survives.

## Artifacts and Notes

The important artifacts this plan must produce are:

- [docs/crypto/native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md)
- [docs/crypto/native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md)
- [docs/crypto/native_backend_attack_worksheet.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_attack_worksheet.md)
- [docs/crypto/native_backend_constant_time.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_constant_time.md)
- [testdata/native_backend_vectors](/Users/pldd/Projects/Reflexivity/Hegemon/testdata/native_backend_vectors)
- [tools/native-backend-ref](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref)
- [tools/native-backend-timing](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-timing)
- [audits/native-backend-128b](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b)
- [scripts/package_native_backend_review.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/package_native_backend_review.sh)
- [scripts/verify_native_backend_review_package.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/verify_native_backend_review_package.sh)

The target benchmark and claim surface should eventually look like this in `superneo-bench` JSON:

    "native_backend_params": {
      "family_label": "goldilocks_128b_rewrite",
      "spec_digest": "<32-byte hex>",
      "commitment_scheme_label": "...",
      "challenge_schedule_label": "...",
      "maturity_label": "rewrite_candidate"
    },
    "native_security_claim": {
      "claimed_security_bits": 128,
      "transcript_soundness_bits": ...,
      "opening_hiding_bits": ...,
      "commitment_binding_bits": ...,
      "composition_loss_bits": ...,
      "soundness_floor_bits": ...,
      "assumption_ids": ["...", "..."],
      "review_state": "candidate_under_review"
    }

The review package directory should eventually contain a short tree like:

    audits/native-backend-128b/
      CLAIMS.md
      THREAT_MODEL.md
      REVIEW_QUESTIONS.md
      REPORT_TEMPLATE.md
      KNOWN_GAPS.md
      BREAKIT_RULES.md
      package.sha256

## Interfaces and Dependencies

In [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), define:

    pub struct NativeSecurityClaim {
        pub claimed_security_bits: u32,
        pub transcript_soundness_bits: u32,
        pub opening_hiding_bits: u32,
        pub commitment_binding_bits: u32,
        pub composition_loss_bits: u32,
        pub soundness_floor_bits: u32,
        pub assumption_ids: Vec<&'static str>,
        pub review_state: ReviewState,
    }

    pub enum ReviewState {
        Experimental,
        CandidateUnderReview,
        Accepted,
        Blocked,
        Killed,
    }

    impl NativeBackendParams {
        pub fn spec_digest(&self) -> [u8; 32];
        pub fn security_claim(&self) -> Result<NativeSecurityClaim>;
    }

The old `NativeSecurityEnvelope` is gone from the live benchmark and doc surface. The bench, docs, and acceptance logic now move only through `NativeSecurityClaim`.

In [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs), artifact bytes must carry the backend fingerprint and the `spec_digest`, and both builders and verifiers must reject mismatches.

In [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs), add:

    --emit-review-vectors <dir>

This flag must emit deterministic valid and invalid vectors keyed by backend fingerprint and spec digest.

In [tools/native-backend-ref](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref), define:

    pub fn verify_tx_leaf_bytes(artifact: &[u8], tx_context: &RefTxContext) -> anyhow::Result<RefVerificationReport>;
    pub fn verify_receipt_root_bytes(artifact: &[u8], block_context: &RefBlockContext) -> anyhow::Result<RefVerificationReport>;

These functions must not call the production verification helpers.

In [tools/native-backend-timing](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-timing), define one CLI that runs the secret-bearing prover path on two controlled input classes and prints a simple pass/fail summary around a Welch-style timing statistic.

Revision note (2026-03-27 / Codex): created this plan because the repo now has a 128-bit-target native candidate but still lacks the exact spec, explicit claim model, second verifier, negative/fuzz/timing discipline, and external-review package required to treat that target as a serious cryptographic claim.
