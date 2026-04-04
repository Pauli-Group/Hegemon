# Native Backend Reviewer Artifacts For Structured-Lattice Review

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, a professional reviewer will not need to reverse-engineer the native backend’s exact structured lattice instance by hand. The repo will export the exact flattened `A_flat` matrix for the active conservative instance, emit a machine-readable quotient/CRT model that explains where split-ring attacks might come from, run a reduced-instance search harness that targets the most obvious CRT/subfield/low-norm attack shapes, and publish the threshold arithmetic that says how much cryptanalytic improvement is needed before the commitment line becomes the active bottleneck or threatens the public `128`-bit claim.

The visible proof of success is a set of new `superneo-bench` commands and packaged review artifacts that a reviewer can run or inspect directly. They should be able to extract the exact matrix, inspect the quotient model, read the stronger inverse-CRT discussion, and see the reduced-instance attack report without writing their own helper code first.

## Progress

- [x] (2026-04-04 07:46Z) Re-read `DESIGN.md`, `METHODS.md`, the current native review-manifest / attack-model paths in `superneo-bench`, and the current package scripts.
- [x] (2026-04-04 07:52Z) Confirmed the existing review package already has the right home for new machine-readable reviewer artifacts.
- [x] (2026-04-04 07:55Z) Confirmed the existing cryptanalysis note is missing exactly the machine-usable pieces a reviewer would ask GPT to derive: exact `A_flat`, a structured reduced-instance harness, and a more explicit CRT-blowup table.
- [x] (2026-04-04 09:03Z) Extended `superneo-bench` with a code-derived flattened-instance exporter and structured-lattice report.
- [x] (2026-04-04 09:08Z) Extended `superneo-bench` with a reduced-instance CRT/subfield/low-norm search harness.
- [x] (2026-04-04 09:12Z) Strengthened the cryptanalysis note with the new inverse-CRT and threshold artifacts.
- [x] (2026-04-04 09:25Z) Wired the new artifacts into the review package and verification script.
- [x] (2026-04-04 09:28Z) Ran the new commands, rebuilt the reviewer package, and verified the full package path end to end.

## Surprises & Discoveries

- Observation: the inverse CRT map is not “all blowup, everywhere.” Balanced CRT pairs such as `(r_1, r_2) = (t, t)` map back to the small coefficient-basis element `(a, b) = (t, 0)`.
  Evidence: an exact finite search over `[-255,255]^2` found the minimum `max(|a|, |b|)` at the nonzero pair `(-1, -1)`, giving `(-1, 0)`.

- Observation: the relevant obstruction is therefore not “every bounded CRT pair blows up,” but “component-selective or component-imbalanced attacks blow up.” That is the attack shape we need to report explicitly.
  Evidence: the earlier one-component analysis was correct, but the stronger blanket statement is false.

- Observation: the exact active conservative flattened instance is large but still cheap to serialize deterministically.
  Evidence: the exported `flat_commitment_matrix_u64_le.bin` is `19,502,208` bytes for the `594 x 4104` instance, while the structured ring matrix binary is only `361,152` bytes.

- Observation: the first reviewer-facing reduced searches are cheap enough to ship in the default package build.
  Evidence: the packaged harness searched `624`, `531,440`, and `92,880` nonzero candidates respectively for the three initial attack families and found no nonzero kernel witness in the `108 x 108` reduced instance.

## Decision Log

- Decision: put the new reviewer artifacts into `superneo-bench` and the existing review package, not into an ad hoc script.
  Rationale: reviewers already receive `attack_model.json`, `message_class.json`, and `claim_sweep.json` from that path. The new artifacts belong next to them so the review surface remains one coherent package.
  Date/Author: 2026-04-04 / Codex

- Decision: export both the exact flattened matrix and the smaller structured ring matrix.
  Rationale: reviewers want `A_flat`, but the ring/block structure is exactly what they will try to exploit. Shipping only the flattened matrix would hide the useful algebraic view.
  Date/Author: 2026-04-04 / Codex

- Decision: make the reduced-instance harness explicit about the attack families it tests rather than pretending it is exhaustive cryptanalysis.
  Rationale: a small harness is valuable when it clearly says what it searched. It becomes misleading when it suggests that a clean run means “no attack exists.”
  Date/Author: 2026-04-04 / Codex

## Outcomes & Retrospective

Implemented. The repo now exposes the exact conservative structured-lattice instance and the first reviewer-facing attack spikes directly through `superneo-bench` and the review package.

New reviewer commands:

    cargo run -p superneo-bench -- --print-native-structured-lattice-model
    cargo run -p superneo-bench -- --export-native-flattened-sis-instance /tmp/native-flat
    cargo run -p superneo-bench -- --run-native-reduced-cryptanalysis-spikes

Concrete outputs:

- `structured_lattice_model.json` now reports the exact active conservative dimensions, the `GoldilocksFrog` CRT model, the balanced-vs-imbalanced inverse-CRT table, and threshold rows for `305`, `256`, `192`, and `128` bits.
- `structured_lattice/flat_commitment_matrix_u64_le.bin` exports the exact `594 x 4104` flattened matrix in row-major little-endian `u64`.
- `structured_lattice/ring_commitment_matrix_u64_le.bin` exports the exact `11 x 76` ring matrix in coefficient-packed row-major little-endian `u64`.
- `reduced_cryptanalysis_spikes.json` records the initial CRT/subfield/sparse reduced searches over the first `108 x 108` flattened slice.

Stable arithmetic results now shipped in the package:

- `min_one_component_max_coeff_abs = 8589934591`
- `min_nonzero_component_difference_max_coeff_abs = 8589934591`
- `min_abs_x27_coeff_for_nonzero_component_difference = 8589934591`
- Threshold haircuts from the current `3294` block-size line: `2143` to undercut `305`, `2327` to undercut `256`, `2569` to undercut `192`, and `2810` to undercut `128`.

Validation completed:

- `cargo check -p superneo-bench`
- `cargo build -p superneo-bench`
- `./scripts/package_native_backend_review.sh`
- `./scripts/verify_native_backend_review_package.sh`

The rebuilt package hash is:

    fdb9c7200a72a54c27bf45f8b4068f2a14450ec5618be402fa899468c26a3f58  native-backend-128b-review-package.tar.gz

## Context and Orientation

The review package is assembled by [scripts/package_native_backend_review.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/package_native_backend_review.sh) and verified by [scripts/verify_native_backend_review_package.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/verify_native_backend_review_package.sh). The source of truth for the machine-readable attack-model artifacts is [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs), which already emits `review_manifest.json`, `attack_model.json`, `message_class.json`, and `claim_sweep.json`.

The exact matrix generation logic lives in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). The exact live message-class and tx-leaf relation live in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs). The current human-readable quotient/SIS discussion is in [docs/crypto/native_backend_cryptanalysis_note.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_cryptanalysis_note.md).

In this plan, “flattened instance exporter” means a command that emits the exact active conservative matrix and enough metadata to interpret it without reverse-engineering the code. In this plan, “reduced-instance search harness” means a command that takes small reviewer-interesting slices of the structured matrix and runs direct searches for the easiest CRT/subfield/low-norm patterns. The harness is not expected to replace real cryptanalysis; it is expected to kill the cheapest objections quickly and reproducibly.

## Plan of Work

First, add a machine-readable structured-lattice report and exporter to `superneo-bench`. The report should include the exact active conservative dimensions, the exact ring quotient model, the explicit CRT constants used in the note, the threshold table for `305`, `256`, `192`, and `128` bits, and pointers to the exported matrix files. The exporter should emit both the exact ring commitment matrix and the exact flattened coefficient-space matrix, plus metadata describing row-major order, dimensions, modulus, and how the flattening was formed.

Second, add a reduced-instance search harness. The initial search families should be narrow and honest: one-component CRT lifts, component-imbalanced CRT lifts, and low-support bounded vectors over small reduced slices of the active structured matrix. The output should report what was searched, what bounds were used, how many candidates were tested, and whether any nonzero witness was found.

Third, strengthen `docs/crypto/native_backend_cryptanalysis_note.md` with the new nuance about balanced versus imbalanced CRT pairs and with the explicit threshold table that the machine-readable report also emits.

Fourth, package the new artifacts and extend the package verification script so the reviewer bundle checks for them and validates a few stable facts.

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Implementation will add new `superneo-bench` commands alongside the existing review-surface commands:

    cargo run -p superneo-bench -- --print-native-structured-lattice-model
    cargo run -p superneo-bench -- --export-native-flattened-sis-instance /tmp/native-flat
    cargo run -p superneo-bench -- --run-native-reduced-cryptanalysis-spikes

Packaging acceptance will include:

    ./scripts/package_native_backend_review.sh
    ./scripts/verify_native_backend_review_package.sh

## Validation and Acceptance

This work is accepted when all of the following are true:

1. `superneo-bench` can emit a machine-readable structured-lattice model for the active family.
2. `superneo-bench` can export the exact active conservative ring matrix and flattened `A_flat` matrix.
3. `superneo-bench` can run a reduced-instance attack harness and produce a machine-readable result.
4. The cryptanalysis note explains the balanced-versus-imbalanced CRT nuance and includes the explicit threshold arithmetic.
5. The review package includes the new artifacts and its verification script checks for them.

## Idempotence and Recovery

The new artifacts are additive. Re-running the exporter should overwrite its output directory deterministically. Re-running the package script should rebuild the package deterministically except for the existing worktree fingerprint input, which already reflects local state. If any new artifact format changes, the verification script must be updated in the same change.

## Artifacts and Notes

Current local arithmetic that shaped the plan:

    one-component shortcut: blocked inside [-255,255]
    balanced pair example: (-1, -1) -> (a, b) = (-1, 0)

This means the missing artifact is not a blanket “inverse CRT always blows up” claim. It is a more precise report about which CRT attack shapes do and do not survive the coefficient bound.

## Interfaces and Dependencies

This plan will touch:

- `circuits/superneo-bench/src/main.rs`
- `circuits/superneo-bench/Cargo.toml` only if new serialization dependencies are truly needed
- `circuits/superneo-backend-lattice/src/lib.rs` for any public export helpers
- `docs/crypto/native_backend_cryptanalysis_note.md`
- `docs/crypto/native_backend_security_analysis.md` if the new artifact deserves a link there
- `scripts/package_native_backend_review.sh`
- `scripts/verify_native_backend_review_package.sh`

The new machine-readable outputs should be JSON for metadata and reports, with binary files only where the exact matrix would be impractical in JSON. Any binary matrix file must ship with a JSON metadata file describing dimensions, modulus, byte order, row-major order, and file names.

Revision note: created on 2026-04-04 to turn the reviewer-preparation suggestions into concrete repo artifacts rather than leaving them as advice in chat.
