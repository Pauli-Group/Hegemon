# Lean-Verified Hegemon Core

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md`. The active user goal is to build a Lean-verified Hegemon core where every production-critical validity rule is represented by an executable Lean specification, every exported security claim is backed by a named theorem that builds with no `sorry`, `admit`, or undeclared axioms, and release Rust code is forced to conform to that Lean kernel through generated vectors, differential tests, and eventually verified or extracted implementation paths. The final goal also requires validation on `hegemon-dev`.

## Purpose / Big Picture

The repository currently has a claims ledger, a blueprint DAG, reference vectors, and TLA+ model inventory. That is not enough. This plan starts the real machine-checked layer: a pinned Lean 4 project under `formal/lean` with executable protocol specifications and named theorems. The first milestone proves a concrete safety property for inbound bridge replay: after a replay key is accepted and inserted into the consumed set, the same key cannot be accepted again.

After this milestone, a contributor can run `bash scripts/check_lean_formal.sh` from the repository root and observe Lean building the theorem files while the script rejects `sorry`, `admit`, and declared `axiom` text. The existing `bash scripts/check_formal_core.sh` gate will call the Lean gate, so CI/release validation starts depending on a machine-checked proof artifact rather than only JSON metadata.

## Progress

- [x] (2026-06-06T06:43:00Z) Re-read `DESIGN.md`, `METHODS.md`, the current formal-core scripts, and the current branch state.
- [x] (2026-06-06T06:43:00Z) Confirmed local `lean`, `lake`, and `elan` are not installed.
- [x] (2026-06-06T06:58:00Z) Added a pinned Lean project under `formal/lean` with `leanprover/lean4:v4.30.0`.
- [x] (2026-06-06T06:58:00Z) Added an executable bridge replay specification and theorems `Hegemon.Bridge.accept_inserts_key` and `Hegemon.Bridge.accept_prevents_duplicate`.
- [x] (2026-06-06T06:58:00Z) Added `scripts/check_lean_formal.sh`; it builds the explicit `Hegemon` Lean target, directly checks the replay Lean file, and rejects `sorry`, `admit`, and declared axioms.
- [x] (2026-06-06T06:58:00Z) Wired the Lean gate into `scripts/check_formal_core.sh` as a mandatory step 3 of 10.
- [x] (2026-06-06T06:58:00Z) Updated documentation and formal-security metadata so `bridge.inbound-replay-state` points at the named Lean theorem evidence.
- [x] (2026-06-06T06:58:00Z) Installed local `elan`, ran `bash scripts/check_lean_formal.sh`, and ran `bash scripts/check_formal_core.sh`; both passed locally.
- [x] (2026-06-06T07:08:00Z) Validated branch tip `326a1c7d` on `hegemon-dev`; the full 10-step formal-core gate passed after installing elan and downloading the pinned Lean `v4.30.0` toolchain.
- [x] (2026-06-06T18:17:00Z) Extended the Lean bridge kernel with canonical `BridgeMessageV1` byte encoding, two-phase inbound replay staging/import transitions, and theorems `stage_prevents_duplicate_pending`, `import_prevents_reimport`, and `import_prevents_restaging`.
- [x] (2026-06-06T18:17:00Z) Added the Lean executable `gen_bridge_vectors` and a `protocol-kernel` conformance test that checks generated Lean bridge encoding/replay examples against production helpers when `HEGEMON_LEAN_BRIDGE_VECTORS` is set.
- [x] (2026-06-06T18:17:00Z) Moved native bridge duplicate-replay validation to the shared `protocol-kernel::InboundReplayState` helper, so node staging and block-validation paths use the helper checked by Lean-generated vectors.
- [x] (2026-06-06T18:30:00Z) Validated branch tip `972b6933` on `hegemon-dev`: the 11-step formal-core gate passed, `make node` rebuilt the release binary, `hegemon-node.service` restarted cleanly, smoke RPC checks passed, mining advanced from height `402479` to `402481`, and `scripts/test-node.sh wallet-send` passed.
- [x] (2026-06-06T18:44:00Z) Added shared Lean byte helpers plus a shielded nullifier-state kernel proving zero rejection, duplicate pending rejection, and spent-nullifier rejection.
- [x] (2026-06-06T18:44:00Z) Added `gen_shielded_vectors` and a `protocol-shielded-pool` conformance test that checks generated Lean nullifier stage/import examples against production `NullifierState` when `HEGEMON_LEAN_SHIELDED_VECTORS` is set.
- [x] (2026-06-06T18:44:00Z) Moved native nullifier staging, block validation, state replay/import, and author preview checks to the shared `protocol-shielded-pool::NullifierState` helper.
- [x] (2026-06-06T18:50:00Z) Validated branch tip `0e6e6030` on `hegemon-dev`: the expanded 11-step formal-core gate passed with 10 claims and both generated conformance tests, `make node` rebuilt the release binary, `hegemon-node.service` restarted cleanly, smoke RPC checks passed, mining advanced from height `402561` to `402564`, and `scripts/test-node.sh wallet-send` passed.

## Surprises & Discoveries

- Observation: The current repo has no Lean project and no Lean toolchain files.
  Evidence: `rg --files | rg '(^formal|lean|lake|\\.lean$)'` only found existing formal-core JSON/scripts and no `.lean`, `lakefile.lean`, or `lean-toolchain` files.

- Observation: Lean/Lake/Elan are not installed locally.
  Evidence: `command -v lean`, `command -v lake`, and `command -v elan` returned no paths.

- Observation: Plain `lake build` was too weak as evidence for this initial project.
  Evidence: The first run printed `Build completed successfully (0 jobs)`. Running `lake build Hegemon` compiled `Hegemon.Bridge.Replay` and `Hegemon`, reporting 4 jobs. The script now builds the explicit `Hegemon` target and directly elaborates `Hegemon/Bridge/Replay.lean`.

- Observation: The first actual Lean theorem is now part of the same formal-core gate as the JSON/vector checks.
  Evidence: `bash scripts/check_formal_core.sh` reported `[3/10] Checking Lean formal proof kernel`, `Build completed successfully (4 jobs)`, then `claims = 9`, `production_eligible = 7`, `nodes = 9`, and `production_nodes = 7`.

- Observation: The same Lean theorem gate works on `hegemon-dev` from a fresh Lean toolchain install.
  Evidence: Remote validation at commit `326a1c7d` downloaded Lean `v4.30.0`, built `Hegemon.Bridge.Replay`, built `Hegemon`, and completed the full `bash scripts/check_formal_core.sh` gate.

- Observation: Generated Lean vectors can now be checked against production Rust helpers.
  Evidence: `lake exe gen_bridge_vectors` emits two bridge encoding examples and four replay-state examples; the formal-core gate runs `HEGEMON_LEAN_BRIDGE_VECTORS=<generated-json> cargo test -p protocol-kernel lean_generated_bridge_vectors_match_production -- --nocapture`.

- Observation: `hegemon-dev` can run the new proof/conformance gate and the rebuilt node stays healthy.
  Evidence: Remote `bash scripts/check_formal_core.sh` passed all 11 steps at `972b6933`; remote `make node` completed; `sudo systemctl restart hegemon-node.service` returned an active service; `scripts/smoke-test.sh` passed against `http://127.0.0.1:9944`; a 25-second height sample advanced from `402479` to `402481`; `scripts/test-node.sh wallet-send` passed.

- Observation: The second Lean-backed production slice now covers native shielded nullifier state.
  Evidence: Local `bash scripts/check_lean_formal.sh` built `Hegemon.Shielded.Nullifier` and `gen_shielded_vectors`; local `HEGEMON_LEAN_SHIELDED_VECTORS=<generated-json> cargo test -p protocol-shielded-pool lean_generated_nullifier_vectors_match_production -- --nocapture` passed; local `cargo test -p hegemon-node submit_action_stages_and_imports_shielded_transfer --lib --no-default-features -- --nocapture` passed after the native node switched to the shared helper.

- Observation: `hegemon-dev` can run the nullifier proof/conformance gate and the rebuilt node continues mining.
  Evidence: Remote `bash scripts/check_formal_core.sh` at `0e6e6030` reported `claims = 10`, `production_eligible = 8`, `falsification_cases = 16`, and both generated Rust conformance tests passed; remote `make node` completed; `sudo systemctl restart hegemon-node.service` returned an active service; `scripts/smoke-test.sh` passed; a 25-second height sample advanced from `402561` to `402564`; `scripts/test-node.sh wallet-send` passed.

## Decision Log

- Decision: Pin Lean to `leanprover/lean4:v4.30.0`.
  Rationale: Upstream Lean 4 reports `v4.30.0` as the latest release on 2026-05-26. Pinning a specific version avoids the drift of `stable`.
  Date/Author: 2026-06-06 / Codex.

- Decision: Start with bridge replay safety rather than proof-system soundness.
  Rationale: Replay safety is production-critical, finite, and already close to the current bridge claim surface. It can be represented as an executable Lean state transition with a real theorem today. Full SmallWood/PCS soundness is a larger mathematical project and should come after the Lean toolchain and theorem gate are real.
  Date/Author: 2026-06-06 / Codex.

- Decision: Keep cryptographic hashes abstract in the first Lean milestone.
  Rationale: The no-replay theorem depends on equality of replay keys and consumed-set state, not on BLAKE3 cryptographic security. Hash-function implementation equivalence will be a later milestone tied to generated vectors and/or verified code extraction.
  Date/Author: 2026-06-06 / Codex.

- Decision: Add Lean-generated conformance vectors before attempting a larger proof-system theorem.
  Rationale: The active goal requires release Rust to be forced toward the Lean kernel. Generated bridge encoding and replay-state examples are a narrow but concrete differential gate, and they expose production drift faster than another prose claim.
  Date/Author: 2026-06-06 / Codex.

- Decision: Mechanize shielded nullifier state before full MASP balance.
  Rationale: Nullifier uniqueness is the production anti-double-spend invariant and is small enough to prove exactly in Lean today. Full per-asset balance conservation and AIR/proof-system soundness remain larger follow-on kernels.
  Date/Author: 2026-06-06 / Codex.

## Outcomes & Retrospective

This plan is in progress. The expected first outcome is not a complete verified Hegemon, but it must be a real Lean theorem that builds under a pinned toolchain and becomes part of the formal-core gate.

## Context and Orientation

The active branch is `codex/formal-blueprint-dag`. The current formal gate is `scripts/check_formal_core.sh`. It checks JSON claims, a blueprint DAG, bridge reference vectors, native backend vectors, and optional TLA+ model checkers. The current gap is that no claim is backed by a Lean theorem.

The first Lean project will live under `formal/lean`. The project will be deliberately small and dependency-light: no Mathlib dependency for the first theorem, because the theorem only needs Lean's core `List` library and decidable equality. The file `formal/lean/Hegemon/Bridge/Replay.lean` will define a `ReplayKey` as a byte list, a `ReplayState` as a consumed-key list, an executable `accept` transition, and the theorem that accepting a key prevents accepting it again in the resulting state.

The new script `scripts/check_lean_formal.sh` will build the Lean project with `lake build`, then scan Lean sources for forbidden proof placeholders or declared axioms. This scan is not the proof itself; it is a guard that prevents vacuous theorem files from passing.

## Plan of Work

First, create `formal/lean/lean-toolchain`, `formal/lean/lakefile.lean`, and `formal/lean/Hegemon/Bridge/Replay.lean`. The Lean file will define the executable replay-state kernel and prove that once a key has been inserted by `accept`, a second `accept` for the same key returns `none`.

Second, create `scripts/check_lean_formal.sh`. It will add `$HOME/.elan/bin` to PATH when present, require `lake`, run `lake build` in `formal/lean`, and reject forbidden text in `.lean` files: `sorry`, `admit`, and lines beginning with `axiom`.

Third, wire `scripts/check_formal_core.sh` to call `scripts/check_lean_formal.sh` before the JSON/vector checks complete. This makes Lean proof compilation part of the existing release-facing command.

Fourth, update docs and metadata. `DESIGN.md`, `METHODS.md`, `docs/SECURITY_REVIEWS.md`, and `config/formal-security-blueprint.json` should state that the bridge replay claim now has a named Lean theorem. They must not say every production claim is Lean-proved yet.

## Concrete Steps

All commands run from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Install Lean tooling if missing:

    curl https://elan.lean-lang.org/elan-init.sh -sSf | sh -s -- -y --default-toolchain none
    export PATH="$HOME/.elan/bin:$PATH"

Build the Lean project:

    bash scripts/check_lean_formal.sh

Then run the full formal gate:

    bash scripts/check_formal_core.sh

## Validation and Acceptance

The first milestone is accepted when:

1. `bash scripts/check_lean_formal.sh` exits 0 and runs `lake build`.
2. `bash scripts/check_formal_core.sh` exits 0 and includes a mandatory Lean proof step.
3. `formal/lean/Hegemon/Bridge/Replay.lean` contains a named theorem proving duplicate replay rejection after acceptance.
4. The Lean source contains no `sorry`, `admit`, or declared `axiom`.
5. `hegemon-dev` can fetch the branch tip and run the same formal-core gate.

This does not complete the full active goal. It is the first machine-checked theorem and gate needed to make the goal real.

Observed local output on 2026-06-06:

    [3/10] Checking Lean formal proof kernel
    Build completed successfully (4 jobs).
    [6/10] Checking formal security claims ledger
    {
      "claims": 9,
      "passed": true,
      "production_eligible": 7,
      "residual_risks": 2
    }
    [7/10] Checking formal security blueprint DAG
    {
      "edges": 13,
      "falsification_cases": 13,
      "nodes": 9,
      "passed": true,
      "production_nodes": 7
    }

## Idempotence and Recovery

Installing `elan` with `--default-toolchain none` is safe to repeat. The Lean project pins its toolchain in `formal/lean/lean-toolchain`, so running `lake build` repeatedly should use the same Lean version. If toolchain download fails, rerun the command after network recovery. If `lake build` fails, fix the Lean file and rerun `bash scripts/check_lean_formal.sh`.

## Artifacts and Notes

Expected files:

    formal/lean/lean-toolchain
    formal/lean/lakefile.lean
    formal/lean/Hegemon/Bridge/Replay.lean
    scripts/check_lean_formal.sh
    scripts/check_formal_core.sh

## Interfaces and Dependencies

In `formal/lean/Hegemon/Bridge/Replay.lean`, define:

    abbrev ReplayKey := List UInt8

    structure ReplayState where
      consumed : List ReplayKey

    def ReplayState.accept (state : ReplayState) (key : ReplayKey) : Option ReplayState

    theorem accept_prevents_duplicate :
      ReplayState.accept state key = some next ->
      ReplayState.accept next key = none

Revision note 2026-06-06T06:43:00Z: Created this plan after confirming the repo has no Lean project and the local environment has no Lean tooling installed.

Revision note 2026-06-06T06:58:00Z: Recorded the first pinned Lean project, replay-state theorem, Lean shell gate, formal-core integration, metadata/doc updates, and passing local validation.

Revision note 2026-06-06T07:08:00Z: Recorded successful `hegemon-dev` validation of the pinned Lean theorem gate at commit `326a1c7d`.

Revision note 2026-06-06T18:17:00Z: Added Lean bridge encoding, two-phase replay theorems, generated Lean conformance vectors, a production `InboundReplayState` helper, and a protocol-kernel conformance test wired into the formal-core gate. Remote validation is still pending for this revision.

Revision note 2026-06-06T18:30:00Z: Recorded `hegemon-dev` validation for commit `972b6933`, including formal-core, release rebuild, service restart, smoke RPC checks, mining height advance, and wallet submission compatibility.

Revision note 2026-06-06T18:44:00Z: Added shared Lean byte helpers, a shielded nullifier-state Lean kernel, generated shielded conformance vectors, a production `NullifierState` helper, and native-node use of that helper. Remote validation is still pending for this revision.

Revision note 2026-06-06T18:50:00Z: Recorded `hegemon-dev` validation for commit `0e6e6030`, including formal-core, release rebuild, service restart, smoke RPC checks, mining height advance, and wallet submission compatibility.
