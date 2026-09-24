# Build and run a disk-bounded standalone-proof autoresearch campaign

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this file in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon needs an optimizer that can run many falsifiable proof-system experiments without confusing a small weak-profile proof with a production-qualified proof. After this work, a researcher can describe one candidate as data, run it through the exact full Pay1x2 gates, record deterministic proof bytes and host costs in a tamper-evident ledger, compare the Pareto frontier, and automatically clean every disposable build directory. The optimizer never activates consensus and never treats aggregation, a geometry proxy, or a self-asserted security label as a valid transaction proof.

The first campaign starts from the measured all-private Binius64 prototype: a 350,800-byte proof plus a 12-byte envelope for the full prospective V5/Delta Pay1x2 relation. That result is a useful size baseline but remains in the prototype lane because the pinned backend uses a 96-bit query budget, SHA-256 proof commitments, and GF(2^128). The target lane requires one unchanged standalone proof, SHAKE256-512 proof hashing, wide algebraic challenges, complete zero knowledge, and a composed post-quantum security result of at least 128 bits.

## Progress

- [x] (2026-08-19 14:16Z) Audited the measured full Pay1x2 backend, all-private patch runner, exact verification report, strict security scaffold, current dirty worktree, and host free space.
- [x] (2026-08-19 14:31Z) Implemented the external autoresearch controller, campaign contract, upstream-only patch policy, baseline candidate, hash-chained ledger, separate Pareto reporting, and UUID ownership markers.
- [x] (2026-08-19 15:26Z) Added 15 standard-library tests covering exact result parsing, invariant rejection, lane separation, ledger tampering and strict-self-attestation rejection, nonblocking locks, the confirmed git-header path bypass, seed substitution, the non-lowerable reserve, a Seatbelt-contained tiny live run, and marked stale-run cleanup; all pass.
- [x] (2026-08-19 14:53Z) Sealed the campaign digest, moved immutable artifacts out of candidate control, added post-apply tree enumeration, a sanitized environment, network-denied/run-root-only macOS Seatbelt policy, process-group RSS accounting, exact `proof + 12` and 478-byte statement checks, and two-live-run strict completion.
- [x] (2026-08-19 14:53Z) Ran the no-prover baseline import and controller smoke path. The ledger verifies and reports 350,812 bytes only in the prototype lane; no Cargo target or owned run directory remains. `doctor` verifies the sandbox and pinned source but currently refuses a heavy run because 29,960,568,832 free bytes is just below the 28 GiB admission threshold.
- [x] (2026-08-19 14:57Z) Activated Codex task `01a01a5b-e019-70f2-a184-bfcdfe05e09b` (“Hegemon proof-size autoresearch”) with `gpt-5.6-luna` at `max` reasoning and the sealed external-evaluator prompt.
- [x] (2026-08-19 14:58Z) Recorded the first supervised snapshot: Luna ran `doctor`, observed 29,890,535,424 free bytes below the 30,064,771,072 admission threshold plus expected nested-sandbox Seatbelt denial, and correctly started no Cargo build or prover. It is preparing only `/private/tmp/hegemon-proof-autoresearch-inbox/luna-mask-cocommit-v1.{json,patch}` until admission clears.
- [x] (2026-08-19 15:26Z) Split candidate handling into trusted preparation, compile-only, and exact-binary runtime profiles. Compile and runtime now default-deny host reads, with only the owned closure, offline Cargo/Rust closure, exact executable, temporary paths, and required operating-system files visible. Smoke tests prove an outside secret cannot be read in either phase and that candidate runtime cannot fork, exec another binary, create a launchd job, signal another process, or escape its process group.
- [x] (2026-08-19 15:26Z) Re-seeded and verified the baseline ledger against the final sealed campaign. It contains one prototype record at 350,800 proof / 350,812 envelope bytes, with entry digest `54fd0b847f63ae7aa9f2ea7414d524d1ac2a9996b089759a6760f49f9cc919d8`; the strict lane remains empty.
- [x] (2026-08-19 15:26Z) Luna delivered the first mechanically regenerated candidate: mask/private-oracle co-commitment. Its manifest SHA-256 is `89bb48b18ef2708a0280f4b21bf874adaea3f0f35da7fd34edea3013d1fcccb3`, its patch SHA-256 is `65489ee26d7ca96338dbecbb627d21de69d9514e64fbd8f310e2d4fbb6961c44`, and independent `git apply --check` passes both the pinned source and the exact post-baseline tree. It remains deliberately unmeasured because `doctor` reports 29,820,055,552 free bytes, 244,715,520 below admission.
- [x] (2026-08-19 15:31Z) Closed the remaining same-UID control path by denying runtime `process-info*`; the live sentinel smoke returns denial while the exact candidate runtime remains executable. Final adversarial review reports GO for isolated Luna proposal generation and the supervised prototype lane with no remaining P0. Remaining P1 boundaries are sampled rather than quota-backed disk caps, candidate-linked prototype measurements, and candidate-manifest-owned seed declaration; strict admission already treats all three as non-authoritative.
- [x] (2026-08-19 19:34Z) Ran Luna's regenerated `luna-precommit-cocommit-v2` through the sealed evaluator. The exact full 478-byte-statement/40-permutation/1,883,192-row Pay1x2 proof and every frozen mutation, composition, carry, range, action, envelope, and fresh-forgery gate passed. The canonical result is 309,072 proof bytes and 309,084 envelope bytes, 41,728 bytes (11.89%) below baseline, with 213 actions per 64 MiB block (3.55 TPS), 1.98 seconds proving, 175 ms verification, and 7,352,647,680 bytes peak RSS. The ledger has two valid prototype Pareto entries and head `bfe43a55f9f5540004af07abd37c93c64ff6edc01433eb042b46c60ae5e2c726`; strict remains empty.
- [x] (2026-08-19 19:44Z) Re-ran `doctor` after cleanup. The pinned source is clean, the sandbox smoke is operational, free space is 30,637,985,792 bytes (28.53 GiB), the 28 GiB admission gate is open with narrow headroom, and the 20 GiB abort floor remains enforced. Luna 5.6/Max continues proposal-only against the new frontier; the sealed evaluator is idle and ready for the next reviewed candidate.

## Surprises & Discoveries

- Observation: The repository already contains most of the expensive experimental substrate; the missing piece is a disciplined search loop rather than another proof backend wrapper.
  Evidence: `prototypes/standalone-shake256-binius/all-private-patch/run-full-pay1x2.sh` already hash-guards the complete source closure, uses a 16 GiB free-space reserve, builds in `/private/tmp`, tests the composed verifier, sweeps rates 2/3/4, and deletes exact temporary sources and targets.

- Observation: The 350,800-byte best result is not a strict-security baseline.
  Evidence: `prototypes/standalone-shake256-binius/all-private-patch/full-pay1x2-measurement-2026-08-19.json` records `query_security_bits = 96`, SHA-256 proof hashing, GF(2^128), incomplete QROM accounting, and no established end-to-end zero knowledge.

- Observation: Textual patch allowlisting is insufficient because `git apply` follows `---`/`+++` paths rather than trusting the `diff --git` label.
  Evidence: Adversarial review produced a patch whose allowlisted `diff --git` header targeted `crates/ip/src/lib.rs` while its apply headers targeted root `Cargo.toml`. The controller now checks all headers and the runner commits the post-baseline disposable tree, applies the candidate, and enumerates actual changed paths/modes before any build.

- Observation: The strict arithmetic calculator is not an independent proof parser or composed verifier.
  Evidence: Strict admission is explicitly unavailable in `campaign.json` and `_run_authority_if_needed` returns false until a separate sealed HGSP/action/statement verifier is implemented. Candidate security booleans cannot promote a result.

## Decision Log

- Decision: Optimize one self-contained wallet-generated proof per transaction; forbid aggregates, sidecars, proof caches, geometry proxies, reduced-round SHAKE, removed Boolean constraints, and off-proof semantic checks from the eligible search space.
  Rationale: Hegemon requires the same canonical proof to survive RPC, relay, mempool, blocks, sync, reorg, and fresh-node replay. Moving validity elsewhere is an architecture change, not proof-size optimization.
  Date/Author: 2026-08-19 / Codex

- Decision: Keep strict and prototype results in separate Pareto lanes, with strict qualification dominating every prototype result regardless of byte size.
  Rationale: A weak proof cannot win the campaign by being smaller. Prototype measurements remain useful for locating byte levers but cannot satisfy the user's security goal.
  Date/Author: 2026-08-19 / Codex

- Decision: Use a model-driven outer loop and a deterministic local evaluator rather than embedding an API key or autonomous model client in the repository.
  Rationale: The requested Luna task supplies hypotheses and code changes; the local evaluator supplies reproducible truth, bounded resource use, and a small ledger. This avoids credentials, hidden cloud state, and token-heavy duplicate orchestration.
  Date/Author: 2026-08-19 / Codex

- Decision: Permit only one experiment process at a time, require 28 GiB free to start a heavy run, and make 20 GiB a non-lowerable in-run reserve.
  Rationale: The full proof uses about 5.5 GiB peak resident memory, prior disposable targets were hundreds of MiB, and free space fell by roughly 4 GiB during read-only setup because another process shares the APFS volume. A global lock, admission margin, and hard reserve prevent concurrent agents from exhausting storage.
  Date/Author: 2026-08-19 / Codex

- Decision: Run Luna in a separate Codex worktree and accept only candidate manifests and patch bytes through the mode-0700 `/private/tmp/hegemon-proof-autoresearch-inbox`; evaluate them with the sealed controller in the original worktree.
  Rationale: Candidate code and the research model must not be able to rewrite the evaluator, campaign, ledger, or immutable Hegemon semantic closure. The candidate itself additionally executes under Seatbelt with no network and only its UUID run root writable.
  Date/Author: 2026-08-19 / Codex

## Outcomes & Retrospective

The local campaign is operational. The sealed ledger contains two verified prototype Pareto points: the 350,812-byte all-private baseline and Luna's 309,084-byte co-commit envelope. The new winner raises provisional weak-profile capacity from 188 to 213 actions per 64 MiB block, or from 3.13 to 3.55 TPS at 60-second blocks. Luna 5.6/Max remains active in proposal-only mode; the sealed evaluator is idle, globally serialized, and admitted by the current disk gate. No production route or consensus code was activated. The strict lane remains empty because SHAKE256-512 proof hashing, wide challenges, complete exact-relation zero knowledge, composed QROM/PQ128 evidence, independent artifact verification, formal refinement, and two clean reproductions are not established.

## Context and Orientation

The executable scalar relation lives under `circuits/standalone-shake256-prototype/` and `circuits/standalone-pay1x2-relation-prototype/`. The authoritative prospective action-to-statement projection lives under `circuits/standalone-pay1x2-statement-prototype/`. The exact proof envelope lives under `circuits/standalone-proof-envelope-prototype/`. The complete Binius64 circuit and composed verifier live under `prototypes/standalone-shake256-binius/pay1x2-backend/`. The all-private optimization is an applyable patch and disposable runner under `prototypes/standalone-shake256-binius/all-private-patch/`.

The new directory `prototypes/standalone-shake256-binius/autoresearch/` is an experiment controller, not a proof system. A candidate is a JSON file containing an identifier, parent, falsifiable hypothesis, immutable relation claims, and at most one narrow patch; the campaign, not the candidate, owns the immutable artifact closure. A trial is one execution of that candidate. The ledger is an append-only JSON-lines file in which every record commits to the prior record hash. A Pareto frontier contains candidates that are not simultaneously worse in proof bytes, verification time, proving time, and peak memory than another candidate in the same security lane.

The controller accepts final JSON emitted by the existing benchmark harness or the frozen full-measurement schema. It validates all named semantic, canonicality, action-projection, envelope, fresh-forgery, carry, range, and mutation gates. It then classifies the result as `strict`, `prototype`, or invalid. This classification is research bookkeeping only; production authorization still requires code review, formal refinement, independent cryptanalysis, and the release manifest.

## Plan of Work

Create `campaign.json` with the fixed relation and security contract, a 512 KiB optimization target, a 1 MiB hard cap, a 28 GiB heavy-run admission floor, a non-lowerable 20 GiB hard reserve, a 4 GiB Cargo-target cap, a 5 GiB complete run-root cap, bounded output, and a 30-minute timeout. Include every boolean verification path that the frozen full backend already emits.

Create `autoresearch.py` using only the Python standard library. It must exact-parse candidates and known measurement schemas; reject ambiguous identifiers, shell strings, symlinked state paths, missing artifacts, invalid booleans, oversized proofs, and relation/proxy drift; acquire both a campaign ledger lock and a host-wide experiment lock; execute candidates in their own marked `/private/tmp/hegemon-proof-autoresearch-*` directory; monitor free space, run-directory bytes, output bytes, and wall time; terminate the complete process group on a limit breach; verify that candidate source artifacts did not mutate during the run; clean the exact marked directory on all exits; and append a hash-chained compact record. It must expose `doctor`, `seed`, `run`, `status`, `verify-ledger`, and `gc` commands.

Create `candidates/baseline-all-private-r3.json`. Its live command invokes the existing `run-full-pay1x2.sh` against the pinned local Binius checkout. Its seed measurement points to the frozen 350,800-byte full Pay1x2 result, allowing the campaign to initialize without spending build time or disk.

Create standard-library unit tests in `tests/test_autoresearch.py`. Tests must use temporary directories and tiny fake result producers; they may not run Cargo or delete paths outside their owned test directory. The tests must demonstrate that a smaller candidate with a failed mutation cannot win, a smaller weak-security candidate cannot displace a strict candidate, a tampered ledger is detected, concurrent lock acquisition fails, stale cleanup refuses unmarked or symlinked paths, and output/disk guard failures leave no run directory.

Once local validation passes, create a separate Codex task in the Hegemon project from the current working tree. Use exactly `gpt-5.6-luna` with `max` reasoning. The prompt must instruct the task to treat the controller as the experimental authority, start with `doctor` and `status`, change one proof-system lever per candidate, run cheap static/security tests before expensive proofs, retain only Pareto-improving candidates, never lower security or alter semantics, keep one experiment active at a time, wait below the 28 GiB admission floor, and stop before the 20 GiB reserve. The task should prioritize mixed-field/native binary commitment designs, oracle co-commitment, transcript/PCS layout, and exact serialization; it must not revive aggregation.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, run:

    python3 -m unittest discover -s prototypes/standalone-shake256-binius/autoresearch/tests -p 'test_*.py'
    python3 prototypes/standalone-shake256-binius/autoresearch/autoresearch.py doctor
    python3 prototypes/standalone-shake256-binius/autoresearch/autoresearch.py seed \
      --candidate prototypes/standalone-shake256-binius/autoresearch/candidates/baseline-all-private-r3.json \
      --measurement prototypes/standalone-shake256-binius/all-private-patch/full-pay1x2-measurement-2026-08-19.json
    python3 prototypes/standalone-shake256-binius/autoresearch/autoresearch.py status

The seed command must report one eligible `prototype` record at 350,812 envelope bytes and must explicitly report that the strict lane is empty. No Cargo target should exist afterward.

For a live rerun after `doctor` confirms at least 28 GiB free and the pinned Binius checkout at `/private/tmp/binius64-api-3f961630`, run:

    python3 prototypes/standalone-shake256-binius/autoresearch/autoresearch.py run \
      --candidate prototypes/standalone-shake256-binius/autoresearch/candidates/baseline-all-private-r3.json

The command is expected to rebuild in disposable directories, execute every composed verification gate, append one compact result, and remove its marked run directory. It is optional for platform setup because the exact live result is already frozen and the requested Luna task will use the live runner for changed candidates.

## Validation and Acceptance

Platform setup is accepted when all Python tests pass; `doctor` reports the correct repository, pinned Binius revision, configured limits, and free bytes; `seed` imports the frozen baseline; `verify-ledger` accepts the resulting chain; `status` shows 350,812 bytes as the prototype frontier and no strict winner; and no owned temporary directory or Cargo target remains.

The research campaign is not complete merely because it beats 350,812 bytes. A qualifying outcome must prove the exact full relation, pass every immutable gate, remain one self-contained proof, be at or below the 1 MiB hard cap, and supply a measured implemented profile with at least 128 composed post-quantum bits and established zero knowledge. The 512 KiB value is an optimization target, not permission to weaken security.

## Idempotence and Recovery

`doctor`, `status`, and `verify-ledger` do not build or prove; `doctor` creates and removes one tiny sandbox smoke directory. `run` uses a fresh random directory and always cleans it through a signal-safe finalizer. `gc` only removes directories with the exact prefix and UUID, a regular ownership marker matching this campaign, the current user id, an age above two hours, a dead controller identity, and no live worker process group; it refuses symlinks and every unmarked directory.

The controller never runs `git reset`, never deletes repository files, never reuses `$HOME`, and never uses a shared Cargo target. Candidate changes live as ordinary reviewed patches or source files in the task worktree.

## Artifacts and Notes

The frozen baseline is:

    proof bytes:       350800
    envelope bytes:    350812
    compiled rows:     1883192
    padded rows:       2097152
    prove time:        about 2065 ms
    verify time:       about 185 ms
    peak RSS:          about 5.47 GB
    security lane:     prototype only

These numbers are measurement anchors, not target constants. A candidate may change proof geometry, but it must continue proving the same fixed Pay1x2 semantics and authoritative action/network binding.

## Interfaces and Dependencies

`autoresearch.py` uses Python 3, `fcntl`, `subprocess`, `resource`, `hashlib`, and the filesystem. It has no network dependency and consumes no API key. Candidate commands are exact JSON arrays, not shell source. Placeholders are limited to `{repo}`, `{run_dir}`, `{target_dir}`, and `{binius_source}`.

The controller's normalized result interface contains `proof_bytes`, `envelope_bytes`, `prove_ms`, `verify_ms`, `peak_rss_bytes`, `security_lane`, `strict_qualified`, `verification_complete`, `capacity`, `source_schema`, and the exact candidate/artifact digests. Every ledger entry contains `previous_digest` and `entry_digest`, computed from canonical UTF-8 JSON with sorted keys and no insignificant whitespace.

Revision note (2026-08-19 15:26Z): Sealed and adversarially hardened the evaluator through separate preparation, compile, and runtime policies; recorded the frozen baseline in the prototype lane; activated the Luna 5.6/Max optimizer task; and independently validated its first mask co-commit patch. The first heavy experiment is intentionally pending disk admission rather than bypassing the reserve.

Revision note (2026-08-19 19:44Z): Promoted the first sealed Luna frontier improvement at 309,084 envelope bytes after a full real-proof gate run, verified the two-entry ledger and current disk/sandbox doctor state, and kept the result explicitly confined to the nonqualifying prototype lane.
