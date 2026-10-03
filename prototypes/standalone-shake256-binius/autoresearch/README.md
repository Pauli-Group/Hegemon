# Standalone Pay1x2 proof autoresearch

This directory is a local, `snark.fast`-style experimental loop for one Hegemon objective: minimize the canonical standalone proof for the exact full prospective V5/Delta Pay1x2 transaction while preserving the complete semantic, composition, privacy, and security contract.

It is not a consensus component. It never activates a route, and it keeps two leaderboards that cannot be compared away:

- `prototype` records real proof geometry under an incomplete security profile. The historical sealed ledger retains Luna's 309,084-byte envelope; versioned scalar trials verified canonical terminal serialization, compact Merkle multiproofs, and verifier-known FRI values at 244,252 envelope bytes. The exact full-relation native-word M4 measurement is now **65,440 proof bytes plus the 12-byte envelope** after verifier-owned public-message reconstruction, terminal-target leaves, and padding-fiber terminal compression at the pinned upstream 96-bit/SHA-256/GF(2^128) profile. It is transparent, so it does not populate the zero-knowledge or strict frontier.
- `strict` requires SHAKE256-512 proof hashing, GF(2^384) challenges, at least 264 classical bits in every modeled protocol budget, complete QROM accounting, exact-relation zero knowledge, at least 128 composed post-quantum bits, an exact proof artifact, and a passing independent `strict_pq_profile.py --require-release` run. This lane is empty today by design.

Security is a hard predicate, not a weighted score. A one-byte weak proof never outranks a larger strict proof.

## What is frozen

Candidate patches apply only to allowlisted source paths in a disposable copy of pinned Binius64 revision `3f96163049f680b2909f6545690bd929f1b48c44`, after the existing all-private input patch. They cannot modify Hegemon's scalar relation, action/statement adapter, envelope parser, composed-verifier harness, measurement wrapper, or tests.

The campaign JSON is digest-sealed in the controller, and the immutable artifact list is campaign-owned rather than candidate-selected. Text validation covers every git path header; after application, the disposable tree is independently enumerated and accepts only modifications to existing regular `crates/*/src/*.rs` files. The trusted preparation phase applies patches but executes no candidate code. Compilation then sees a read-only source closure, default-denied host reads, only the owned evaluator plus offline Cargo/Rust and operating-system closure, and explicit target/tmp/output/home write paths. Candidate-linked test and prover/verifier binaries run under a second default-deny-read Seatbelt profile exposing only the exact executable, target/tmp, and operating-system runtime closure; it additionally denies forks, non-self execs, launchd job creation, Mach/XPC lookup, POSIX IPC, external signals, process-group changes, and network access. The doctor smoke test verifies both phases cannot read an outside secret.

Every eligible result must remain:

- one input, two ordered outputs, one hidden depth-32 path, 61-bit native values, exact integer conservation, derived spend authorization, and owner-authorized change;
- 2,448 private witness bytes, a 478-byte HGS2 statement, the exact HGS2 route `2/5/4/1/1`, prospective V5/Delta family `1` action `7`, and HGSP V1's 12-byte direct-proof header;
- at least 40 SHAKE/Keccak permutations with no reduced rounds, removed Boolean constraints, off-proof membership or conservation checks, geometry proxy, aggregate, receipt, cache authority, sidecar, or proof reference; and
- passing every public/proof/trailing mutation, action and envelope preflight, fresh-forgery composition control, carry/range boundary, and canonical round-trip fact listed in `campaign.json`.

The current row count is a diagnostic, not a frozen invariant. A genuine circuit optimization may reduce rows while the external relation and mutation contract remains fixed.

## Cheap-first research loop

Use one falsifiable hypothesis per candidate. The preferred loop is:

1. Run `doctor`. If `heavy_run_admitted` is false, do not build or prove.
2. Inspect `status` and choose one byte source from the current proof breakdown.
3. Create a small git-format patch against the disposable Binius tree after the baseline private-input patch. Do not edit the frozen evaluator.
4. Run static patch checks and, when available, Binius `SizeTrackingChannel` first. A size-only result may reject a candidate but can never promote it.
5. Review the narrow source diff, then run one real full candidate through `run`. Only the prototype lane can execute today; strict admission remains disabled until an independent artifact parser/composed verifier exists.
6. Keep the patch only if it improves the same security lane or exposes a reusable Pareto tradeoff. Reproduce any prospective winner from another clean tree with fresh prover randomness before calling it stable.
7. Update the candidate hypothesis and parent rather than combining unrelated changes.

The first high-value experiment co-committed the small fresh mask buffer with unused padded capacity in the private oracle and verified both relations against the same commitment/opening. The sealed evaluator accepted the exact full Pay1x2 gates and measured 309,084 envelope bytes, a 41,728-byte (11.89%) reduction from the baseline. This is still transcript/PCS surgery in the prototype lane: the measurement establishes geometry and invariant preservation, not strict soundness, complete zero knowledge, QROM security, or production eligibility.

The cumulative scalar trial sends the canonical terminal message, uses a query-derived compact Merkle frontier, and omits FRI leaf scalars already fixed by authenticated fold claims. Its full supervised run produced a 244,252-byte envelope with every frozen gate passing. Applying that wire profile to the exact single-main M4 relation produced a 72,892-byte envelope; deterministic public-message reconstruction, terminal-target leaves, and padding-fiber terminal compression reduce the exact envelope to 65,452 bytes. Frozen reports are under `../m4-selected-wire-patch/`, `../m4-public-elision-patch/`, `../m4-terminal-target-patch/`, and `../m4-padding-fiber-patch/`. The strict lane remains empty.

## Commands

From the repository root:

    python3 -m unittest discover \
      -s prototypes/standalone-shake256-binius/autoresearch/tests \
      -p 'test_*.py'

    python3 prototypes/standalone-shake256-binius/autoresearch/autoresearch.py doctor

Initialize a new ledger from the already measured baseline without building:

    python3 prototypes/standalone-shake256-binius/autoresearch/autoresearch.py seed \
      --candidate prototypes/standalone-shake256-binius/autoresearch/candidates/baseline-all-private-r3.json \
      --measurement prototypes/standalone-shake256-binius/all-private-patch/full-pay1x2-measurement-2026-08-19.json

Inspect and verify:

    python3 prototypes/standalone-shake256-binius/autoresearch/autoresearch.py status
    python3 prototypes/standalone-shake256-binius/autoresearch/autoresearch.py verify-ledger

Run one live baseline or candidate only when `doctor` admits it:

    python3 prototypes/standalone-shake256-binius/autoresearch/autoresearch.py run \
      --candidate prototypes/standalone-shake256-binius/autoresearch/candidates/baseline-all-private-r3.json

To add a local candidate, copy the baseline JSON, set a new `id`, `parent_id`, and falsifiable `hypothesis`, and set `candidate_patch` to a repository-relative patch path. An isolated model task instead writes its manifest and patch beneath the mode-0700 `/private/tmp/hegemon-proof-autoresearch-inbox`; the sealed evaluator remains in this worktree. The patch must touch only an allowlisted existing non-test Binius Rust source. The runner applies the baseline private-input patch first, then validates both the patch text and the actual post-apply tree.

## Disk and process safety

Repository files, `/private/tmp`, and the user temp directory share one APFS volume. Temp placement improves cleanup, not capacity.

The controller therefore:

- refuses a heavy run below 28 GiB free;
- kills the complete child process group if free space falls below a non-lowerable 20 GiB reserve;
- rejects network access and writes outside six exact preparation/build directories, then runs candidate-linked binaries under the stricter no-fork/no-job/no-Mach runtime profile;
- caps the Cargo target at 4 GiB and the complete marked run root at 5 GiB;
- caps stdout and stderr at 8 MiB each, the canonical result at 1 MiB, reported peak RSS at 8 GiB, and wall time at 30 minutes;
- uses at most four Cargo jobs, native CPU flags, offline locked dependencies, no incremental compilation, no debug data, no core dumps, and a 1 GiB file-size limit;
- serializes all experiments through a user-owned `fcntl` lock; and
- always terminates and reaps the child group before deleting only the exact UUID-marked run directory.

`gc` examines only names beginning `hegemon-proof-autoresearch.run.` under the configured user-private temp parent. It requires the exact marker schema, campaign id, uid, matching UUID, an age above two hours, and a dead recorded PID. Unmarked, symlinked, young, live, or ambiguous paths are retained. It never touches the repository `target/`, `formal/`, `.git/`, Cargo/Rust caches, the pinned Binius checkout, or pre-existing Hegemon temp paths.

The latest sealed `doctor` read 30,637,985,792 free bytes (28.53 GiB), so the 28 GiB heavy-run gate is open with narrow headroom; the non-lowerable in-run floor remains 20 GiB. Free space can fluctuate because other tasks share the volume, so run `doctor` immediately before every real proof.

## Result integrity and claim boundary

`ledger/results.jsonl` is append-only and tamper-evident, not a cryptographic signature. Every canonical JSON record contains the prior record digest and its own SHA-256 digest; status re-derives eligibility from the retained measurement, security, and complete verification facts. A stored row cannot self-assert a strict authority pass. The isolated Luna task cannot write this evaluator worktree; its proposals must be reviewed and re-evaluated here before promotion.

The controller independently enforces resource limits, patch scope, source hashes, fixed result fields, and the current external mutation contract. The 4/5 GiB directory ceilings are sampled safety checks rather than an APFS quota; the non-lowerable 20 GiB reserve and 28 GiB admission floor provide the additional disk runway. This is still research tooling, not an independent cryptographic audit. Prototype measurements are produced by candidate-linked proof code and therefore locate size opportunities but do not certify soundness. A candidate-supplied security label cannot enter the strict lane: the controller requires an owned exact proof file and a separate sealed HGSP/action/statement verifier, whose implementation/review capability flags are currently false.

Success is two matching clean live reproductions of a strict-PQ128 envelope at or below 512 KiB. One MiB is only the admissibility ceiling. The old 124,080-byte number is a stretch target, not a precondition for the first safe profile and not permission to use aggregation. Strict admission is deliberately unreachable today: the budget calculator is not an independent HGSP/action/statement verifier, so the campaign requires a separate sealed composed verifier before any strict result can enter the ledger.
