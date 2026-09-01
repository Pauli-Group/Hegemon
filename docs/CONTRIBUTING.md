# Contributing Guide

This repository is a single monorepo that houses the cryptography primitives (`crypto/`), proving circuits (`circuits/`), consensus/networking logic (`consensus/` and `network/`), wallet UX (`wallet/`), and narrative documentation (`docs/`, `DESIGN.md`, `METHODS.md`). Every change **must** keep all three layers aligned:

1. Update the code.
2. Update the relevant section in `DESIGN.md` (architecture/intent) and `METHODS.md` (operational procedures/testing strategy).
3. Update the affected doc(s) inside `docs/` so downstream contributors can find the new behavior quickly.

The unified `hegemon` binary is the canonical way to exercise the node and wallet. Legacy Python proxies and standalone dashboards have been removed; new work should focus on the desktop app and CLI surfaces.

## Toolchains and workflows

| Area | Language | Primary Commands |
| --- | --- | --- |
| PQ primitives (`crypto/`) | Rust 1.75+ | `cargo fmt --all`, `cargo test -p synthetic-crypto` |
| Core circuits (`circuits/block`, `circuits/transaction`) | Rust 1.75+ | `cargo test -p block-circuit`, `cargo test -p transaction-circuit` |
| Node/protocol/network (`node`, `protocol/*`, `network`, `consensus`) | Rust 1.75+ | `cargo test -p consensus`, `cargo test -p network`, `cargo test -p protocol-kernel`, `cargo test -p protocol-shielded-pool`, `cargo test -p hegemon-node --lib`, `cargo build -p hegemon-node --release` |
| Wallet (`wallet`) | Rust 1.75+ | `cargo test -p wallet`, `cargo test --test security_pipeline -- --nocapture` |
| Manual simulators/benchmarks (SmallWood candidates, `wallet/bench`, `consensus/bench`) | Rust + Go 1.21 | `cargo test -p transaction-circuit compressed_level5_radix2_roundtrip_benchmark --release -- --ignored --nocapture`, `cargo run -p transaction-circuit --release --example pq128_profile_bench -- 3`, `cargo run -p wallet-bench -- --smoke`, `go test ./...` inside `consensus/bench`, `go run ./cmd/netbench --smoke` |

The correctness/build commands below are what CI enforces by default. Performance and benchmark harnesses remain manual tools.

> Tip: Run `make setup` once on a fresh clone to install toolchains. Then build the node with `make node` and run `HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp` to start an isolated development node. For shared mining, set `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` unless the approved seed list has deliberately rotated. All miners on one network must share the same seeds to avoid partitions and forks, and mining hosts must run NTP or chrony because future-skewed PoW timestamps are rejected. For daily work, use `make check` to lint/test or `make bench` to run benchmarks.

## Continuous integration

GitHub Actions runs `.github/workflows/ci.yml` on every push/PR. Jobs:

- `rust-lints`: runs the lean formatting/lint gate through `./scripts/check-core.sh lint`.
- `dependency-audit`: runs `./scripts/dependency-audit-gate.sh`; unwaived advisories or yanked crates block release build.
- `formal-core`: runs `bash scripts/check_formal_core.sh`; the gate builds the pinned Lean proof kernel, checks generated Lean-to-Rust bridge message-root/replay, bridge checkpoint-output canonical/journal bytes, bridge long-range proof-shape, bridge header-MMR opening-shape, bridge header-MMR parent/root transcript, bridge FlyClient sampling transcript/index, shielded-nullifier, consensus fork-choice, consensus PoW-admission, consensus header-preimage, consensus PoW miner-identity, native miner-identity, consensus version-policy, consensus proof-policy, consensus native tx-leaf admission, consensus receipt-root admission, consensus recursive-block admission, consensus recursive public replay, consensus recursive semantic inputs, consensus block tree-transition, consensus DA-root byte binding, consensus proven-batch binding, supply-accounting, consensus supply-chain invariant, native action-ordering, native action request projection admission, native action hash/count admission, native action-root transcript binding, native action-state/stream planning, native action-plan application admission, native action wire-replay projection admission, native announced-block admission, native mined-work admission, native storage-durability admission, native codec admission, native action scope admission, native bridge action payload admission, native RISC Zero release-verifier fail-closed admission, native transfer action payload admission, native transfer state admission, native coinbase accounting admission, native coinbase action payload admission, native mineable action admission, native resource-budget admission, native RPC admission, native sidecar upload admission, network secure-channel key schedule, PQ Noise key schedule/signing transcript, release PQ-binary policy, dependency-audit waiver policy, native candidate artifact admission, native candidate artifact coupling admission, native block artifact binding admission, native block commitment admission, native block replay refinement, native tx-leaf artifact, native receipt-root, wallet note-ciphertext wire, transaction-balance, transaction Merkle-path, transaction public-input shape, transaction public-input binding, transaction proof-wrapper admission, and transaction statement-hash conformance vectors, validates the formal/security claims ledger, blueprint DAG, formal model inventory, independent bridge vectors, native backend reference vectors, and the packaged native backend candidate-under-review release posture. Claim changes must update both `config/formal-security-claims.json` and `config/formal-security-blueprint.json` so status, dependencies, target review, implementation bindings, Lean theorem evidence, falsification cases, and residual risks stay synchronized.
- `formal-crypto-isolation`: runs `bash scripts/check_formal_crypto.sh --isolation-only` and rejects any attempt to turn the isolated research package into production authority by importing forbidden production claim surfaces.
- `formal-crypto-sanity`: runs the complete `formal/crypto` build and axiom audit, then checks Lean-generated proof-wire vectors against the production parser. Passing means the explicitly scoped ideal/caller-supplied/conditional theorems are internally valid; it does not mint deployed-end-to-end authority.
- `core-tests`: runs the fast shipping-path Rust tests through `./scripts/check-core.sh test`.
- `native-path-tests`: runs the exact production-verifier evidence regression and the active SHA-512 self-consistent PCS forgery rejection, alongside the other native shipping-path tests.
- Changes to native proof or mempool admission must also preserve the exact anchor/root mismatch, negative-zero/public-input alias, verify-before-persist, semantic single-flight, verifier-lane reservation, startup sanitizer, and valid-sibling quarantine regressions in `hegemon-node`; do not replace these with timing-only tests.
- `security-adversarial`: runs `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh`, including hostile proving regressions plus review-package parity checks.
- `release-build`: depends on both formal-crypto jobs and the native-path tests, then builds the release `hegemon-node` binary through `./scripts/check-core.sh build`.

Default CI no longer does a blanket `cargo test --workspace`. The gate is intentionally curated around the shipping native node, wallet, protocol, and circuit path so it clears quickly and does not burn time on dead or auxiliary lanes.
Operator-scenario harnesses such as `./scripts/test-node.sh two-node-restart` remain available for manual debugging, but they are not part of the default blocking CI gate.
Benchmark, simulator, and profiling harnesses such as the release-mode SmallWood candidate benchmark, `wallet-bench`, `go test ./...` in `consensus/bench`, and `netbench` are also manual, not part of default CI.
The merge-blocking hostile minimum is `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh`. Heavier adversarial/property harnesses such as `cargo test -p consensus --test fuzz -- --ignored`, `cargo test -p transaction-circuit --test security_fuzz`, `cargo test -p network --test adversarial`, `cargo test -p wallet --test address_fuzz`, and `HEGEMON_REDTEAM_MODE=full bash scripts/run_proving_redteam.sh` remain manual unless you are hardening those surfaces or preparing a release.

When you add a new crate or language toolchain, extend CI accordingly **and** document the new step here and in `METHODS.md`.

## Native mining and fork-sync regression contract

Changes to native history access, mining work, block import, fork choice, or sync retry must preserve these invariants:

- Canonical work preparation, mining status, and mined-work revalidation use the canonical state's validated compact header-MMR peaks. They must not reconstruct the full chain. Between retargets, difficulty uses the exact persisted parent. At a retarget boundary, the implementation follows at most `RETARGET_WINDOW - 1` actual parent links through validated batch rows or allocation-free persisted projections; the canonical path additionally requires both the supplied parent and derived anchor to match their height indexes. Keep an independent full-history oracle in tests and compare `pow_bits`, MMR root/length, header preimage, and import result byte-for-byte.
- Cached MMR peaks are derived state, not consensus authority. Missing persisted tip/anchor data, inconsistent ancestor heights, and malformed peak shape reject fail-closed.
- Sync import must distinguish canonical advancement, stored noncanonical data, already-known data, missing parent, and error. A missing parent is not `AlreadyKnown`. Exact-classify every supplied record as known-exact, missing, or a terminal same-hash metadata mismatch; a connected `known / missing / known` response must validate the complete path, persist only the missing connector, and continue without another identical request. Every nonempty response must be a contiguous prefix of the exact outstanding peer request. Only in-flight entries authorize responses; cooldown fingerprints reject late duplicates. Missing-parent recovery must widen and then page bounded windows backward across protocol-cap boundaries; after a connected all-known or stored-noncanonical prefix, the next request must advance from that side-branch tip and bind its first parent to the preceding response hash. Preserve a peer-bound cursor across monotone target growth, require the advertised hash on the final target page, and do not resolve an equal-height target from an ancestor page. Supplied cumulative work is not target authority: a nonwinning target may clear only after the authorized response is fully processed and the exact target row is validated and durably loaded from local storage. Empty, malformed, stale, busy-import, worker-failure, and import-error paths must keep the target unresolved and cool down the exact request instead of repeating it on the next scheduler tick.
- Add a regression using the live-size 64-block response shape, with the divergent parent immediately before the formerly repeated range. Assert canonical progress, bounded queue/retry state, and that the mining sync gate remains closed until the hash-anchored target resolves.

Run `cargo test -p hegemon-node --lib` for focused native changes and the broader repository gates required by the touched surfaces. If consensus results, import ordering, mining admission, a formalized helper, or `config/formal-security-blueprint.json` changes, also run `bash scripts/check_formal_core.sh` and the applicable generated-vector/conformance tests. Storage-query optimizations are not exempt: their tests must instrument metadata reads and full-chain reconstruction counts so a future apparently harmless RPC or template change cannot restore height-linear decoding.

Memory reports must distinguish operating-system measurements (RSS, private-anonymous residency, high-water marks, OOM records) from source-confirmed allocations/retained values and from inferred allocator retention or fragmentation. Do not label RSS growth a confirmed live-object leak without heap-profiler reachability evidence. A realistic controlled soak should record chain progress and workload, avoid or disclose diagnostic RPC perturbation, and show a stable RSS envelope over repeated mining and fork-recovery cycles; structural counters and an RSS plateau support different claims and both belong in a performance-fix PR.

Winning reorganization must use compact ancestry and one-stored-body-at-a-time passes, but reports must retain its history/state/output-sized residuals: carried replay state, compact projections, action/orphan/pending/staged sets, and canonical output-plan/write-set ownership. Scalar and header-only RPCs must not clone the tip action body; body-returning and bounded-row RPCs may still decode the records they return.

Use `./scripts/check_native_node_memory_sync_recovery.sh --structural-only` for the focused deterministic gate. For the local RSS/progress acceptance mode, pass an explicit node PID, loopback RPC URL, output CSV, and RSS growth/envelope limits selected before the run; see `--help`. The full mode intentionally polls `hegemon_miningStatus`, requires active ungated nonsyncing mining and canonical height progress, and records that diagnostic workload in its JSON summary.

Any operator or rollout material introduced by the change must use `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` unless the approved seed list has deliberately rotated, require every miner on the network to share that list, and require NTP or chrony. Because the append-only chunk variants have no capability negotiation, a one-node canary against an old peer must first prove all required records fit the legacy 16 MiB frame or use an upgraded relay; a record above that cap requires upgraded endpoints on both sides. Testnet deployment or service restart remains separately authorized from code review and PR creation.

## Dependency advisories

Use `./scripts/dependency-audit-gate.sh` before opening security-sensitive PRs. It fails on unwaived cargo-audit findings. Use `./scripts/dependency-audit.sh --record` to append a human-readable snapshot to `docs/DEPENDENCY_AUDITS.md` after updating the waiver policy.

## Benchmarks

Four benchmarking harnesses exist to make performance work repeatable:

1. `cargo test -p transaction-circuit compressed_level5_radix2_roundtrip_benchmark --release -- --ignored --nocapture` – constructs, proves, parses, and verifies the exact 64- and 128-lane SmallWood candidates and reports proof bytes plus proving and verification latency.
2. `cargo run -p transaction-circuit --release --example pq128_profile_bench -- 3 [candidate-label]` – produces and verifies exact candidate proofs under the same active relation while reporting bytes, combined round-trip time, corrected Level-5 LVCS projections, and the ideal-model-only CMS diagnostic. Candidate constants stay benchmark-local; activate only a strict size/prover/verifier Pareto improvement with unchanged conservative security accounting.
3. `go run ./cmd/netbench --smoke` (inside `consensus/bench`) – simulates miner gossip and reports achieved messages/second given synthetic PQ signature sizes and payload targets.
4. `cargo run -p wallet-bench -- --smoke` – constructs shielded notes, derives nullifiers, and signs view keys to report wallet ops/second.

Capture benchmark deltas in pull requests when you optimize anything in the hot path.

## PQ design guardrails

- Only ML-DSA/SLH-DSA signatures and ML-KEM encryption are allowed (see `DESIGN.md §1`).
- Hash-based commitments and STARK-friendly hashes drive all circuits; never introduce ECC primitives.
- Default symmetric key sizes are 256-bit to maintain ≥128-bit quantum security after Grover reductions.
- Native JSON-RPC resource hardening includes the 8 MiB HTTP body cap, 8 in-flight request cap, batch caps, and byte parser caps; keep `native RPC admission` and `native sidecar upload admission` formal-core coverage synchronized when changing those limits.
- Threat mitigations from `THREAT_MODEL.md` (network DoS budgets, wallet key-rotation cadence, and memory-hard proving limits in the remaining offline circuit tooling) must be satisfied by code and tests.

Document any deviations in both `DESIGN.md` and `METHODS.md` before landing code.
