# Native Node Security Review And Hardening

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md`. It is self-contained so a future contributor can continue the review from only this file and the current working tree.

## Purpose / Big Picture

Substrate has been removed, so `hegemon-node` now owns consensus import, persistent state, JSON-RPC, mining control, and PQ networking directly. The goal of this security review is to remove any critical or high-severity native-node vulnerability that could let a remote peer, public RPC caller, or local operator mistake corrupt chain state, control a node, bypass proof or PoW checks, or compromise long-lived node identity. The user-visible outcome is a native node that still builds, starts, mines, syncs, and serves wallet-compatible RPCs, while high-risk controls fail closed.

## Progress

- [x] (2026-04-24T16:40Z) Read `.agent/PLANS.md`, `DESIGN.md`, and `METHODS.md`, then mapped the native attack surface in `node/src/native/mod.rs`, `consensus/src/pow.rs`, and the PQ networking identity path.
- [x] (2026-04-24T16:40Z) Identified high-severity findings to patch first: deterministic PQ identity seed derivation, unsafe RPC method policy not enforced, missing native future-skew check on announced blocks, and supply accounting advancing when no shielded coinbase note exists.
- [x] (2026-04-24T16:40Z) Patch native PQ identity seed loading so keys come from OS entropy, persist as `0600`, and may be overridden only by `HEGEMON_PQ_IDENTITY_SEED` or `HEGEMON_PQ_IDENTITY_SEED_PATH`.
- [x] (2026-04-24T16:40Z) Patch native JSON-RPC dispatch so `--rpc-methods=safe` denies unsafe DA staging and mining-control endpoints; `auto` must resolve to `safe` on external RPC and `unsafe` on loopback.
- [x] (2026-04-24T16:40Z) Patch native PoW block validation to enforce the documented `MAX_FUTURE_SKEW_MS` bound for peer-announced blocks.
- [x] (2026-04-24T16:40Z) Patch native supply accounting so blocks without a shielded coinbase action do not add newly spendable supply to `supply_digest`.
- [x] (2026-04-24T16:40Z) Patch imported block action validation so peer-originated blocks must satisfy the same binding-hash, payload-shape, and shielded-transfer ordering rules as locally staged actions.
- [x] (2026-04-24T16:40Z) Patch the legacy native P2P framed connection used by `network::P2PService` so unauthenticated and encrypted frames have explicit size limits.
- [x] (2026-04-24T16:59Z) Patch public wallet archive RPCs so commitments, ciphertexts, and nullifiers honor pagination and never materialize unbounded state in one response.
- [x] (2026-04-24T16:40Z) Add regression tests for all patched high-severity findings.
- [x] (2026-04-24T16:40Z) Focused validation passed: `cargo test -p hegemon-node --lib native:: -- --nocapture` and `cargo test -p network oversized_handshake_frame_is_rejected -- --nocapture`.
- [x] (2026-04-24T16:59Z) Expanded focused validation passed after pagination and P2P compatibility repair: `cargo test -p hegemon-node --lib native:: -- --nocapture` and `cargo test -p network -- --nocapture`.
- [x] (2026-04-24T17:37Z) Broad pre-advisory validation passed: `make check`, `make node`, live `./scripts/smoke-test.sh` against a release dev miner, `./scripts/test-node.sh two-node-restart`, and `./scripts/test-node.sh wallet-send`.
- [x] (2026-04-24T17:40Z) Ran `cargo audit`; it found high-severity dependency advisories in `aws-lc-sys` and `quinn-proto`, plus non-high advisories in `bytes`, `rustls-webpki`, and `time`.
- [x] (2026-04-24T17:41Z) Updated `Cargo.lock` to fixed compatible versions: `aws-lc-sys` 0.40.0, `aws-lc-rs` 1.16.3, `quinn-proto` 0.11.14, `rustls-webpki` 0.103.13, `rustls` 0.23.39, `bytes` 1.11.1, and `time` 0.3.47.
- [x] (2026-04-24T17:41Z) Reran `cargo audit`; it exits successfully with no vulnerability advisories remaining. Only warning-class unmaintained/yanked/unsound entries remain.
- [x] (2026-04-24T17:55Z) Reran focused and broad local gates after the dependency updates: `cargo fmt --check`, `cargo test -p hegemon-node --lib native:: -- --nocapture`, `cargo test -p network -- --nocapture`, `make check`, `make node`, live `./scripts/smoke-test.sh`, `./scripts/test-node.sh two-node-restart`, `./scripts/test-node.sh wallet-send`, and final `cargo audit`.
- [x] (2026-04-24T18:56Z) Removed unused direct `atty` dependency from `hegemon-node`, which removed two warning-class audit entries; reran `cargo audit`, `cargo test -p hegemon-node --lib native:: -- --nocapture`, `make node`, and live local `./scripts/smoke-test.sh`.
- [x] (2026-04-24T19:09Z) Synced the final post-`atty` working tree to `hegemon-dev:/tmp/hegemon-security-review`, built `make node`, passed isolated live smoke on RPC 19944/P2P 31335, passed clean high-port `two-node-restart` on RPC 22945/22946 and P2P 33333/33334, passed remote `wallet-send`, then removed the temporary remote copy.
- [x] (2026-04-24T19:15Z) Final local `make check` passed on the post-`atty` tree, including native node tests and `security_pipeline`.

## Surprises & Discoveries

- Observation: `DESIGN.md` and `METHODS.md` already require PQ identity seeds to be OS-random and persisted, but `node/src/native/mod.rs` derived the identity seed from node name plus base path.
  Evidence: `start_native_p2p` used `hash32_with_parts(b"hegemon-native-peer-v1", node_name, base_path)`.
- Observation: The native CLI accepted `--rpc-methods auto|safe|unsafe`, but RPC dispatch did not consult the policy.
  Evidence: `dispatch_rpc_method` exposed `da_submitCiphertexts`, `da_submitProofs`, `hegemon_startMining`, and `hegemon_stopMining` unconditionally.
- Observation: The consensus crate has a 90 second future-skew rule, but native announced-block validation did not call it.
  Evidence: `consensus/src/pow.rs` rejects `timestamp_ms > current_time_ms() + MAX_FUTURE_SKEW_MS`; `validate_announced_block` only required `timestamp_ms > parent.timestamp_ms`.
- Observation: Native supply accounting added the block subsidy even when there was no shielded coinbase action, which creates a supply digest that says issuance happened without a corresponding note commitment.
  Evidence: `native_block_supply_delta` returned `subsidy` when no `ACTION_MINT_COINBASE` action was present.
- Observation: Peer-imported native blocks validated nullifier uniqueness and roots, but did not re-run the local binding-hash/payload checks or enforce the documented nondecreasing shielded-transfer order.
  Evidence: `validate_block_actions_locked` did not call `validate_binding_hash` and did not compare adjacent transfer `action_order_key` values.
- Observation: The `network::p2p::Connection` path used by `P2PService` built a default `LengthDelimitedCodec`, which has no project-level explicit frame limit.
  Evidence: `Connection::new` called `LengthDelimitedCodec::new()` and handshake/message deserialization used unrestricted `bincode::deserialize`.
- Observation: Native wallet archive RPCs ignored pagination parameters and returned whole commitment/nullifier/ciphertext collections.
  Evidence: `wallet_commitments`, `wallet_ciphertexts`, and `wallet_nullifiers` took no params and always returned `has_more: false`.
- Observation: The lockfile still carried vulnerable TLS/QUIC/body dependencies after Substrate removal.
  Evidence: `cargo audit` reported high-severity advisories for `aws-lc-sys` 0.34.0 and `quinn-proto` 0.11.13, plus advisory fixes available for `bytes`, `rustls-webpki`, and `time`.
- Observation: `hegemon-dev` already had a service bound on the default smoke RPC/P2P ports.
  Evidence: A first remote smoke attempt saw height 9110 on `127.0.0.1:9944`, missing `author_pendingExtrinsics`, while the temp node log showed `Address already in use`. Isolated ports passed against the synced temp binary.
- Observation: `atty` was a direct dependency of `hegemon-node` but had no source use.
  Evidence: `rg` found `atty` only in `node/Cargo.toml`; removing it deleted the `atty` package from `Cargo.lock` and reduced `cargo audit` warning-class entries from 12 to 10.

## Decision Log

- Decision: Treat mining-control RPC and DA sidecar staging RPC as unsafe-only, while leaving wallet transaction submission (`hegemon_submitAction`) available on safe RPC.
  Rationale: Wallet submission is the public compatibility surface; DA sidecars and mining controls are documented as proposer/local controls and can consume disk or alter node behavior.
  Date/Author: 2026-04-24 / Codex
- Decision: Use `consensus::reward::MAX_FUTURE_SKEW_MS` for native announced-block validation rather than introducing a node-local constant.
  Rationale: The design already treats consensus reward/pow constants as the single source of truth, and this keeps native validation aligned with `PowConsensus`.
  Date/Author: 2026-04-24 / Codex
- Decision: When a block omits the native shielded coinbase action, native `supply_digest` should not increase.
  Rationale: No spendable note was minted. Advancing the digest without a note commitment is inconsistent accounting and would make later audits impossible.
  Date/Author: 2026-04-24 / Codex
- Decision: Treat imported block actions as untrusted wire data even after their action hash matches.
  Rationale: The hash only proves byte stability. Consensus must still reject payloads whose public binding hash, metadata fields, or transfer ordering do not match the protocol rule.
  Date/Author: 2026-04-24 / Codex
- Decision: Cap legacy P2P frames at a fixed 16 MiB and cap handshake frames at 64 KiB.
  Rationale: This admits current native block/artifact payloads while preventing a peer from forcing unbounded length-delimited allocation before authentication.
  Date/Author: 2026-04-24 / Codex
- Decision: Treat wallet archive pagination as part of the security boundary, not only a performance feature.
  Rationale: These methods remain available under safe/public RPC and their cost grows with chain state.
  Date/Author: 2026-04-24 / Codex
- Decision: Resolve high/critical dependency advisories by updating the lockfile to the newest compatible patched versions rather than suppressing audit findings.
  Rationale: These crates sit in the RPC/client/TLS/QUIC dependency graph. Even if some paths are not the native PQ gossip path, they are reachable through operator-facing binaries and security test tooling.
  Date/Author: 2026-04-24 / Codex

## Outcomes & Retrospective

The security review is clear for critical/high findings found in this pass. It closed eight high-severity native-cutover classes: predictable PQ identity keys, unsafe RPC exposure under safe policy, future-dated PoW block import, supply digest advancement without a coinbase note, imported transfer ordering/binding mismatch, unbounded P2P frames, unbounded public wallet archive RPC responses, and vulnerable high-severity dependency versions in the TLS/QUIC graph. Local and `hegemon-dev` validation passed on the final post-`atty` tree. `cargo audit` exits 0 with no vulnerability advisories; 10 warning-class dependency debt entries remain for unmaintained/yanked/unsound transitive crates and should be tracked separately because they are not critical/high in this review.

## Context and Orientation

The native node lives mainly in `node/src/native/mod.rs`. It opens sled trees, stores block metadata, builds and imports mined blocks, accepts peer-announced blocks, runs the Hegemon PQ P2P service, and dispatches the JSON-RPC compatibility API used by wallets, scripts, and Electron. `consensus/src/pow.rs` is still the stricter generic PoW consensus implementation and defines timestamp and supply rules that the native node must mirror. `consensus/src/reward.rs` contains chain constants such as `MAX_FUTURE_SKEW_MS`.

An unsafe RPC method is a method that mutates local node control state or stages proposer-local sidecar data rather than submitting a normal public transaction. These methods are acceptable on loopback with `--rpc-methods=unsafe`, but they must not be exposed on public RPC when the operator chose `safe` or external `auto`.

## Plan of Work

First, add an RPC policy helper to `node/src/native/mod.rs` and call it before method dispatch. The helper must normalize `auto`, `safe`, and `unsafe`. `auto` means `safe` when `--rpc-external` is set and `unsafe` otherwise. Invalid policy strings should fail node startup rather than silently falling through.

Second, replace deterministic native PQ identity derivation with a seed loader. The loader must accept `HEGEMON_PQ_IDENTITY_SEED` as a 32-byte hex string, otherwise read `HEGEMON_PQ_IDENTITY_SEED_PATH` or `<base-path>/pq-identity.seed`, creating the file from OS entropy when missing. On Unix, new files must be created with mode `0600` and existing files should be tightened to `0600`.

Third, align native announced-block validation with the consensus timestamp rule by rejecting timestamps more than `MAX_FUTURE_SKEW_MS` ahead of the local wall clock.

Fourth, fix imported action validation. For each shielded transfer action, decode the SCALE payload, check that decoded commitments, ciphertext hashes, ciphertext sizes, anchor, proof size, and binding hash match the metadata carried by the action, then enforce nondecreasing `blake2_256(binding_hash || nullifiers...)` order across transfer actions in the block.

Fifth, fix native supply accounting so only explicit coinbase mint actions add supply. Empty blocks and blocks without coinbase leave `supply_digest` unchanged. Existing tests that synthesize side chains must be updated accordingly.

Sixth, add explicit frame caps to `network/src/p2p.rs` so remote peers cannot send unbounded handshake or encrypted frames.

Seventh, change `hegemon_walletCommitments`, `hegemon_walletCiphertexts`, and `hegemon_walletNullifiers` to parse the existing `{ start, limit }` parameter shape, clamp limits to a node-side maximum, and return accurate `total` and `has_more`. Ciphertext entries must use the wallet-compatible `{ index, ciphertext }` shape with base64 DA bytes.

Finally, add focused regression tests for policy gating, identity persistence/unpredictability, future timestamp rejection, and supply-digest behavior. Run focused package tests first, then the broader native gate set.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Run focused checks during implementation:

    cargo fmt --check
    cargo test -p hegemon-node --lib native::

After focused tests pass, run broader validation:

    cargo test -p consensus
    cargo test -p network
    cargo test -p wallet --lib
    cargo test -p hegemon-node --lib
    cargo audit
    make check
    make node
    ./scripts/smoke-test.sh
    ./scripts/test-node.sh two-node-restart

## Validation and Acceptance

The review is clear for critical/high native issues when the code has regression tests proving:

1. A new node creates a random persisted PQ identity seed, restarts with the same identity seed, and does not derive it from public node name or base path.
2. `--rpc-methods=safe` rejects unsafe DA and mining-control methods, while `unsafe` permits them. `auto` resolves to safe for external RPC and unsafe for loopback.
3. A block whose timestamp exceeds the local clock by more than `MAX_FUTURE_SKEW_MS` is rejected before import.
4. A native block without a shielded coinbase action leaves `supply_digest` unchanged, while a valid coinbase action still increases it by the expected reward.
5. A peer-originated block with out-of-order shielded transfers or mismatched binding metadata is rejected.
6. Oversized P2P handshake frames are rejected before deserialization.
7. Wallet archive RPCs return bounded pages with accurate `has_more` and wallet-compatible field names.
8. Existing wallet-compatible safe RPCs still pass the smoke test.

## Idempotence and Recovery

The code changes are local and testable. The identity seed loader creates one file per base path and then reuses it; repeated starts are stable. Tests use temporary directories. If a validation command fails, inspect the failing test output, patch the specific failure, and rerun the focused tests before returning to broader gates.

## Artifacts and Notes

Important evidence before patching:

    node/src/native/mod.rs derived `identity_seed` from node name and base path.
    node/src/native/mod.rs exposed unsafe RPCs without checking `rpc_methods`.
    consensus/src/pow.rs already enforces `MAX_FUTURE_SKEW_MS`, but native announced blocks did not.
    native_block_supply_delta returned subsidy when no coinbase action existed.

## Interfaces and Dependencies

In `node/src/native/mod.rs`, add or expose only local helpers; no new public crate interface is required. Use `getrandom` or a standard secure RNG already available in the workspace for 32 bytes of OS entropy. Continue to use `PeerIdentity::generate(&seed)` after obtaining the seed. Use `consensus::reward::MAX_FUTURE_SKEW_MS` for timestamp skew. Keep JSON-RPC method names and payload shapes stable; only unsafe method availability changes under safe policy.
