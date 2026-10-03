# Enable Bitcoin ASIC mining without replacing Hegemon transactions


This living ExecPlan follows `.agent/PLANS.md`. The October 2, 2026 request authorizes implementing a consensus format usable by ordinary Bitcoin ASIC miners, either in PR #205 or a follow-up. Work uses follow-up branch `codex/bitcoin-asic-mining` in `/private/tmp/rp05-ci-20261001.223oOy`, starting from PR #205's fully green `f322352ccdfe6da3310fb43dfc0adcb35660095f`. The primary checkout and live testnet nodes are not edited or restarted.

## Purpose / Big Picture


After this change a Bitcoin miner can receive a standard Stratum V1 job, reconstruct an 80-byte SHA-256d header, and submit a nonce that the Hegemon node independently checks and imports through its normal block validation. SHA-256d means applying SHA-256 twice. Stratum is the newline-delimited JSON mining protocol between a pool controller and miner. Hegemon's complete block metadata and transaction commitments remain bound into the header's 32-byte mining root. This changes the consensus work format and fresh genesis, not transaction proof bytes or monetary policy.

Physical ASIC acceptance needs an actual device. Software acceptance must demonstrate known Bitcoin header vectors, independent Stratum reconstruction, real TCP job/submission traffic, normal Hegemon block import, restart and a second-node import. A simulated protocol test must not be reported as measured hardware TH/s.

## Progress


- [x] 2026-10-02 21:45 UTC: Confirmed current native work is SHA-256d over 64 bytes, native work/submission RPCs are disabled, and PR #205 is green. Created separate follow-up branch; retained the dirty primary checkout and existing artifacts.
- [x] Assigned exclusive write ownership to consensus/header, native job/import, and Stratum adapter workers. Root owns RPC dispatch/policy, integration, shared documents and validation.
- [x] Implement and validate the exact 80-byte work envelope and legacy/new-rule separation; final 45 light-client tests pass.
- [x] Connect CPU mining, bounded jobs, submitted solutions and native import to the same new consensus equation; introduce distinct fresh genesis. Initial three native ASIC tests pass; additional resource/refresh cases are included in the final suite.
- [x] Implement bounded authenticated Stratum V1 adapter and independent protocol tests; final 14 socket cases pass. Focused review fixes preserve retriable solutions and valid same-parent templates without allowing ordinary share accounting to block network solutions or stalled clients to block work polling.
- [x] Real disposable-node test passed again after the retarget fix; the frozen-source run independently solved the header, matched its display hash to the imported block, synced the second node, rejected wrong-time/replayed submissions, and preserved the tip at restart. Final receipt `hegemon-bitcoin80-live-q7smj87q/receipt.json`; no live seed was touched.
- [x] Complete final affected native suite: 753 passed, 0 failed, 10 existing ignored; ASIC import/cache/expiry/refresh and actual height-20 retarget cases included. One cache test was corrected to assert rebuilt contents instead of incidental subsecond timestamp drift.
- [x] Unchanged consensus package suite and native-startup policy check pass.
- [x] Correct the unsigned-compact retarget edge for the new ASIC era; sign-boundary, exponent-33 overflow clamp, strict admission and consistent native template/import/sync/replay tests pass. Frozen new rules hash is `a08fc9ec383eec2bff554c64085bed809160241b89cee84cf2c8f27170a7e41f`.
- [x] Final binary/live validation, formatting, startup policy and correctness/suspicious lint pass after those changes.
- [x] Mechanically refreshed source-policy checks pass: blueprint has 121 nodes and 231 implementation bindings; all 121 external reviews remain pending, with no review-status or proof-claim promotion. The exact 14 governance tests pass.
- [x] Prepare the reviewable stacked follow-up to #205 with exact software evidence, reset instructions and the physical-device validation limitation; publish from the checked branch.

## Surprises & Discoveries


The current 32-byte nonce lies inside the first SHA compression block. Bitcoin ASICs search a four-byte nonce in the second block of an 80-byte header. Adding a network proxy or padding the old message changes neither constraint correctly. Current raw digest comparison is big-endian; Bitcoin ASIC filters expect the Bitcoin digest interpretation. The new function must reverse the raw double-SHA digest into the existing big-endian stored work-hash convention.

Focused review found three mining-yield bugs in the first adapter: permanent
duplicate marking after temporary node refusal, valid block refusal at ordinary
share-cache capacity, and rejection of still-valid same-parent templates.
Separate bounded network reservations, retained same-parent jobs and explicit
`clean_jobs` semantics fix these. A fourth notification-blocking issue is fixed
with one writer and an eight-message outbound queue per bounded connection.
All cases have socket regressions; the reviewer found no remaining actionable
defect in those final changes. This is a focused source review, not hardware
validation or a general security audit.

Final integration found that the historical retarget encoder treats all 24
mantissa bits as unsigned, whereas Bitcoin compact targets reserve the top
mantissa bit as a sign. Initial positive targets passed but a later retarget
could produce a negative Bitcoin nBits. The new era therefore needs explicit
positive canonical compact targets and a fixed maximum of `0x207fffff` across
work preparation, import, sync and replay. Historical codecs and generated
formal schedule vectors remain legacy evidence, not proofs of this new wrapper.

## Decision Log


Use a follow-up branch rather than rewriting the green PR #205 baseline. The user permits a coordinated reset because both miners are theirs, but this implementation does not perform that operational reset or delete any database.

Preserve the existing 713-byte canonical V2 metadata commitment and use a distinct ASIC rules hash. Legacy V1 and legacy-rules V2 light-client hashing remain unchanged. The new native release selects only the new rules and fresh genesis; old persisted state must reject before mutation.

Use an ordinary Bitcoin-shaped work envelope and a structurally serialized, one-input Bitcoin coinbase transaction solely for mining-root construction. It is not a Hegemon reward action or a claim to a valid Bitcoin block/reward. Its scriptSig commits to a domain, the complete canonical Hegemon header prehash and 28 bytes of extra nonce, allowing work-space expansion without changing private transaction proofs. A zero-value OP_RETURN output completes the transaction grammar for firmware that parses Stratum coinbase bytes. The node remains the authority for actual Hegemon coinbase rewards and block validity.

## Context and Orientation


`consensus-light-client/src/lib.rs` defines canonical V2 header serialization, pre-hashing and PoW validation. The existing seal is `SHA256d(pre_hash[32] || nonce[32])`. `node/src/native/node_impl.rs` prepares complete block templates and imports solved templates; `node/src/native/mining.rs` searches nonces. `node/src/native/storage.rs` constructs and verifies genesis. `node/src/native/rpc.rs` dispatches HTTP JSON-RPC and `node/src/native/util.rs` classifies unsafe methods. `scripts/bitcoin_asic_stratum.py` will translate authenticated ASIC connections into node-owned jobs. Existing transaction proof grammar and all state/reward checks are retained.

## Plan of Work


Milestone one adds `consensus-light-client/src/bitcoin_pow.rs`. Its 80 bytes are version (4 little-endian bytes), previous work hash (32 Bitcoin internal-order bytes), mining root (32 raw digest bytes), time (4 little-endian Unix-second bytes), target bits (4 little-endian bytes), and final nonce (4 little-endian bytes). Version is fixed at `0x20000000`. Mining root is double SHA-256 of the serialized coinbase prefix, `nonce[4..32]`, and the fixed serialized suffix. `nonce[0..4]` is the final nonce. The current millisecond timestamp remains committed in the full-header pre-hash; its checked integer division by 1,000 supplies Bitcoin time. Out-of-range time rejects instead of wrapping. The new rule is selected only by a distinct rules hash; the generic legacy function is not silently redefined.

Milestone two uses that helper for both CPU search and solution reconstruction. A bounded job cache retains exact prepared actions, parent, roots, height, timestamp and bits for at most 64 jobs with a 120-second lifetime. Submissions contain only job id, eight-hex-digit numeric nonce, 56-hex-digit raw extra nonce, and the exact job time. The node recomputes the work hash, rejects malformed, expired or stale work, enforces the mining sync gate and network target, and invokes normal import. Work creation and submission remain unsafe administrative RPCs, intended for a trusted loopback adapter. No caller controls block contents, reward recipients, difficulty or state roots.

Milestone three implements real bounded TCP Stratum V1 with subscribe, authorize, notify, set_difficulty and submit. Each connection has a unique 24-byte extra nonce prefix and a four-byte client extra nonce, together forming the 28-byte extra nonce committed by consensus. The notified coinbase prefix/suffix serialize the work transaction; Merkle branches are empty because it is a one-transaction work tree. Version and time rolling are unsupported and explicitly rejected. The adapter checks share hashes and duplicate shares; only full network-target solutions are forwarded to the node. Share difficulty changes accounting only, never consensus difficulty. The default listener is loopback, the operator supplies a worker password, and clients, lines and retained jobs are capped. Documentation explains secure network placement without adding classical TLS to node binaries.

Milestone four validates independently reconstructed headers and actual disposable-node behavior. Only root runs substantial Cargo checks using the warm target and at most two build jobs, with a 16 GiB resident-memory ceiling. Preserve passing unchanged checks. Follow-up publication must distinguish software compatibility from actual unmodified-device acceptance.

## Concrete Steps


Run from `/private/tmp/rp05-ci-20261001.223oOy`:

    CARGO_BUILD_JOBS=2 cargo test --locked --offline -p consensus-light-client
    python3 -B scripts/test_bitcoin_asic_stratum.py
    CARGO_BUILD_JOBS=2 cargo test --locked --offline -p hegemon-node --lib bitcoin_asic
    cargo fmt --all -- --check

Once the software paths pass, run the affected native and light-client suites, targeted generated-vector checks and existing source-policy checks. Record exact commands and results below. Launch demonstration nodes only on loopback with create-only temporary base paths and no public-network seeds. Stop every owned child after validation; leave all pre-existing nodes and databases untouched.

## Validation and Acceptance


A known Bitcoin genesis header produces the exact published raw/display hashes. Independent code reconstructs every notified header byte identically to Rust consensus. Mutating any canonical header commitment, extra nonce, time, bits, final nonce or parent changes/rejects the relevant work. Bitcoin target ordering is checked with asymmetric digests so reversing twice cannot accidentally pass.

A real TCP miner client subscribes, authenticates, receives a job, computes a solution and submits it through the adapter; a running node imports the resulting block. A second temporary node accepts the same persisted block and reopening restores the same height/hash. Wrong password, oversized messages, wrong time, malformed nonce, duplicate share, expired job, stale parent, wrong target and forged reported hash must reject. Old consensus/genesis data must not be reopened as the new era. All unchanged monetary, action, proof and storage checks remain enforced.

## Idempotence and Recovery


All operational checks use fresh temporary directories. Never truncate or remove existing testnet state to force compatibility. A failed implementation remains on the follow-up branch, with the green original commit untouched. The eventual two-host reset requires an explicit release artifact, preserved old data and coordinated configuration; it is not performed by these steps.

## Artifacts and Notes


Root retains focused test logs and a concise validation report under task-specific `/private/tmp` paths and this plan. Public review evidence contains no private wallet keys, credentials or remote host state. The existing proof map remains a proof/release-status map; adding mining features does not close unrelated activation authority.

Final disposable live run hashes are node binary
`02225c49bfa56c36a0f34b01eb47eeaa23ad5c72240a70c795d1eb1c2996c040`,
adapter `06268785b8a09e8bd603d2b508e999e52947756e98dae7ff8d4627133ae757cd`,
and harness `6fef385fe2ebc74b4e6d3a17c4c442e66d77b05687164c5bfff37563886f08b6`.
The 80-byte header was
`00000020e7844baa7172727ecdfe9d9d1a9ed77f5b21f7b66099ad780538a3fd10e8ec61ee32fa5b6b940caee0251b7caa3dc7769346e2ce34e44023c58dd13995d7b2721535c06af7c6101e9bc20c00`;
both nodes accepted display hash
`0000064a7b55fc32157c05c8865775b93d480858b5cdfc571d49891a4031294d`
at height 1. The first node reopened at exactly that tip. Tests use no miner
address and forfeit rewards; this is PoW transport/import validation, not a
new qualification of shielded coinbase proof generation or hardware throughput.

## Interfaces and Dependencies


Reuse SHA-256, BLAKE3, serde JSON, Tokio and the existing node importer. The Python adapter uses only the standard library. Native methods are `bitcoin_asic_work() -> Result<Value>`, `bitcoin_asic_submit(Value) -> Result<Value>` and `bitcoin_asic_status() -> Value`, exposed through the existing pool RPC method names. Returned work identifies `sha256d-bitcoin80`, exact header80 bytes, job id, parent hash, fixed version, time, bits, full target, coinbase prefix/suffix and extra nonce size. Node import never trusts an external claimed hash.

## Outcomes & Retrospective


The software work envelope, native job/import path and bounded Stratum service
are implemented and pass focused plus live two-node acceptance and current
source-policy checks. The reviewable follow-up is prepared for publication from
the checked branch. No physical ASIC test, existing
testnet-service restart, deletion, mainnet activation or measured TH/s is claimed.

Revision 2026-10-02 21:45 UTC: created the implementation plan for the authorized ASIC-format follow-up, separating consensus, protocol integration and hardware acceptance.
