# Native wallet first-scan investigation

This investigation accompanies the v0.10.3 maintenance preparation. The performance baseline uses the exact published v0.10.2 ARM64 node/walletd binaries; transport/default and desktop deadline repairs do not change its scan algorithm. The user's roughly one-hour slow-VPS scan is reported evidence, not a timing reproduced on that VPS.

## Why a first scan does substantial work

A synced node and a synced wallet are different states. A fresh wallet must download every canonical commitment, reconstruct the commitment tree and compare its root, try decrypting every encrypted note to find its own rewards, and check spent nullifiers. A reward cannot be located by a public owner field in this path. Increasing node height alone does not populate wallet balances.

`wallet/src/async_sync.rs::sync_once` performs those phases sequentially with 256-entry pages. Its node RPC deadline is per request, not a deadline for the complete historical scan. HTTP page errors propagate; the engine allows at most one consistency-triggered reset/retry. A successful first scan can therefore legitimately exceed one minute.

## Confirmed source costs

`WalletStore::append_commitments_with_sources` and `apply_ciphertext_batch` call `with_mut`, which serializes and encrypts the entire wallet state, writes a new file, fsyncs it and atomically replaces the old file after every page. Commitment pages rewrite a growing array; ciphertext pages rewrite the completed commitment array even when no owned notes are found. With N commitments and ciphertexts and page size p, their combined leading serialized payload is about 90*N*N/p bytes, before owned-note and fixed overhead. At 117,100 leaves and p=256 that is approximately 4.8 GB processed repeatedly, across about 916 page persistence barriers. This is a source-based estimate, not measured physical disk traffic.

`IncomingViewingKey::decrypt_note` derives diversified ML-KEM-1024 address key material for every ciphertext. Repeated mining outputs with the same diversifier index repeat deterministic key generation, followed by a necessary decapsulation trial. A bounded, zeroizing scan-local key cache could amortize key generation, but this maintenance patch does not change cryptographic key lifetime or note acceptance.

`WalletStore::commitment_tree` appends every stored leaf into a depth-32 Poseidon tree on first access. Each append hashes 32 ancestors. This is linear in leaves for one first scan. Reopening the wallet loses the in-memory tree cache, and a later commitment append invalidates it, so another CLI process can repeat full-history tree work even when little has changed. No root verification is skipped in this repair.

The v0.10.2 node already caches canonical commitment-source labels as an in-memory prefix. Cold extension still decodes and hashes historical block action bodies once; warm pages reuse that work. This removes the old repeated whole-chain reconstruction per page, while cold startup and first archive access remain expensive.

## Desktop interruption repaired

The old renderer aborted ordinary sync after 90 seconds; its walletd bridge independently timed out requests after ten minutes. Those limits interrupt a healthy first scan rather than make it faster. Both sync-specific overall defaults now allow two hours. Individual node RPC deadlines, cancellation, other walletd operation limits and explicit operator overrides retain their behavior. At deadline the UI invalidates the unlocked session synchronously, starts daemon cleanup, and settles the timeout independently if cleanup is unresponsive. The chain-reset option is labeled according to its actual genesis-mismatch semantics.

## Measurement method and results

The bounded experiment uses one offline relay on an APFS clone of a closed public-chain snapshot, mining/bootstrap disabled, empty seeds, quarantined clone-only peer cache, and loopback listeners. It uses a disposable fresh wallet and read-only HTTP measurement proxy. Receipts retain method/page/count/byte/timing metrics and public height/root facts; private wallet outputs and passwords are omitted. The retained source snapshot is fingerprinted before and after and is never opened by the experiment node.

Two setup attempts produced no wallet timing: an IP-only listen address was invalid, then the recorded height-117050 hash was incorrectly checked at tip 117051. Both exited cleanly and preserved source fingerprints. The final harness was independently reviewed before a separate twelve-minute bounded window; it verifies the recorded canonical anchor at 117050, the separate tip at 117051, genesis, zero peers/mining and stable public roots. All observations are saved before assertions. The P2P listener is loopback-only, seeds/imported peers/relays are empty and the clone-only peer cache is quarantined. `HEGEMON_MAX_PEERS=0` means unlimited capacity in this implementation, so it is not the isolation mechanism.

The exact released v0.10.2 fresh wallet scan completed through HTTP and returned the expected 117,100 commitments and ciphertexts at height 117,051, with no owned notes or balances in the disposable wallet. Measurements are on an Apple M2 Mac with 24 GiB RAM and concurrent background work; they do not reproduce the user's VPS.

| Measurement | Observed |
| --- | --- |
| Fresh sync.once response | 176.271 seconds |
| Fresh wallet process/status completion | 176.339 seconds |
| Wallet CPU | 139.479 seconds user + 2.438 seconds system |
| Commitment RPC/page-processing span | 21.128 seconds |
| Final commitment response to first ciphertext request | 116.436 seconds with no RPC requests |
| Ciphertext RPC/page-processing span | 38.503 seconds |
| HTTP calls and returned bytes | 923 calls; 370,127,520 bytes (about 353 MiB) |
| Total node upstream response time | 13.053 seconds |
| Proxy forwarding overhead beyond upstream | About 0.122 seconds |
| Commitment / ciphertext page counts | 458 / 458 |
| Commitment page median / p95 response | 16.10 / 40.50 milliseconds |
| Ciphertext page median / p95 response | 6.69 / 30.00 milliseconds |
| Offline node startup/replay, excluded from wallet scan | 411.318 seconds |

The 116-second gap is about 66% of fresh-scan wall time. A bounded one-second stack sample captured 799 samples under `WalletStore::commitment_tree`, predominantly `CommitmentTree::append`, Merkle node hashing and Poseidon2 permutations. Wallet CPU rose almost one second per elapsed second during the gap. This directly identifies a local full-tree reconstruction cost, rather than waiting for a node request during that interval. A separate ciphertext-phase sample includes whole-store ChaCha20-Poly1305 encryption/persistence and ML-KEM key/decapsulation work; those samples establish presence, not exact whole-phase percentages for each function.

A second process reopened the same disposable store. It issued only six metadata/note calls and then spent more than a minute of CPU rebuilding the same commitment tree despite no new blocks. It reached the remaining experiment deadline during that rebuild and was stopped cleanly. The full experiment therefore has a false acceptance flag with `WalletScanDeadline` in the incremental phase; only the completed fresh scan is a successful timing result. This does not establish a failed wallet recovery or an incremental completion time. The generic harness directory-size field is invalid for this single-file store and is not used as evidence; a separate stat-only observer recorded actual file growth and a final encrypted single-file size of 7,026,858 bytes. The source-based 4.8 GB repeated-write estimate above is not a measured disk-write count.

Receipts are retained under `/private/tmp/hegemon-wallet-http-sync-investigation/baseline/attempt3/`: `initial-summary.json`, public start/end probes, request timings, bounded stack samples and the final baseline summary. The final receipt records 692.750 seconds overall, a clean node exit with durable shutdown/no flush failure, closed owned processes/listeners/sampling watchers and identical retained source byte and non-access-time metadata fingerprints. No additional attempt was run. The end-of-scan public probe was not reached after the incremental deadline; stable start/end equality is not claimed for the whole experiment.

## Follow-up priorities

The measured priority is commitment-tree construction: investigate a bulk canonical rebuild and incremental/persistent tree caching while preserving required roots, inclusion proofs and history semantics. Root equality and recovery/reopen/reorg checks must precede any speed claim. Next measure bounded checkpoint persistence with failure/resume coverage and a bounded zeroizing diversified-key cache. Larger pages reduce repeated writes but retain their quadratic scaling and make cold archive requests hold the node read lock longer. None of these candidates has been implemented or benchmarked as an improvement here. Host CPU speed, disk fsync latency, CPU steal/throttling and mining competition must be measured on the user's VPS before assigning its absolute one-hour duration to a specific cost.
