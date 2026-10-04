# Threat Model

This document explains the attacker capabilities and design assumptions for each subsystem. Keep it synchronized with `DESIGN.md §0-3` and `METHODS.md §Threat Monitoring` whenever behavior or mitigations change.

## Global assumptions

- **Post-quantum only**: Attackers may possess Shor-class quantum computers capable of collapsing classical public-key systems. We therefore forbid ECC/RSA and rely on ML-DSA/SLH-DSA signatures, ML-KEM encryption, 256-bit symmetric primitives, and 48-byte (384-bit) digests for commitments and Merkle roots. Generic quantum search remains a conservative sizing consideration for the symmetric/hash layer, not the primary protocol threat.
- **Transparent proving**: There is no trusted setup. Deployed soundness depends on the SmallWood algebraic reduction, Merkle/transcript hash assumptions, the ideal-QROM-to-SHA-512 instantiation bridge, semantic refinement, and compiled-verifier correspondence described in `DESIGN.md §2`; the last three are not yet discharged by an end-to-end theorem. Compromise of a setup ceremony is out-of-scope because none exists.
- **Adaptive adversaries**: Attackers can corrupt miners, mining pools, or wallets after observing traffic. Key rotation, nullifier privacy, and block template integrity must hold even with partial compromise.
- **Proof-of-work fairness**: Hash-rate swings and rented rigs are assumed. Difficulty targeting plus share accounting must resist sudden 51% bursts for at least 10 minutes while alerts propagate to pool maintainers.

## Component-specific threats

### `crypto/`

- **Keygen misuse**: Attackers might attempt to bias RNGs or turn public transcripts into predictable key material. Production KEM encapsulation and identity/key generation use OS entropy; explicit deterministic seeds are test-only fixtures and must never be derived from public transcripts.
- **Serialization downgrade**: Incorrect key lengths lead to acceptance of weak keys. All APIs perform length checks and return errors that bubble up to consensus/wallet callers.

### `circuits/`

- **Soundness breaks via stale constraints**: Transaction/block circuits must include the latest nullifier/account rules. Circuit README + benchmarking harness describe how to recompile constraints and run proofs.
- **Witness leakage**: Benchmarks never persist witness data to disk; they scrub buffers after proof verification to prevent info leaks during profiling.
- **Proof bypass**: Production verification rejects missing STARK bytes or public inputs; no legacy/fast authoring path is active. Historical V2/Beta and V3/Beta decoders remain compatibility code, but native block import can reach them only through an explicit height-bounded manifest authorization; the production manifest currently authorizes no historical binding.
- **Encoding malleability**: Commitments/nullifiers are 48-byte encodings of six field limbs; any limb ≥ field modulus is rejected to avoid alternate encodings.
- **Balance-tag substitution**: A native `tx_leaf` must not choose an arbitrary outer balance tag that is merely self-consistent with its receipt. The verifier reconstructs the canonical balance tag from the exact transaction verifier inputs, requires equality with the public transaction tag, and only then invokes the embedded SmallWood proof verifier.
- **Public-input aliases and anchor substitution**: Native tx-leaf projection rejects Goldilocks-reduced raw asset aliases, non-canonical padding/stablecoin ids, over-range signed magnitudes, and negative zero. Artifact binding directly compares the decoded statement Merkle root with the action anchor instead of relying only on two equal binding hashes.

### `network/`

- **Peer impersonation**: PQ transport identities must be derived from secret seeds stored with restrictive permissions (0600) or supplied via secure env overrides; seeds must never be derived from public peer IDs to prevent key prediction.

### `consensus/`

- **Network DoS**: Attackers flood PQ-sized signatures and large STARK proofs. The Go net benchmark evaluates miner and pool throughput budgets with inflated payloads, and `METHODS.md` documents required admission-control thresholds for share telemetry.
- **Native RPC parser DoS**: External JSON-RPC listeners must reject request bodies above 8 MiB and cap concurrent in-flight RPC requests at 8 before JSON parsing can fan out resource use. DA sidecar proof batches are chunkable and must not rely on one large aggregate JSON upload.
- **Pending-proof persistence and verifier starvation**: A structurally valid but cryptographically invalid relayed artifact must never persist and poison every mining template. Local and peer shielded actions verify before mempool publication; semantic-hash single-flight, bounded deterministic-failure caching, and separate one-lane peer/local/template quotas under a three-lane cap prevent timestamp replay, unbounded verifier fan-out, and peer starvation of authoring. Startup and template recovery durably remove only independently invalid actions and preserve valid siblings.
- **V8 batch ordering and resource exhaustion**: A block or mempool batch may carry at most 512 V8 actions, while each full canonical record and the exact 64 MiB aggregate encoded-action budget are checked independently. At one stablecoin root, source-verified disabled/no-write actions are ordered by canonical action id before the single permitted mint or burn edge; only advancing edges are cycle-checked. The security report still charges 523 proofs per block, so its union count conservatively exceeds the runtime ceiling.
- **Same-block shielded output spend**: Every V8 action's note anchor must be in the retained canonical note-root history as it existed before the block. Roots created by earlier actions or coinbase in the same block are ineligible, matching the wallet rule that an output becomes spendable only after mining and synchronization.
- **Unauthorized mint staging**: Candidate artifacts and externally submitted coinbase actions are not mempool routes. Mining constructs its own coinbase after transfer selection, so submitted or persisted mint rows cannot consume action budgets or redirect miner rewards.
- **Forking via outdated PQ params**: Consensus nodes pin ML-DSA and ML-KEM parameter sets and reject blocks signed with unknown variants so malicious pools cannot replay stale templates.
- **Miner impersonation**: Share submissions must be signed with approved miner identities; consensus rejects unbound identities even if the PoW difficulty is valid.
- **Aggregation proof malleability**: Outer proofs must be bound to the exact inner proofs/public inputs; nodes recompute recursion public inputs from transaction proofs and verify aggregation proofs with explicit public values, rejecting missing or mismatched proofs.
- **Proof-version downgrade and recursive-artifact injection**: Mined, announced, replayed, and sync-imported native blocks converge on one next-height proof-policy gate before raw proof decoding or verification. Active blocks admit V4/Gamma. V2/Beta, V3/Beta, and recursive candidate artifacts require separate explicit, inclusive historical height ranges in the release manifest; both historical authorization lists are empty in the production manifest, so compatibility decoders alone grant no block-validity authority.

### `wallet/`

- **View-key compromise**: Full viewing keys include a view-derived nullifier key (`view_nf`) for spentness tracking but do not embed `sk_spend`; compromise exposes nullifier tracking but not extrinsic signing keys.
- **Metadata leakage**: Wallet bench stresses note batching to keep `rho` diversifiers unpredictable even under load.
- **Disclosure package leakage**: Payment-proof packages include value, asset id, recipient address, commitment, and anchor. Wallet stores encrypt outgoing disclosure records and CLI verification enforces canonical encodings, genesis-hash checks, and on-chain anchor validation to limit replay and tampering risks.

## Security margins

- **Signatures**: Target ≥ 128-bit PQ security (ML-DSA-65 / SLH-DSA-128f). Keys larger than spec are rejected.
- **KEM**: ML-KEM-1024 for note encryption and PQ transport handshake. Shared secrets truncated to 256 bits of entropy.
- **Hashes**: SHA-256/BLAKE3 externally, Poseidon2 field hash internally (width 12, rate 6, capacity 6, 48-byte outputs).
- **Proving**: The retained SmallWood profile has a conditional 262.3777366-bit interactive bound from its actual parameters. Its ideal finite-query calculation gives 130.7927741 bits at `2^64` quantum queries and failure probability 0.1443083 at `2^128` queries. Production soundness remains unavailable and the route remains disabled until the conventional-hash relation, complete zero knowledge, concrete hash reductions, and compiled-verifier refinement are complete. No end-to-end counterfeit is recorded; the retained Poseidon2 digest has a separate generic quantum collision limit near `2^128` queries, which is not itself a transaction forgery.

When implementation shifts any of these values, update this document alongside the relevant design/method sections.
