## 0. Design goals (what we’re optimizing for)

I’d keep (roughly) Zcash’s original goals, updated for 2025:

1. **One canonical privacy pool** (no Sprout/Sapling/Orchard zoo).
2. **End-to-end PQ security**

   * No ECC, no pairings, no RSA anywhere.
   * Only:

     * Lattice-based KEM/signatures (NIST PQC: ML-KEM, ML-DSA, etc.), ([NIST][1])
     * Hash-based commitments, Merkle trees, PRFs,
     * Hash-based or STARK-style ZK.
3. **Transparent proving system**

   * No trusted setup.
   * SNARK/STARK based only on collision-resistant hashes (FRI-style IOPs etc.). ([C# Corner][2])
4. **Bitcoin-like mental model**: UTXO-ish “notes” with strong privacy, plus viewing keys.
5. **Upgradability**: built-in versioning and “escape hatches” for *future* PQ breaks.
6. **Secure, seamless, delighting UX**: wallet, governance, and miner/operator touchpoints must keep the PQ stack invisible,
   provide ergonomic flows across devices, and surface positive confirmation cues so users feel safe and delighted without
   facing operational friction.

Everything else is negotiable.

---

### 0.1 Explicit overheads relative to Zcash

Contributors routinely ask how these PQ and MASP design choices differ from Zcash’s Sapling/Orchard stack. The high-level costs
are:

* **Cryptographic payload sizes** – ML-DSA/ML-KEM artifacts are orders of magnitude larger than the ECC keys, signatures, and
  ECIES ciphertexts Zcash uses today. Even though the spend circuit keeps Sapling’s “prove key knowledge inside the ZK proof”
  model (so there are no per-input signatures), block headers, miner identities, and the note encryption layer all absorb PQ
  size bloat: ML-DSA-65 pk = 1,952 B vs ~32 B Ed25519, signatures = 3,293 B vs ~64 B, ML-KEM ciphertexts (note encryption)
  = 1,568 B vs ~80–100 B for Jubjub-based ECIES. Runtime AccountIds hash PQ public keys with BLAKE2 into SS58-compatible 32-byte
  identifiers so extrinsic signing and PoW seal verification share the same PQ scheme without changing address encoding.
  Network/consensus plumbing must therefore expect materially larger payloads.
* **Proof sizes and verification latency** – Trading Groth16/Halo2 for a transparent STARK stack removes the trusted setup but
  makes proofs much chunkier: tens of kilobytes with verifier runtimes in the tens of milliseconds, versus sub-kilobyte Groth16
  proofs with millisecond verification. The spend circuit, memo ciphertexts, and block propagation logic all need to budget for
  that bandwidth/latency overhead.
* **Circuit-level MASP costs** – Supporting multi-asset notes requires in-circuit sorting/aggregation of `(asset_id, delta)`
  tuples, introducing an \(O((M+N) \log (M+N))\) constraint factor that Sapling’s single-asset equations avoid. We explicitly
  accept this blow-up because it stays manageable at Zcash-like `M, N` and keeps the user model aligned with today’s MASP work.

These considerations don’t change the core protocol, but they should show up in performance estimations, benchmarking, and any
communication that compares this system to the status quo.

---

## 1. Cryptographic stack (primitives only)

### 1.1 Signatures

Use *only* NIST PQC signatures:

* Primary: **ML-DSA** (Dilithium, FIPS 204) for “everyday” signatures. ([NIST][1])
* Backup: **SLH-DSA** (SPHINCS+, FIPS 205) for long-lived roots of trust (genesis multisig, governance keys, etc.). ([Cloud Security Alliance][3])

Where they're used:

* **Consensus / networking**:

  * Block producers sign block headers with ML-DSA.
  * Mining node identity keys = ML-DSA.
  * PQ network identity seeds are generated from OS entropy, persisted under the node base path (for example `pq-identity.seed`) or provided via environment override, and never derived from public peer IDs.
  * Identity/session records store optional PQ session keys via `SessionKey::PostQuantum` (Dilithium/Falcon); registrations provide PQ bundles through `pallet_identity::register_did`.
* **User layer**:

  * Surprisingly little: within the shielded protocol, we can get rid of *per-input signatures* entirely and instead authorize spends by proving knowledge of a secret key in ZK (like Zcash already does with spend authorizing keys; here we do it with hash/lattice PRFs rather than ECC).

So: signatures are *mostly* a consensus/network thing, not something you see for each coin input.

---

### 1.2 Key exchange / encryption

For note encryption and any “view key” derivation:

* Use **ML-KEM-1024 (Kyber, FIPS 203)** as the KEM to establish shared secrets. ([NIST][1])
* Use a standard AEAD like **AES-256-GCM** or **ChaCha20-Poly1305**:

  * Symmetric is already “quantum-ok” modulo Grover; 256-bit keys give you ~128-bit quantum security.

Design pattern:

* Each address has a long-term **KEM public key** `pk_enc` and an explicit `crypto_suite` identifier.
* For each note, sender:

  * encapsulates to `pk_enc`,
  * runs a KDF on the shared secret plus `crypto_suite` to get the AEAD key and nonce,
  * authenticates `(address_version, crypto_suite, diversifier_index)` as AEAD AAD.

This is directly analogous to ECIES-style note encryption in Zcash, but with ML-KEM.

---

### 1.3 Hashes, commitments, PRFs

To avoid any discrete-log assumptions:

* **Global hash**:

  * Use something boring and well-analyzed like **BLAKE3** (preferred) or **SHA3-256** as the global hash for block headers, Merkle trees, etc.
  * 256-bit outputs ⇒ ~128-bit security under Grover. ([ISACA][4])
* **Field-friendly hash for ZK**:

  * Inside the STARK, use a hash designed for Fp (e.g. Poseidon-ish / Rescue Prime / any modern STARK-friendly permutation).
  * These are *purely algebraic permutations*, so they rely on symmetric-style assumptions and are fine for PQ (again, Grover only).
  * Recursive Fiat–Shamir transcripts should use an in-field hash (Rpo256/Rescue-style) so the recursive verifier can recompute Merkle openings in-circuit without leaving the base field.

Commitments:

* **Hash-based commitments** everywhere with PQ-friendly digests. A minimal design:

  * `Com(m, r) = H("c" || m || r)` with `H = BLAKE3-256` by default (or SHA3-256 when aligning with STARK hash parameters) is the commitment to `m` with randomness `r`.
* **Note commitment tree**:

  * Same conceptual tree as Zcash, but using the global hash or the STARK hash consistently; no Pedersen, no Sinsemilla, no EC cofactor dance.

PRFs:

* All “note identifiers”, nullifiers, etc. are derived with keyed hashes (BLAKE3-256 or SHA3-256, matching the commitment domain separation):

  * `sk_nf = H("view_nf" || sk_view)`
  * `nk = H("nk" || sk_nf)`
  * `nullifier = H("nf" || nk || note_position || rho)`

No group operations anywhere in user-visible cryptography.

STARK verifier parameters (hash function choice, query counts, blowup factors, field extension) are persisted on-chain in the attestations and settlement pallets with governance-controlled upgrade hooks so proof verification stays aligned with PQ-friendly hashes. The runtime seeds attestations with Poseidon2-based hashing (48-byte digests), 43 FRI queries, a 16x blowup factor (log_blowup 4), and quadratic extension over Goldilocks; settlement uses the same hash/query budget. With 384-bit digests, PQ collision resistance reaches ~128 bits for application-level commitments, and 48-byte encodings are used end-to-end.

### 1.4 Reference module layout

The repository now includes a standalone Rust crate at `crypto/` that collects the post-quantum primitives into a single API suiting the plan above. The crate exposes:

* `ml_dsa` – deterministic key generation, signing, verification, and serialization helpers sized to ML-DSA-65 (Dilithium3) keys (pk = 1952 B, sk = 4000 B, sig = 3293 B).
* `slh_dsa` – the analogous interface for SLH-DSA (SPHINCS+-SHA2-128f) with pk = 32 B, sk = 64 B, signature = 17088 B.
* `ml_kem` – Kyber-1024-style encapsulation/decapsulation with pk = 1568 B, sk = 3168 B, ciphertext = 1568 B, shared secret = 32 B.
* `hashes` – SHA-256, SHA3-256, BLAKE3-256, and a Poseidon-inspired permutation over the Goldilocks prime using width 3, 63 full rounds, and NUMS-generated round constants/MDS (SHA-256 domain separation + Cauchy matrix), plus helpers for commitments (`b"c"` tag), PRF key derivation (`b"nk"`), and nullifiers (`b"nf"`) that default to BLAKE3 with SHA3 fallbacks for STARK-friendly domains. The Plonky3 transaction AIR uses Poseidon2 (width 12, rate 6, capacity 6) for in-circuit commitments and nullifiers, producing 48-byte outputs for PQ soundness; application-level types now use 48-byte digests end-to-end.

Everything derives deterministic test vectors using a ChaCha20-based RNG seeded via SHA-256 so that serialization and domain separation match the simple hash-based definitions above. Integration tests under `crypto/tests/` lock in the byte-level expectations for key generation, signing, verification, KEM encapsulation/decapsulation, and commitment/nullifier derivation.

### 1.5 External cryptanalysis cadence

Every time we tweak the parameter sets above—or annually even without code drift—we commission an external lattice/hash review as captured in `docs/SECURITY_REVIEWS.md`. Vendors receive `DESIGN.md §1`, `METHODS.md`, and the relevant source paths (`crypto/`, `circuits/transaction-core/src/hashing_pq.rs`, `circuits/transaction-core/src/poseidon2_constants.rs`) so they can re-derive the Poseidon/Poseidon2 constants and deterministic RNG taps we use for ML-DSA, ML-KEM, and SLH-DSA. Findings are logged using the JSON template in the same doc and each accepted change must reference that ID inside this file plus `METHODS.md`. This keeps the declared parameter choices in sync with the state of the art in lattice reduction and ensures that side-channel or collision discoveries are reflected in our primitives immediately.

---

## 2. ZK proving system: single STARKish stack

Rather than BCTV14 → Groth16 → Halo2, we pick **one** family: hash-based IOP → STARK-style.

Properties:

* **Transparent**: no trusted setup (only hash assumptions). ([C# Corner][2])
* **Post-quantum**: soundness reduces to collision resistance of the hashes + random oracle, so Shor has nothing to grab; Grover just reduces effective hash security by ~½.
* **Recursive-friendly**: pick something in the Plonky2/Plonky3 space that supports efficient recursion and aggregation. ([C# Corner][2])

Concretely:

* Base field: a 64-bit-friendly prime like 2⁶⁴×k−1 suitable for FFTs and FRI.
* Prover:

  * CPU-friendly (no big-integer pairings).
  * Highly parallelizable (good for GPU/prover markets).
* Verifier:

  * Proof sizes are materially larger than SNARKs; with 48-byte digests and a 128-bit PQ target, single-transaction Plonky3 proofs are currently hundreds of kB (≈357KB for the release `TransactionAirP3` e2e test).

**Lesson from Zcash:** we do *not* change proving systems mid-flight if we can avoid it. We pick one transparent, STARK-ish scheme and stick with it, using recursion for evolution rather than entire new pools.

Implementation detail: the Plonky3 backend uses `p3-uni-stark` (v0.4.x). For the transaction AIR, fixed schedule selectors (Poseidon round flags, cycle markers, and row-specific assertions) are embedded as explicit schedule columns in the main trace; this keeps the schedule deterministic while avoiding preprocessed-trace OOD mismatches. Other circuits may still use preprocessed columns where stable.

#### 2.1 Algebraic embeddings that claw back overhead

The transparent stack above is heavier than Groth16/Halo2, but a few circuit-level embeddings keep it manageable:

* **Goldilocks-friendly encodings** – Express the note/balance logic directly in the 64-bit-friendly base field instead of relying on binary gadgets. Packing `(value, asset_id)` pairs into two 64-bit limbs each lets the AIR use cheap addition/multiplication constraints with no Boolean decomposition. This matches Plonky3’s Goldilocks optimizations and avoids the \((\times 32\) blow-up you’d get from bit-constraining every register.
* **Permutation/Ishai–Kushilevitz style lookups** – MASP balance checks need large-domain comparisons (e.g., `asset_id` equality during the in-circuit sort). Encoding those comparisons as STARK-friendly permutation arguments—rather than explicit comparator circuits—reuses the same algebraic lookup table that the prover already commits to for Poseidon rounds. Empirically this trims ~15–20 % of the trace width relative to naive comparison gadgets while remaining transparent.
* **Batched range proofs via radix embeddings** – Instead of per-note binary range proofs, embed values in radix-`2^16` limbs and reuse a single low-degree check `limb < 2^16` over the entire column. A single lookup table enforces limb bounds, and the batched sum-check amortizes across all limbs, driving the marginal cost per constrained value close to 1–2 constraints.
* **Folded multi-openings for recursion** – Recursively verifying child proofs requires many polynomial openings; batching them through a single FRI transcript with linear-combination challenges keeps the verifier time in the "tens of ms" bucket despite the larger STARK proofs.

None of these tricks negate the inherent bandwidth hit of transparent proofs, but they make the witness columns thinner and the constraint system shallower so that prover time and memory stay near the Zcash baseline even with PQ primitives.

### 2.5 Formal verification and adversarial pipelines

The `circuits/formal/transaction_balance.tla` model captures the MASP balance rules (nullifier uniqueness + per-asset conservation) using a compact TLA+ spec. Any change to the AIR/witness layout must update that spec plus rerun TLC/Apalache, recording the outcome in the associated README and in `docs/SECURITY_REVIEWS.md`. On the implementation side, `circuits/transaction/tests/security_fuzz.rs` performs property-based fuzzing of `TransactionWitness::balance_slots` and `public_inputs` to catch serialization edge cases. Both the formal model and the fuzz harness are wired into the `security-adversarial` CI job, so contributors get immediate feedback when the balance/tag logic drifts.

---

## 3. Ledger model: one PQ shielded pool, no transparent pool

### 3.1 Objects: notes and nullifiers

We keep the Zcash mental model, but trimmed:

* A **note** is a record:

  * `value` (e.g. 64-bit or 128-bit integer)
  * `asset_id` (for a MASP-like multi-asset pool)
  * `pk_view` (recipient’s viewing key material, see below)
  * `rho` (per-note secret)
  * `r` (commitment randomness)
* The chain stores only:

  * a **commitment** `cm = Com(value, asset_id, pk_view, rho; r)` (48-byte, 6-limb encoding),
  * a Merkle tree of note commitments,
  * a **nullifier** `nf` when the note is spent (48-byte, 6-limb encoding).

The ZK proof shows:

* “I know some opening `(value, asset_id, pk_view, rho, r)` and nullifier secret `sk_nf` such that:

  * `cm` is in the tree,
  * `nf = PRF(sk_nf, rho, position, …)`,
  * total inputs = total outputs (value-conservation),
  * overflow conditions don’t happen.”

No ECDSA/EdDSA/RedDSA anywhere; the “authorization” is just knowledge of `sk_nf` inside the ZK proof.

Note: the switch to 6-limb 48-byte commitment/nullifier encodings is protocol-breaking. Any chain spec
that adopts this encoding requires a fresh genesis and wiping `node.db` plus wallet stores.

### 3.2 Transaction structure

A transaction includes:

* List of **input nullifiers** `nf_i`.
* List of **new note commitments** `cm_j`.
* Encrypted **note ciphertexts** for recipients (KEM+AEAD).
* One or more **STARK proofs** attesting the statements above.

Consensus checks:

* All `nf_i` are unique and not previously seen.
* STARK proofs verify.
* Block value balance is respected (including fees and issuance).

The PoW fork mirrors Bitcoin/Zcash mechanics so operators can reason about liveness intuitively:

* Block headers expose an explicit `pow_bits` compact target, a 256-bit nonce, and a 128-bit `supply_digest`. Miners sign the
  full header (including the supply digest) with ML-DSA and then search over the nonce until `sha256(header) ≤ target(pow_bits)`.
  A zero mantissa is invalid, and every PoW header must carry the seal (there is no “missing” difficulty case between retargets).
* Difficulty retargeting is deterministic: every `RETARGET_WINDOW = 10` blocks the chain recomputes the target from the window's
  timestamps, clamping swings to ×¼…×4 and aiming for a `TARGET_BLOCK_INTERVAL = 60 s` (1 minute). Honest nodes reject any block whose
  `pow_bits` diverges from this schedule, which makes retarget spoofing impossible even across deep reorgs. Blocks between
  retarget boundaries MUST inherit the parent’s `pow_bits` verbatim and the retarget math uses the clamped timespan so outlier
  timestamps cannot skew difficulty even after a reorg.
* Each PoW block carries a coinbase commitment—either a dedicated transaction referenced by index or a standalone `balance_tag`
  —that spells out how many native units were minted, how many fees were aggregated, and how many were burned. Consensus enforces
  `minted ≤ R(height)` where `R()` starts at `50 · 10⁸` base units and halves every `210_000` blocks (height 0 mints nothing).
  Nodes update the running `supply_digest = parent_digest + minted + fees − burns` inside a 128-bit little-endian counter that
  rejects underflows/overflows and compare it against the header before accepting the block. Coinbase metadata that omits the
  balance tag or references an out-of-bounds transaction index fails validation.
* Data availability is enforced via `da_root` and `da_params` in the header. The block’s ciphertext blob is serialized in
  transaction order with length prefixes, erasure-coded with 1D Reed–Solomon (`p = ceil(k/2)` parity shards over `k` data shards),
  and Merkleized with BLAKE3 under `da-leaf`/`da-node` domain tags. Validators recompute `da_root` from the payload, then sample
  `da_params.sample_count` shard indices using per-node randomness and refuse to relay or extend blocks when any sampled proof fails.
* Timestamp guards match the implementation: the header time must exceed the median of the prior 11 blocks and be no more than
  90 seconds into the future relative to the local clock; nodes may re-evaluate future-dated candidates as time advances but
  still reject any header that remains beyond the skew bound or fails median-time-past.
* Block template helpers in `consensus/tests/common.rs` show how miners wire these fields together: compute the note/fee/nullifier
  commitments, attach the coinbase metadata, recompute `supply_digest`, and only then sign + grind the header.

No transparent outputs; everything is in this one PQ pool from day 1.

Substrate RPC extensions in `node/src/substrate/rpc` expose that state machine so operators can monitor the same fields remotely. `/blocks/latest` and `/metrics` stream hash rate, mempool depth, stale share rate, best height, and compact difficulty values that miners compare against the reward policy in `pallets/coinbase/src/lib.rs`. Per `TOKENOMICS_CALCULATION.md`, the initial block reward is ~4.98 HEG (derived from the 60-second block time), and epochs last 4 years (~2.1M blocks). Every mined block updates the header’s `supply_digest`, and the quickstart playbook in [runbooks/miner_wallet_quickstart.md](runbooks/miner_wallet_quickstart.md) walks through querying those endpoints before wiring wallets to the node API. Substrate integrations reuse the same machinery: the `consensus::substrate::import_pow_block` helper executes the PoW ledger checks (version-commitment + STARK commitments + reward checks) as blocks flow through a Substrate import queue, and the node exposes `/consensus/status` to mirror the latest `ImportReceipt` alongside miner telemetry so the benchmarking tools under `consensus/bench` see consistent values.

### 3.3 Shielded stablecoin issuance

Stablecoin issuance and burn are modeled as a non-native MASP asset that lives entirely inside the shielded pool. Instead of exposing a transparent mint, the transaction circuit allows a single asset id to carry a non-zero net delta, but only when the proof binds to an on-chain policy hash plus the latest oracle and attestation commitments. The policy lives in `pallets/stablecoin-policy` and is hashed with BLAKE3 under the `stablecoin-policy-v1` domain so the circuit can consume a single 48-byte value. The verifier in `pallets/shielded-pool` checks that the policy hash, policy version, oracle commitment freshness, and attestation dispute status match chain state before accepting the proof.

Issuance and burn therefore stay shielded: the proof shows `inputs - outputs = issuance_delta` for the stablecoin asset, and the runtime rejects any stablecoin binding supplied via the unsigned path. Wallet tooling assembles the binding by reading `StablecoinPolicy`, `Oracles::Feeds`, and `Attestations::Commitments`, then submits a signed `shielded_transfer` extrinsic so role checks and replay protection remain in place. Normal stablecoin transfers do not require a binding, but they still ride the same MASP rules and never leave the privacy pool.

---

## 4. Addresses and keys (PQ analogue of Sapling/Orchard)

We still want:

* **Spending keys**
* **Full viewing keys**
* **Incoming-only viewing keys**
* Public addresses derived from those.

### 4.1 Secret key hierarchy

```mermaid
flowchart TD
    ROOT[sk_root<br/>256-bit master secret]

    ROOT -->|HKDF "spend"| SK_SPEND[sk_spend]
    ROOT -->|HKDF "view"| SK_VIEW[sk_view]
    ROOT -->|HKDF "enc"| SK_ENC[sk_enc]
    ROOT -->|HKDF "derive"| SK_DERIVE[sk_derive]

    VK_NF -->|H "nk"| NK[nk - Nullifier key]

    subgraph Viewing Keys
        IVK[Incoming VK<br/>sk_view + sk_enc]
        FVK[Full VK<br/>IVK + vk_nf]
    end

    SK_VIEW --> IVK
    SK_ENC --> IVK
    SK_VIEW -->|H "view_nf"| VK_NF[vk_nf]
    VK_NF --> FVK

    SK_DERIVE --> ADDR[Diversified Addresses<br/>shca1...]
```

Let's define base secret material:

* `sk_root` – master secret for the wallet.
* Derive sub-keys via KDFs:

  * `sk_spend = H("spend" || sk_root)`
  * `sk_view = H("view" || sk_root)`
  * `sk_enc = H("enc" || sk_root)`

From this we derive:

* **Spending authorization material**:

  * `sk_spend` remains in the wallet for authorization/signing and is never embedded in viewing keys.
* **Nullifier key material**:

  * `vk_nf = H("view_nf" || sk_view)` is used inside the STARK to derive `nk` and nullifiers.
* **Viewing keys**:

  * `vk_full`: includes enough to derive both incoming and outgoing note info plus `vk_nf` for spentness tracking.
  * `vk_incoming`: only the KEM/AEAD decryption info and the ability to scan for your notes, not to reconstruct spends.

Everything is done via hash-based PRFs / KDFs; no ECC.

### 4.2 Address encoding

A **shielded address** contains:

* A version byte (for future evolution).
* A **crypto suite** identifier (the note-encryption parameter set).
* A **KEM public key** `pk_enc` (for ML-KEM).
* An **address-id / diversifier** derived from `sk_view` via PRF.

You can have multiple diversified addresses derived from the same underlying key material (like Zcash’s diversified addresses). Each address binds the crypto suite, ML-KEM public key, and recipient key derived from a diversifier index.

### 4.3 Wallet crate implementation

The repository now contains a `wallet` crate that wires these ideas into code:

* `wallet/src/keys.rs` defines `RootSecret`, `DerivedKeys`, and `AddressKeyMaterial`. A SHA-256-based HKDF (`wallet-hkdf`) produces `sk_spend`, `sk_view`, `sk_enc`, and `sk_derive`, and diversified addresses are computed deterministically from `(sk_view, sk_enc, sk_derive, index)`.
* `wallet/src/address.rs` encodes addresses as Bech32m (`shca1…`) strings that bundle the version, crypto suite, diversifier index, ML-KEM public key, and `pk_recipient`. Decoding performs the inverse mapping so senders can rebuild the ML-KEM key and note metadata.
* `wallet/src/notes.rs` handles ML-KEM encapsulation plus ChaCha20-Poly1305 AEAD wrapping for both the note payload and memo. The shared secret is expanded with a domain-separated label (`wallet-aead`) plus the crypto suite so note payloads and memos use independent nonces/keys and suite-confusion fails authentication.
* `walletd/` is a sidecar daemon that opens a wallet store and exposes a versioned newline-delimited JSON protocol over stdin/stdout so GUI clients (like `hegemon-app`) can drive sync, send, and disclosure workflows without re-implementing cryptography. The protocol includes capability discovery plus structured error codes, and `walletd` enforces an exclusive lock file alongside the store to prevent concurrent access.
* `wallet/src/viewing.rs` exposes `IncomingViewingKey`, `OutgoingViewingKey`, and `FullViewingKey`. Incoming keys decrypt ciphertexts and rebuild `NoteData`/`InputNoteWitness` objects for the transaction circuit, outgoing keys let wallets audit their own sent notes, and full viewing keys add the view-derived nullifier key (`vk_nf = BLAKE3("view_nf" || sk_view)`) needed for spentness tracking.
* `wallet/src/bin/wallet.rs` ships a CLI with the following flow:
  * `wallet generate --count N` prints a JSON export containing the root secret (hex), the first `N` addresses, and serialized viewing keys.
  * `wallet address --root <hex> --index <n>` derives additional diversified addresses on demand.
  * `wallet tx-craft ...` reads JSON inputs/recipients, creates `TransactionWitness` JSON for the circuit, and emits ML-KEM note ciphertexts for the recipients.
  * `wallet scan --ivk <path> --ledger <path>` decrypts ledger ciphertexts with an incoming viewing key and returns per-asset balances plus recovered note summaries.
  * `wallet substrate-sync`, `wallet substrate-daemon`, and `wallet substrate-send` are the live Substrate RPC flows; `wallet substrate-send` uses proof-backed `submitShieldedTransfer`.

Integration tests in `wallet/tests/cli.rs` exercise those CLI flows, so anyone can watch address derivation, note encryption, and viewing-key-based balance recovery stay compatible with the proving system.

Long-lived wallets rely on the Substrate WebSocket RPC client (`wallet/src/substrate_rpc.rs`) and async sync engine (`wallet/src/async_sync.rs`) rather than ad-hoc scripts. `AsyncWalletSyncEngine` pages through commitments/ciphertexts/nullifiers plus the latest block height, storing commitments inside the encrypted `WalletStore` so daemons can resume after crashes. The runbook in [runbooks/miner_wallet_quickstart.md](runbooks/miner_wallet_quickstart.md) walks through starting those daemons against two nodes.

The Polkadot.js Apps dashboard (https://polkadot.js.org/apps/) connects to the node's standard Substrate RPC endpoint and provides block exploration, account management, and chain state queries out of the box.

---

### 4.4 Disclosure on demand (payment proofs)

When a sender must prove a specific shielded payment to an exchange or auditor without revealing a viewing key, the wallet can generate a targeted **payment proof**. A disclosure package includes a STARK proof from `circuits/disclosure` binding `(value, asset_id, pk_recipient, commitment)` to the note-opening secrets `(rho, r)`, plus non-ZK confirmation data (Merkle inclusion path, anchor root) and the chain `genesis_hash`. The wallet stores outgoing note openings in the encrypted `WalletStore`, then `wallet payment-proof create` produces the package on demand. `wallet payment-proof verify` checks the STARK proof, Merkle path, `hegemon_isValidAnchor`, and the disclosed chain identity. Optional `disclosed_memo` fields are treated as user-supplied context and are not bound by the ZK proof.

## 5. Privacy & “store now, decrypt later”

Because we’re using only PQ primitives, the main “store-now-decrypt-later” concern is:

* Hashes & symmetric: we dimension them (e.g. 256-bit hash output, 256-bit AEAD keys) to keep ≈128-bit post-quantum security even with Grover. ([ISACA][4])
* Lattice schemes: we stick close to NIST’s strength categories for ML-KEM/ML-DSA. ([NIST][1])

Architecturally, we:

* Ensure that **address privacy** is not tied to any structure that might become classically invertible (no dlog; only KDFs).
* Use **one-time KEM keys** per transaction where helpful to add forward secrecy: sender can include ephemeral KEM pk in the ciphertext, so even compromise of recipient’s long-term `sk_enc` only reveals part of the past, not all.

The nice bit vs current Zcash: if a “Shor-class” machine appears, *nothing* trivially collapses, because there’s nothing ECC-based to break.

---

## 6. Upgradability & future-PQC break handling

We can hard-bake in lessons from the whole “quantum-recoverability” ZIP saga, but in a PQ setting:

1. **Versioned proofs & circuits**

   * Every transaction carries:

     * a circuit version ID,
     * a commitment to its statement in a version-agnostic way.
   * Recursion allows a new circuit to verify old proofs, so we can move from “Circuit v1” to “Circuit v2” without spinning up a new pool.
2. **Algorithm agility** for KEM/signatures:

   * Address versioning encodes a `crypto_suite` identifier for note encryption.
   * Wallets can rotate to, say, ML-KEM-v2 or a code-based KEM if lattices get scary; signatures continue to follow the protocol version bindings.
3. **Escape hatch**:

   * If some PQ primitive looks shaky, nodes can:

     * stop accepting new TXs using that primitive,
     * require users to “upgrade notes” via a special circuit that proves correct transfer into a new algorithm set.

So you get the “compartmentalization” Zcash achieved by multiple pools, but implemented via *versioning & recursion* rather than parallel pools.

Concrete modules in the repository now reflect this plan. A dedicated `state/merkle` crate maintains the append-only commitment tree with Poseidon-style hashing, while the `circuits/block` crate now treats commitment proofs as the primary block-validity artifact: `CommitmentBlockProver` builds a `CommitmentBlockProof` that commits to transaction proof hashes via a Poseidon sponge, and consensus verifies the commitment proof alongside per-transaction input checks. The commitment proof binds `tx_proofs_commitment` plus the starting/ending state roots, nullifier root, DA root, and the transaction-ordered + sorted nullifier lists as public inputs; consensus enforces the actual state-transition Merkle updates because naive in-circuit updates exceed the ~2^14 row target by two orders of magnitude (each depth-32 append costs ~10k rows). Nullifier uniqueness is proven in-circuit to prevent double-spend without per-tx consensus work, and consensus recomputes the padded transaction-ordered nullifier list to ensure the proof’s public inputs match the block’s transactions before accepting that uniqueness claim. When a block carries an aggregation proof (via `ShieldedPool::submit_aggregation_proof`), nodes verify the aggregated recursion proof with explicit public-value binding and skip per-transaction STARK verification; without it, they verify each transaction proof in parallel. Consensus validates a block by deriving commitment-proof public inputs from the block’s transactions, verifying the `CommitmentBlockProof`, recomputing `tx_proofs_commitment` from transaction proof hashes, then verifying the aggregation proof if present (or each transaction proof otherwise) before applying commitments to the state tree; in the Substrate node path, proof bytes are carried on-chain via unsigned `ShieldedPool::submit_commitment_proof` and `ShieldedPool::submit_aggregation_proof` extrinsics and checked during block import. The `protocol-versioning` crate defines a `VersionBinding { circuit, crypto }` pair plus helpers for recording per-block version matrices.

Consensus enforces version rollouts via `VersionSchedule`, a governance-friendly structure that records which bindings are allowed at which heights. ZIP-style `VersionProposal`s (see `governance/VERSIONING.md`) specify activation heights, optional retirement heights, and any special upgrade circuits required to migrate notes from a deprecated primitive to a fresh one. The PoW network consults the schedule before accepting a block, so solo miners and pools can mix v1 and v2 proofs during a rollout without coordination beyond rebasing on the canonical chain. When an emergency primitive swap is required, operators follow the runbook in `runbooks/emergency_version_swap.md` to publish an activation proposal, enable the upgrade circuit, and shepherd users through note migrations before the retirement height lands; pools can track adoption by computing per-block version counts from transaction bindings.

---

## 7. What we explicitly **prune** from legacy Zcash

If we’re being ruthless:

1. **No transparent pool**

   * Every coin is shielded from genesis.
   * If you want transparency, you can reveal with a “view key” or build a public accounting layer on top, but the base protocol doesn’t do cleartext UTXOs.

2. **No multiple curve zoo**

   * No BN254, BLS12-381, Jubjub, Pallas, Vesta, etc.
   * All “algebra” is just over:

     * One STARK field for proofs,
     * Integer fields for value arithmetic,
     * Hash permutations for commitments.

3. **No trusted setups, no separate SNARK generations**

   * One transparent STARK family from day one.
   * Migration handled via recursion and circuit versions, not by creating Sapling/Orchard-style new pools.

4. **No ECC-based in-circuit commitments**

   * No Pedersen, no Sinsemilla.
   * Only hash-based commitments and Merkle proofs.

5. **Simplified key hierarchy**

   * One main shielded address type, with a clean, hash/KEM-based derivation for spend/view/enc keys.
   * No proliferation of key types and curves.

[1]: https://csrc.nist.gov/projects/post-quantum-cryptography
[2]: https://www.c-sharpcorner.com/article/zk-snarks-vs-zk-starks/
[3]: https://cloudsecurityalliance.org/artifacts/post-quantum-cryptography-and-zero-knowledge-proofs/
[4]: https://www.isaca.org/resources/isaca-journal/issues/2020/volume-2/quantum-computing-and-post-quantum-cryptography

## 6. Monorepo structure, docs, and benchmarking

Implementation now follows an explicit monorepo layout so each subsystem’s tests, docs, and benchmarks stay synchronized:

- `crypto/` – Rust crate `synthetic-crypto` that implements ML-DSA/SLH-DSA signatures, ML-KEM, and the SHA-256/BLAKE3/Poseidon-style hashing used throughout this design. Changes here must update `docs/API_REFERENCE.md#crypto` plus the guardrails in `docs/THREAT_MODEL.md` that spell out the PQ security margins (≥128-bit post-Grover strength for all primitives).
- `circuits/transaction`, `circuits/block`, and the new `circuits/bench` binary crate – contain the canonical STARK circuits and a CLI (`cargo run -p circuits-bench -- --prove`) that compiles dummy witnesses, produces transaction proofs, and runs block-level commitment proofs plus parallel verification checks. The benchmark keeps track of constraint row counts, hash invocations, and elapsed time so that any change to witness construction or proving fidelity can be measured. Section 2 should be updated in lockstep with these outputs.
- `consensus/` and `consensus/bench` – the Rust miner node logic still enforces version bindings and PQ signature validation, while the Go `netbench` simulator replays synthetic payloads sized to ML-DSA signatures plus STARK proofs. Its output feeds directly into the threat model’s DoS budgets because it reports achieved messages/second under PQ payload sizes.
- `wallet/` and `wallet/bench` – the CLI plus a Rust benchmark that derives keys, encrypts/decrypts notes, and computes nullifiers using the same derivations in §3–4. This ensures wallet UX changes keep Grover-aware 256-bit symmetric margins.
- `docs/` – authoritative contributor docs, threat models, and API references. The new files explicitly call out which paragraphs inside this DESIGN and `METHODS.md` must change together. Any interface change now requires edits in all three locations (code, DESIGN, docs) before CI will pass.

Continuous integration (see `.github/workflows/ci.yml`) mirrors this structure. Jobs cover:

1. Rust linting/tests across the workspace (crypto, circuits, consensus, wallet, state, protocol).
2. Targeted crypto tests to ensure ML-DSA/ML-KEM fixtures stay deterministic.
3. Circuit proof checks plus the `circuits-bench --smoke --prove` run so the proving pipeline always compiles.
4. Wallet CLI/integration tests alongside the `wallet-bench` smoke test to exercise note encryption and nullifier derivations.
5. Go-based network simulator tests (`consensus/bench`) to keep PQ throughput budgets measurable.
6. A non-blocking `benchmarks` job that executes all smoke benchmarks and posts their JSON output in the build log for regression tracking.

These scaffolds exist to keep the design’s PQ security assumptions observable. Any change that alters signature sizes, hash widths, or witness semantics must update:

1. The relevant crate README (`crypto/README.md`, `circuits/README.md`, `consensus/README.md`, `wallet/README.md`).
2. The API entry in `docs/API_REFERENCE.md` and the guardrails in `docs/THREAT_MODEL.md`.
3. This section of DESIGN.md plus the operational instructions in `METHODS.md` so reviewers can verify code and documentation move together.

## 8. Security assurance program

- **Cryptanalysis & audits** – `docs/SECURITY_REVIEWS.md` defines how we commission lattice/hash reviews and third-party audits. Design-impacting findings must be mirrored in the sections above plus `METHODS.md`, and every mitigation PR links back to the finding ID logged there.
- **Formal verification** – TLA+ specs under `circuits/formal/` (transaction balance) and `consensus/spec/formal/` (HotStuff safety/liveness) are now part of the release checklist. Any modification to witness layouts, balance tags, or consensus phases must update the corresponding spec and README.
- **Continuous adversarial testing** – The `security-adversarial` CI job runs the new property-based tests for transaction validation, network handshakes, wallet address encoding, and the root-level adversarial flow in `tests/security_pipeline.rs`. Operators follow `runbooks/security_testing.md` when the job fails, capturing artifacts for auditors before re-running.

Together these loops ensure PQ parameter choices, circuit semantics, and miner logic stay observable and auditable as the system evolves.
