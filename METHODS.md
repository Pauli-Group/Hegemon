## 1. What a “shielded spend” proves (ZK statement)

We’ll design a *single* canonical shielded pool, with a fixed “join–split” circuit used for all transactions.

Say each transaction supports up to:

* `M` inputs (old notes),
* `N` outputs (new notes),

per proof. Think Sapling/Orchard style: fixed `M, N` for the base circuit, recursion if you need more.

### 1.1 Data model

A **note** is conceptually:

* `value` - integer (e.g. 64-bit, or 128-bit if you're paranoid)
* `asset_id` - 64-bit label (u64) in the current circuit, encoded as a single field element inside the STARK. Commitments and nullifiers are serialized as 48-byte outputs with six 64-bit limbs for 384-bit capacity, and application-level types use 48-byte digests end-to-end. `0` = native coin (ZEC-like).
* `pk_recipient` – an encoding of the recipient’s “note‑receiving” public data (tied to their incoming viewing key)
* `pk_auth` – a spend-authorization public key derived from the owner’s spend secret
* `rho` – per‑note secret (random)
* `r` – commitment randomness

We define the note commitment:

```text
cm = Com_note(value, asset_id, pk_recipient, pk_auth, rho, r)
   = Hc("note" || enc(value) || asset_id || pk_recipient || rho || r || pk_auth)
```

* `Hc` is a commitment‑strength hash (could be domain‑separated Poseidon or Blake3; binding+hiding rely on hash + randomness).
* `enc(value)` is some fixed‑width encoding for `value`.

On‑chain, the **global state** for the pool is:

* An append‑only **Merkle tree of `cm`** (like Zcash’s note commitment tree)
* A **nullifier set**: any `nf` that has appeared as an input is “spent”

Each **transaction** includes:

* Public:

  * `nf[0..M-1]` – nullifiers for each consumed note
  * `cm'[0..N-1]` – commitments for each new note
  * `ct_hash[0..N-1]` – ciphertext hashes for each output note (domain-separated BLAKE3-384)
  * `balance_tag` – a compressed representation of value balance (see below)
  * optional `memo`s, network fee, etc.
  * one or a few STARK proofs
* Hidden (witness in the proof):

  * openings of the consumed and created notes
  * sender’s secret keys
  * Merkle paths for each input note

### 1.2 ZK statement per transaction

The core statement the STARK proves:

> There exist:
>
> * for each input `i` in `[0..M-1]`:
>
>   * `(value_i, asset_i, pk_recipient_i, pk_auth_i, rho_i, r_i, pos_i)`
>   * `sk_spend`
> * for each output `j` in `[0..N-1]`:
>
>   * `(value'_j, asset'_j, pk'_j, pk'_auth_j, rho'_j, r'_j)`
>
> such that:
>
> 1. **Note commitments match**
>
>    * For all inputs/outputs:
>
>      ```text
>      cm_i  = Com_note(value_i,  asset_i,  pk_recipient_i,  pk_auth_i,  rho_i,  r_i)
>      cm'_j = Com_note(value'_j, asset'_j, pk'_j, pk'_auth_j, rho'_j, r'_j)
>      ```
>    * And the published `cm'_j` equal these.
> 2. **Inputs are in the tree (membership)**
>
>    * For each input:
>
>      ```text
>      MerkleRoot == Merkle(cm_i, pos_i, path_i)
>      ```
>
>      where `path_i` is the Merkle authentication path, and `Merkle()` is a hash‑based tree function fixed by the protocol.
> 3. **Nullifiers are correct**
>
>    * Derive a nullifier key:
>
>      ```text
>      nk = H("nk" || sk_spend)
>      ```
>    * For each input note:
>
>      ```text
>      nf_i = H("nf" || nk || rho_i || pos_i)
>      ```
>    * And the published `nf_i` match these.
> 4. **Balance is preserved** (per asset)
>
>    * Let’s start with single‑asset to keep it clean:
>
>      ```text
>      sum_i value_i  = sum_j value'_j + fee
>      ```
>    * For MASP, we enforce this per `asset_id` — more on that in a moment.
> 5. **No negative values or overflow**
>
>    * Check `0 <= value_i, value'_j <= 2^64 - 1` (or your chosen bound) by range‑checking in‑circuit.

You can think of this as “Sapling/Orchard semantics with: no ECC, no Pedersen, no RedDSA — everything is hash‑or lattice‑based.”

---

## 2. MASP value‑balance (multi‑asset) in a STARK

In a MASP, each note carries an `asset_id`; a transaction can involve multiple assets, but you must enforce conservation *per asset*.

There are various ways to do this. A reasonably simple STARK‑friendly approach:

### 2.1 Commit to per‑asset balances inside the circuit

Define:

```text
Δ_k = (total_inputs of asset k) - (total_outputs of asset k)
```

We want:

* For the native asset `k = 0`: `Δ_0 = fee` (or `Δ_0 = issuance + fee`)
* For all other assets `k != 0`: `Δ_k = 0`

Instead of explicitly enumerating all possible assets in the circuit, you:

1. Compute a **multiset of (asset_id, signed_value_delta)** inside the circuit:

   * For each input:   add `(asset_i,  value_i)`
   * For each output:  add `(asset'_j, -value'_j)`

2. Sort this multiset by `asset_id` *inside the circuit* (or enforce a permutation against a sorted copy). This is standard in modern SNARK/STARK design: you pay constraints proportional to `M+N` and log of that for the sort.

3. Aggregate runs with the same `asset_id`:

   * For each run of equal `asset_id = k`, sum the deltas to get `Δ_k`.

4. Check:

   * For the designated “native asset” id (e.g. all‑zero or some constant):

     ```text
     Δ_native = fee + issuance
     ```
   * For all other `k`: `Δ_k = 0`.

5. Output a single public field element `balance_tag` that is, say, a commitment to `(Δ_native, fee, issuance)` — used by nodes for sanity and future audit.

This gives MASP semantics without any ECC:

* The sort + run‑sum works over plain integers in the STARK field.
* The size cost is O((M+N) log (M+N)) constraints, which is manageable at Zcash‑like M,N.

If you want to be more aggressive, you can avoid exposing per‑asset details publicly: the proof enforces the equalities, but `balance_tag` is simply a commitment to the whole vector `(Δ_k)`. Nodes don’t need to inspect it; they only check that the proof verifies.

### 2.2 Stablecoin issuance binding

Stablecoin issuance and burn are handled as a controlled exception to the per-asset conservation rules. The circuit allows exactly one non-native asset id to have a non-zero delta when a stablecoin binding is present. The binding is part of the public inputs and includes:

* `stablecoin_asset_id`
* `issuance_delta` (signed, exposed as sign + magnitude)
* `policy_hash`
* `oracle_commitment`
* `attestation_commitment`
* `policy_version`

Inside the AIR, the stablecoin binding payload stays in the public inputs. The fixed four balance-slot asset ids are also public inputs, with a canonical encoding enforced by the runtime and wallet: slot `0` is always the native asset, non-native asset ids are strictly increasing, and any `u64::MAX` padding must appear only as a suffix. The witness trace carries only the running in/out sums for those four slots plus a compact 2-bit selector for the chosen non-native balance slot: `00` means “no stablecoin binding,” while `01`, `10`, and `11` select non-native slots `1`, `2`, and `3` respectively. When the binding is enabled, that selected slot must match `stablecoin_asset_id` and its net delta must equal `issuance_delta`. All other non-native slots are still constrained to zero. The runtime then enforces that the binding matches the active `StablecoinPolicy` hash and version, the oracle commitment is fresh, and the attestation is not disputed. This keeps issuance fully shielded while still tethering it to protocol-approved policy inputs.

Consensus stitches this MASP output into PoW validation by requiring a coinbase commitment on every block. The `ConsensusBlock`
type now carries `CoinbaseData` that either references a concrete transaction (by index) or supplies an explicit `balance_tag`.
Miners populate `CoinbaseData` with the minted amount, collected fees, and any explicit burns, and full nodes recompute the
running `supply_digest = parent_digest + minted + fees − burns`. If the coinbase is missing, points at an invalid transaction,
or mints more than the scheduled subsidy `R(epoch)` (~4.98 × 10⁸ base units halving every ~4 years per `TOKENOMICS_CALCULATION.md`), the block is rejected
before the fork-choice comparison runs. This keeps the STARK circuit, MASP accounting, and the PoW header’s supply digest in
lockstep.

Substrate nodes wire the same enforcement path into block import. `consensus::substrate::import_pow_block` wraps the `PowConsensus`
state machine with a Substrate-friendly `BlockOrigin` tag and returns an `ImportReceipt` that records the validated proof
commitment, version commitment, and fork-choice result. Node services call this helper inside their block intake path so the
version-commitment and STARK commitment checks run during import (not after the fact), and `/consensus/status` mirrors the latest
receipt alongside miner telemetry to keep the Go benchmarking harness under `consensus/bench` in sync with runtime behavior.

On the Substrate runtime side, shielded transfers now accumulate split per-block fee buckets:
`BlockFeeBuckets { miner_fees, prover_fees }`. The shielded reward mint path (`mint_coinbase` external call name; `mint_block_rewards`
internal path) validates a `BlockRewardBundle` with a required miner note and optional prover note. Miner reward must equal
`subsidy + miner_fees`; prover reward, when claimed, must equal `prover_fees` and match the submitted prover claim metadata. If a
block omits reward minting, both fee buckets are treated as burned and tracked on-chain.

Fee pricing is parameterized on-chain with deterministic split accounting:
`prover_fee = proof_fee|batch_proof_fee`,
`miner_fee = inclusion_fee|batch_inclusion_fee + bytes * da_byte_fee + bytes * retention_byte_fee * hot_retention_blocks`,
`total_fee = prover_fee + miner_fee`.
These parameters live in the shielded pool pallet, are seeded from the active protocol manifest, and are exposed via runtime API/RPC as both total
quote and breakdown (`fee_quote`, `fee_quote_breakdown`) so clients can quote fees without auctions.

The legacy forced-inclusion bond queue is removed in the proof-native cut. Censorship resistance for the private lane is now handled by the unsigned shielded submission path itself plus block-import validation, rather than by reserving public balances behind a transparent account.

Within a block, shielded transfer extrinsics must appear in nondecreasing order of the hash of their SCALE-encoded call data.
Nodes enforce this during block import and local block production so miners do not have discretionary ordering inside the private lane.

### Aggregation mode and proof sidecar (rollup path)

For scalability, the system supports a per-block “aggregation mode” that allows shielded transfer extrinsics to omit the per-transaction STARK proof bytes and rely on a single aggregation proof checked during block import:

* Block authors include `ShieldedPool::enable_aggregation_mode` early in the block.
* A chain-level `ProofAvailabilityPolicy` gates whether per-tx proofs must be inline (`InlineRequired`) or may be omitted in aggregation mode (`SelfContained`).
* In aggregation mode + `SelfContained`, `shielded_transfer_unsigned_sidecar` may omit proof bytes; the runtime skips `verify_stark` and only enforces binding hashes + non-ZK checks (nullifiers, anchors, fee floor).
* In aggregation mode + `SelfContained`, proofless transfers require a valid `submit_proven_batch` in the same block. Proof-carrying transfers can still be verified through the inline path when no ready bundle is attached.
* Block template assembly keeps a liveness-first posture under proofless load: it includes the largest proofless subset with a ready proven batch and defers the rest, allowing empty/non-shielded blocks to continue instead of stalling template construction. Operators can raise `HEGEMON_MIN_READY_PROVEN_BATCH_TXS` to require larger ready batches before proofless inclusion (throughput-first mode), while the default remains `1` for liveness-first behavior. A bounded retry loop still exists for true “ready batch required” failures (`HEGEMON_PENDING_PROVEN_BATCH_WAIT_MS`, `HEGEMON_PENDING_PROVEN_BATCH_MAX_ATTEMPTS`), but routine deferred proofless traffic no longer blocks sealing.
* Proof bytes may still be staged off-chain via `da_submitProofs` keyed by `binding_hash`, but this is proposer/mempool coordination only and is not part of consensus validity.
* The node verifies the commitment proof + aggregation proof during import and rejects any block whose aggregated transactions are invalid, without fetching proof-DA manifests/entries.

---

### Experimental post-proof receipt folding spike

The repo now carries a bounded SuperNeo research spike under `circuits/superneo-*`. The method being tested is deliberately post-proof: instead of compiling the full transaction AIR into a second proof system, the experimental relation starts from a transaction-proof receipt. The receipt statement binds five 48-byte digests: a transaction-statement digest, a proof-bytes digest, a verifier-profile digest, a public-inputs digest, and a verification-trace digest.

The witness method is equally narrow. `circuits/superneo-hegemon` pads raw proof bytes into a fixed-width receipt lane and carries a bounded vector of binary “verification trace bits.” `circuits/superneo-ring` then packs those witness lanes with declared bit widths so the experiment can measure pay-per-bit packing pressure directly in Goldilocks terms. This is not a real verifier circuit; it is a method scaffold for comparing artifact size and fold orchestration against the frozen `raw_active` benchmark before deeper backend work begins.

`circuits/superneo-backend-lattice` now implements a direct in-repo SuperNeo-style folding backend over Goldilocks. The method is still experimental and not a production lattice commitment scheme, but it is no longer a pure mock. The current steps are:

* pack witness values with pay-per-bit widths in `superneo-ring`,
* expand the packed witness to its used bit slice,
* commit to those bits with a deterministic public matrix over Goldilocks (so commitment work scales with witness bit-width rather than a fixed 64-bit lane width),
* bind each leaf to its statement digest and packed witness in a leaf proof,
* fold commitments with transcript-derived linear challenges to produce parent commitments and parent statement digests.

For canonical tx-validity receipts, the verifier can reconstruct the packed witness directly from the public receipt digests, so the receipt-root artifact stays digest-only even though the backend itself now performs concrete bit-linear commitment and fold work. This gives Hegemon a stable-Rust experimental implementation of the folding geometry described in Neo/SuperNeo without importing an external nightly-only lattice library. The remaining gap is cryptographic hardness: the current commitment operator is a deterministic Goldilocks matrix projection, not the Ajtai/module-SIS commitment from the papers.

---

## 3. The STARK arithmetization

We don’t need to pick a specific scheme (Plonky2/Plonky3/etc.), but we do need the rough structure.

### 3.1 Field and hash choices

* Choose a prime field `Fp` suitable for FRI/FFT:

  * Something like `p ≈ 2^64 * k ± 1` with big 2‑adicity, so you can work with large multiplicative subgroups.
* Use:

  * A STARK‑friendly hash `Hf` inside the proof (Poseidon‑ish, Rescue, etc.).
  * A standard hash `Hg` (Blake3/SHA‑256) outside for block headers and note commitments if you like. In practice you might unify them for simplicity.

Inside the circuit:

* Implement `Hf` as a permutation with a small number of rounds.
* Implement Merkle hashes by repeated `Hf` applications.

### 3.2 Circuit layout (conceptual)

You design one “join–split” circuit with:

* Columns (registers) for:

  * All note fields for inputs/outputs,
  * Merkle path bits/elements,
  * Hash state (for `Hf`),
  * Accumulators for MASP sorting.

* Constraints enforcing:

  1. Correct computation of note commitments.
  2. Correct Merkle path verification (each level: hash(left, right) = parent).
  3. Correct nullifiers.
  4. Value range checks (bit‑decompositions).
  5. Sorting network constraints for the `(asset_id, delta)` array.
  6. Run‑sum correctness.
  7. Balance equations.

The exact low‑level shape depends on whether you use AIR (transition function on a trace) or PLONK‑style gates, but conceptually you have one STARK proof that “this whole finite state machine” executed correctly over your witness.

In the Plonky3 implementation, the transaction AIR keeps fixed schedule data (Poseidon round flags, cycle markers, row-specific assertions) in explicit schedule columns inside the main trace. This preserves deterministic scheduling without relying on preprocessed trace columns for the transaction circuit, while other circuits can still use `builder.preprocessed()` where stable. The tradeoff is a wider trace for the transaction AIR, but it avoids the preprocessed-trace OOD mismatch seen in the 0.4.x backend.

You might split this into:

* a “note membership + nullifier” sub‑circuit, and
* a “balance + MASP” sub‑circuit,

and then recursively prove both and aggregate them into a compact proof. But that’s an optimization, not a different design.

---

## 4. Key hierarchy and viewing keys (ML‑KEM‑based)

Now, how do secret keys, addresses, and viewing keys fit into this picture *without* ECC?

### 4.1 Master secret and derived keys

Let:

* `sk_root` – main user secret (stored in wallet)

Derive subkeys using a KDF `HKDF`:

```text
sk_spend  = HKDF("spend"  || sk_root)
sk_view   = HKDF("view"   || sk_root)
sk_enc    = HKDF("enc"    || sk_root)
sk_derive = HKDF("derive" || sk_root)  // for diversified addresses
```

We define:

* **Spending key material**:

  * `sk_spend` used for wallet authorization and extrinsic signing; it is not embedded in viewing keys.
* **Nullifier key material**:

  * `prf_nf = Hf("nk" || sk_spend)` for nullifier computation in viewing flows.
* **Viewing key material**:

  * `vk_full = (sk_view, sk_enc, prf_nf, public_params…)`
* **Incoming‑only viewing key**:

  * `vk_incoming = (sk_view, sk_enc, diversifier params)`
    (can scan chain and decrypt incoming notes, but can’t produce spends or see nullifiers.)

### 4.2 Nullifier key

Inside proofs we don’t want to expose `sk_spend`, but we need a deterministic nullifier.

Define:

```text
nk = Hf("nk" || sk_spend)
nf = Hf("nf" || nk || rho || pos)
```

Only someone knowing `sk_spend` can satisfy the ownership constraints for a note. The wallet can still track spentness using
`prf_nf`, which is the derived nullifier PRF output rather than the spend secret itself.

### 4.3 Addresses and encryption keys (ML‑KEM)

For each **diversified address** we want a KEM public key plus maybe some metadata.

Let’s say we use ML‑KEM‑768.

To derive per‑address KEM keys *deterministically*:

1. From `sk_derive`, define an HD‑style derivation:

   ```text
   seed_addr(d) = H("addr-seed" || sk_derive || encode(d))
   ```

   where `d` is a 32‑bit diversifier index.

2. From `seed_addr(d)`, run a deterministic KEM keygen:

   ```text
   (sk_enc(d), pk_enc(d)) = ML-KEM.KeyGen(seed_addr(d))
   ```

   (You use a deterministic variant of keygen seeded by `seed_addr(d)`; this is standard.)

Then an **address** is:

```text
addr_d = EncAddr(version || d || pk_recipient(d) || pk_auth || pk_enc(d))
```
where `pk_recipient(d)` is derived from the viewing key and the diversifier.

Wallet exports:

* Spending key: `sk_root` (or some hardened derivation).
* Full viewing key: `(sk_view, sk_enc(·), HD derivation params)`
* Incoming viewing key: `(sk_enc(·), HD derivation params)` only.

### 4.4 Note encryption and scanning

For each output note to `addr_d`:

1. Sender knows `pk_enc(d)` from the address.

2. Sender chooses a random note secret `rho` and commitment randomness `r`.

3. Sender constructs plaintext:

   ```text
   note_plain =
       (value, asset_id, rho, r, d, maybe extra data)
   ```

4. Sender runs:

   ```text
   (ct, ss) = ML-KEM.Encaps(pk_enc(d))
   key_AEAD = HKDF("note-key" || ss)
   C_note = AEAD_Encrypt(key_AEAD, nonce, note_plain)
   ```

5. On‑chain, the transaction includes:

   * `cm` – the note commitment (public)
   * `ct` – KEM ciphertext
   * `C_note` – AEAD ciphertext

**Scanning with incoming viewing key:**

A wallet with `vk_incoming`:

* Knows `sk_derive`, so can recompute each `sk_enc(d)` and `pk_enc(d)` for its diversified addresses.
* For each new note on chain, try decapsulation with every `sk_enc(d)` you care about; if decap succeeds and the AEAD tag verifies, it’s yours.

Given that ML‑KEM decapsulation is not *that* expensive and users don’t have thousands of addresses typically, trial decryption is acceptable in v1. The scanning cost is similar order of magnitude to Sapling’s trial decryption.

**Full viewing key** `vk_full`:

* Contains everything in `vk_incoming`, plus:

  * enough info to recompute nullifiers (`nk` or a view‑equivalent),
  * so it can see which of “its” notes have been spent.

Hegemon chooses the watch‑only path: full viewing keys include the spend-derived nullifier PRF output (`prf_nf`) so wallets can compute
nullifiers for spentness tracking without embedding `sk_spend`.

### 4.5 Implementation details

*Key derivations and addresses.* `wallet/src/keys.rs` implements `RootSecret::derive()` using the domain-separated label `wallet-hkdf` and SHA-256 to expand `(label || sk_root)` into the 32-byte subkeys for spend/view/enc/diversifier. `AddressKeyMaterial` then uses `addr-seed` plus the diversifier index to deterministically derive the ML-KEM key pair; `pk_recipient` is derived from the view key and diversifier while `pk_auth` is derived from the spend key via the Poseidon2 key schedule used by the circuit. `wallet/src/address.rs` serializes `(version, crypto_suite, index, pk_recipient, pk_auth, pk_enc)` as a Bech32m string (HRP `shca`) so senders can round-trip addresses through QR codes or the CLI.

*Note encryption.* `wallet/src/notes.rs` consumes the recipient’s Bech32 data, runs ML-KEM encapsulation with a random seed, and stretches the shared secret into two ChaCha20-Poly1305 keys via `expand_to_length("wallet-aead", shared_secret || label || crypto_suite, 44)`. The first 32 bytes drive the AEAD key and the final 12 bytes form the nonce so both note payload and memo use disjoint key/nonce pairs. Ciphertexts record the version, crypto suite, diversifier index, and ML-KEM ciphertext so incoming viewing keys can reconstruct the exact `AddressKeyMaterial` needed for decryption. The AEAD AAD binds `(version, crypto_suite, diversifier_index)` so header tampering fails authentication. Runtime admission hard-cuts to current header version `v3`; any other version is rejected.

*Viewing keys and nullifiers.* `wallet/src/viewing.rs` defines `IncomingViewingKey` (scan + decrypt), `OutgoingViewingKey` (derive `pk_recipient` for audit), and `FullViewingKey` (incoming + spend-authority metadata). Full viewing keys now store the spend-derived nullifier PRF output (not the spend secret), so wallets can compute chain nullifiers while the transaction witness still proves knowledge of `sk_spend` in-circuit. `RecoveredNote::to_input_witness` converts decrypted notes into `transaction_circuit::note::InputNoteWitness` values by reusing the same `NoteData` and taking the best-effort `rho_seed = rho` placeholder until the circuit’s derivation is finalized.

*CLI, daemon, and fixtures.* `wallet/src/bin/wallet.rs` now ships three families of commands:

  * Offline helpers (`generate`, `address`, `tx-craft`, `scan`) that mirror the deterministic witness tooling described in DESIGN.md. `tx-craft` emits redacted witness JSON (no serialized `sk_spend`) so exported artifacts are safe to share.
* Wallet management over Substrate RPC (`wallet init`, `wallet substrate-sync`, `wallet substrate-daemon`, `wallet substrate-send`, `wallet status`, `wallet export-viewing-key`). `wallet init` writes an encrypted store (Argon2 + ChaCha20-Poly1305) containing the root secret or an imported viewing key. `wallet substrate-sync` and `wallet substrate-daemon` use WebSocket RPC to fetch commitments/ciphertexts/nullifiers and maintain a local Merkle tree/nullifier set, while `wallet substrate-send` crafts witnesses, proves them locally, and submits a shielded transfer before tracking pending nullifiers.
  * Ciphertext sync is robust to DA/sidecar quirks: ciphertext indices can have gaps (retention) and may include non-canonical ciphertexts during forks. The wallet maps decrypted notes back to commitment positions via the commitment list and skips any decrypted note whose commitment cannot be found locally.
* Substrate RPC wallet management (`substrate-sync`, `substrate-daemon`, `substrate-send`, `substrate-batch-send` gated behind the `batch-proofs` feature) that use the WebSocket RPC for live wallets. `wallet substrate-send` records outgoing disclosure records inside the encrypted store so on-demand payment proofs can be generated later. In v0.9 strict mode, `walletd` defaults to self-contained unsigned submission (`HEGEMON_WALLET_DA_SIDECAR=0`) so proof/ciphertext bytes propagate with the transaction across miners; sidecar staging remains opt-in for controlled topologies.
  * Compliance tooling (`payment-proof create`, `payment-proof verify`, `payment-proof purge`) that emits disclosure packages and verifies them against Merkle inclusion plus `hegemon_isValidAnchor` and the chain genesis hash.

JSON fixtures for transaction inputs/recipients still follow the `transaction_circuit` `serde` representation used by the witness builder, with spend secrets intentionally excluded from serialized witness files. `wallet/tests/cli.rs` exercises the offline commands via `cargo_bin_cmd!`, and `wallet/tests/disclosure_package.rs` covers payment-proof package generation plus tamper rejection without requiring a live node. The disclosure circuit itself is tested under `circuits/disclosure/tests/disclosure.rs`.

---

## 5. Upgrade path / versioning in the circuit layer

Because we’ve only got one pool, we want the ability to evolve the circuit / hash / KEM / sigs *without* new pools.

Mechanism:

### 5.1 Versioned circuits

* Every STARK statement includes a **circuit version ID** as a public input.
* The chain’s consensus defines which version IDs are currently permitted for new transactions.
* When you introduce a new circuit version:

  * Old notes remain valid; you just switch off acceptance of new proofs with old version IDs after some epoch.

You can also build a **transition circuit** that:

* Verifies a proof of old version,
* Emits commitments/nullifiers consistent with a new internal representation,
* Is itself proved with the new version.

That’s “in‑pool recursion” for upgrades.

The current implementation wires those abstractions into code:

* `protocol-versioning` defines the canonical `VersionBinding { circuit, crypto }`, `VersionMatrix`, and helper commitments that every transaction and block now expose. `TransactionWitness` carries a binding, `TransactionPublicInputs` serializes `circuit_version`/`crypto_suite`, and `TransactionProof::version_binding()` lets the block circuit pick the right verifying key for each proof.
* `circuits/block` exposes commitment-proof helpers and keeps per-version counts so consensus can hash them into the header’s `version_commitment`; transaction proofs are verified in parallel by consensus using the same `VersionBinding` table.
* `consensus::version_policy::VersionSchedule` stores ZIP-style `VersionProposal`s (activation height, optional retirement, optional `UpgradeDirective` that points at the special migration circuit binding). Both BFT and PoW consensus paths call `schedule.first_unsupported(...)` and surface `ConsensusError::UnsupportedVersion` if a block contains an unscheduled binding.
* Governance documentation (`governance/VERSIONING.md`) specifies how to draft a proposal, vote on it, and publish the activation window, while the operational runbook (`runbooks/emergency_version_swap.md`) walks operators through emergency swaps: announce the swap, enable the upgrade circuit, watch `version_counts` to ensure old notes migrate, then retire the deprecated binding at the scheduled height.

### 5.2 Algorithm agility

Addresses include a crypto-suite identifier:

* `crypto_suite` ∈ {ML‑KEM‑1024, ML‑KEM‑v2, …} for the note-encryption KEM+AEAD parameters.

Signatures are versioned via the protocol’s `VersionBinding` rather than the address format. The join–split circuit doesn’t care; it just treats `asset_id` and `pk_recipient` as opaque bytes. Only the *note encryption/decryption* layer and wallet code depend on the crypto suite.

On algorithm deprecation:

* Consensus can forbid new transactions with, say, `crypto_suite = ML‑KEM‑1024` after block X, but still allow spends of existing notes for some grace period.
* You can also add a “must migrate by height H” rule for certain key types, enforced by a special migration circuit.

---

## Appendix: Concrete Parameters and Protocol Details

### 1. Concrete parameters

#### 1.1 Field

Take a “Goldilocks” prime:

* \(p = 2^{64} - 2^{32} + 1\).

Properties:

* Fits in 64 bits, which is convenient for CPU implementations.
* Large enough that 64-bit values plus a few dozen additions will not overflow modulo \(p\).
* Has a large 2-power multiplicative subgroup, which is useful for FFT/FRI.

Everything arithmetized in the STARK (commitments, Merkle hashes, PRFs) lives in \(\mathbb{F}_p\).

#### 1.2 Internal hash / permutation

Define a Poseidon2 permutation \(P: \mathbb{F}_p^t \to \mathbb{F}_p^t\) with width \(t = 12\) (rate 6, capacity 6), S-box \(x^7\), 8 full rounds + 22 partial rounds, and deterministic constants generated from the fixed seed `hegemon-tx-poseidon2-seed-2026!!`.

We derive a field hash by sponge:

\[
H_f(x_0, \ldots, x_{k-1}) = \operatorname{Sponge}(P, \text{capacity}=6, \text{rate}=6, x_0, \ldots, x_{k-1})
\]

For commitments, nullifiers, and Merkle nodes we emit six field elements (48 bytes). Single-field values (e.g., balance tags) still use the first state word.

Outside the circuit (for block headers, addresses, etc.) we can still use standard SHA-256 as a byte-oriented hash. Inside, we stick to \(H_f\).

#### 1.3 Merkle tree

* Each leaf: a commitment \(cm\) represented as six limbs (48 bytes).
* Parent hash: for children \(L, R\) (each 6 limbs), absorb the limbs in circuit order and output the same limb count:

\[
\text{parent} = H_f(\text{domain}_{\text{merkle}}, L_0, L_1, L_2, L_3, R_0, R_1, R_2, R_3)
\]

where \(\text{domain}_{\text{merkle}}\) is a fixed field element.
This formula applies with six limbs per child.

* Tree depth: say 32 or 40 (gives capacity for \(2^{32}\)–\(2^{40}\) notes; you can always roll a new tree later via a transition proof).
* Runtime keeps a bounded window of recent Merkle roots (`MerkleRootHistorySize`); anchors older than the window are invalid to cap state growth.

#### 1.4 PQC choices

To have something specific in mind:

* KEM: ML-KEM-1024 (Kyber-1024 equivalent) with \(|pk| \approx 1568\) bytes, \(|ct| \approx 1568\) bytes, 256-bit classical and roughly 128-bit post-quantum security.
* Signature: ML-DSA-65xx (Dilithium-level) or category-3 equivalent with approximately 2–3 KB signatures and 1–2 KB public keys. Runtime extrinsics and PoW seals reuse this scheme through `runtime::PqSignature`/`PqPublic`, hashing PQ public keys with BLAKE2 into SS58-prefix-42 AccountId32 values so address encoding stays stable while signatures grow.

We do not need signatures inside the shielded circuit, only for block authentication and possibly transaction-level authentication.

#### 1.5 Network identity seeds

PQ network identities are derived from a 32-byte secret seed that must be generated from OS entropy and persisted on disk with restrictive permissions (mode 0600). The node loads this seed from `HEGEMON_PQ_IDENTITY_SEED` (hex) when provided, otherwise it reads `HEGEMON_PQ_IDENTITY_SEED_PATH` or defaults to `<base-path>/pq-identity.seed`. The seed is never derived from public peer IDs; peer IDs are computed from the public keys that result from this secret seed. This keeps PQ transport identity keys unpredictable while keeping peer identity stable across restarts.

#### 1.6 Peer discovery (PQ address exchange)

The Substrate node’s PQ network stack is **not** libp2p, so we do not get Kademlia/mDNS discovery “for free”.

Instead, once a PQ connection is established, peers run a small “address exchange” protocol over the PQ framed message channel:

* Protocol id: `/hegemon/discovery/pq/1`
* Messages (serde+bincode encoded):

  * `Hello { listen_port }` – the receiver combines the *observed peer IP* with `listen_port` to form a dialable `IP:port` even if the connection’s TCP source port was ephemeral.
  * `GetAddrs { limit }` and `Addrs { addrs }` – bounded address lists used to share additional dial targets beyond seeds.
  * `GetPeerGraph { limit }` and `PeerGraph { peers }` – bounded lists of currently connected peers used to build a multi-hop peer graph for dashboards.

Nodes persist learned addresses under the Substrate `--base-path` (cache file: `<base-path>/pq-peers.bin`) and opportunistically dial a small batch of learned addresses when peer count is low. `HEGEMON_SEEDS` remains the bootstrap mechanism (operators should still share the same seed list to avoid partitions).

To ensure early-joining nodes continue to learn about peers that connect later, nodes periodically re-request addresses from a random connected peer and attempt a bounded batch of dials from the discovery cache while below the peer target (defaults: `HEGEMON_PQ_DISCOVERY_MIN_PEERS=4`, `HEGEMON_PQ_DISCOVERY_TICK_SECS=30`).
Nodes also request peer graphs on a periodic tick (default: `HEGEMON_PQ_PEER_GRAPH_TICK_SECS=30`) so monitoring tools can render the network topology.

Sync source selection is gated by an explicit compatibility probe instead of a "peer is not too far ahead" heuristic. For unknown peers, the node first issues `CompatibilityProbe { local_genesis_hash, sync_protocol_version, aggregation_proof_format }` and only marks the peer sync-compatible if the response confirms all three values match local expectations. Peers that mismatch on chain identity, sync protocol compatibility version, or aggregation proof format ID are marked incompatible and excluded from sync candidate selection. This keeps bootstrap for brand-new nodes unbounded by height while still filtering legacy/wrong-chain noise deterministically.
Sync request/response correlation uses explicit request identifiers in `SyncMessage::RequestV2 { request_id, request }`; responders echo that ID in `SyncResponse`, and clients accept responses only when `(peer_id, request_id, request_type)` matches a tracked pending request.
Sync scheduling prioritizes already-compatible peers before probing unknown peers, so legacy/high-noise peers cannot stall catch-up when a valid peer is available. Peers newly marked incompatible are disconnected automatically. Discovery address/graph traffic and cached discovery dials are restricted to compatibility-verified peers (chain + protocol + aggregation format) to prevent wrong-chain/legacy nodes from polluting the active peer set.
When no compatible peer currently advertises a higher tip, nodes run a lightweight tip-poll state (`GetBlocks` from `best+1`) that does not mark the node as "actively syncing", so mining continues without pause/resume churn while still recovering from missed announces.

### 2. Object definitions (bits, fields, encodings)

#### 2.1 Value and asset ID

* \(v\): 64-bit unsigned integer, value of note.
* Encoded into one field element \(v \in \mathbb{F}_p\) via the natural embedding (\(0 \le v < 2^{64} \subset \mathbb{F}_p\)).
* \(a\): 64-bit asset ID (current MASP circuit) represented as a single field element \(a \in \mathbb{F}_p\).

#### 2.2 Address tag and randomness

* \(\text{addr\_tag}\): 256-bit tag derived from the recipient’s view key and diversifier index, represented as four field elements \(t_0, t_1, t_2, t_3\).
* \(\rho\): 256-bit per-note secret, represented as four field elements \(\rho_0, \rho_1, \rho_2, \rho_3\).
* \(r\): 256-bit blinding, represented as four field elements \(r_0, r_1, r_2, r_3\).

#### 2.3 Note commitment

Take the Poseidon2 sponge (width 12, rate 6, capacity 6) and define

\[
\begin{aligned}
cm = H_f(&\text{domain}_{cm},
    v, \\
    &a, \\
    &t_0, t_1, t_2, t_3, \\
    &\rho_0, \rho_1, \rho_2, \rho_3, \\
    &r_0, r_1, r_2, r_3)
\end{aligned}
\]

The sponge emits six field elements \((cm_0, cm_1, cm_2, cm_3, cm_4, cm_5)\). On chain, commitments are
serialized as 48 bytes by concatenating each 64-bit limb big-endian; a canonical encoding
requires each limb to be strictly less than the field modulus.

#### 2.4 Nullifier

* Nullifier secret: \(sk_{\text{spend}}\) is a 256-bit integer and never placed on chain.
* Nullifier key: first map \(sk_{\text{spend}}\) to field elements \(ssk_0, \ldots, ssk_3 \in \mathbb{F}_p\) (four 64-bit chunks), then

\[
nk = H_f(\text{domain}_{nk}, ssk_0, ssk_1, ssk_2, ssk_3).
\]

For each note with position \(\text{pos}\) (e.g., a 32-bit index):

* Represent \(\text{pos}\) as a single field element (since \(\text{pos} < 2^{32} < p\)).
* Represent \(\rho\) as above (\(\rho_0, \ldots, \rho_3\)).

Define

\[
nf = H_f(\text{domain}_{nf}, nk, \text{pos}, \rho_0, \rho_1, \rho_2, \rho_3).
\]

The sponge emits six field elements \((nf_0, nf_1, nf_2, nf_3, nf_4, nf_5)\). On chain, the nullifier is the
48-byte concatenation of those limbs, and canonical encodings reject any limb \(\ge p\).

This 6-limb encoding is protocol-breaking relative to the legacy 32-byte encoding; adopting it
requires a fresh genesis and wiping node databases and wallet stores.

### 3. Key / address hierarchy with ML-KEM

#### 3.1 Seed and derivations

Let `seed` be a 256-bit root (e.g., from BIP-39). Derive

```
sk_spend = HKDF("spend" || seed)
sk_view  = HKDF("view"  || seed)
sk_enc   = HKDF("enc"   || seed)
```

To get deterministic KEM keypairs, use `sk_enc` as the seed to the KEM keygen’s RNG. In practice:

```
(pk_enc, sk_enc_KEM) = MLKEM.KeyGen(seed = sk_enc || "0")
```

#### 3.2 Diversified addresses

To get multiple addresses from one wallet, for diversifier index \(i \in \{0, \ldots, 2^{32}-1\}\):

```
div_i      = SHA256("div" || sk_view || i)   // 256 bits
pk_recipient_i = H(sk_view || div_i)         // 256 bits
pk_auth    = Poseidon2("auth" || sk_spend)   // 256 bits (4 field limbs encoded as 32 bytes)
(pk_enc_i, sk_enc_i) = MLKEM.KeyGen(seed = sk_enc || encode(i))
```

The address \(\text{Addr}_i\) is then

```
Addr_i = Encode(version || crypto_suite || i || pk_recipient_i || pk_auth || pk_enc_i)
```

Today, `version = 3` and `crypto_suite = CRYPTO_SUITE_GAMMA` (ML-KEM-1024).

The wallet stores `sk_spend`, `sk_view`, and either `sk_enc` or all `sk_enc_i` derived on demand.

#### 3.3 Viewing keys

* Incoming Viewing Key (IVK): `ivk = (sk_view, sk_enc)` can recompute all `pk_recipient_i` and `sk_enc_i`, decrypt all notes, and see all incoming funds.
* Full Viewing Key (FVK): `fvk = (sk_view, sk_enc, prf_nf)` where `prf_nf = H_f(domain_nk, sk_spend)` is the circuit-compatible nullifier PRF output (not `sk_spend` itself).

In-circuit, nullifiers are derived from `sk_spend` and each input note is additionally bound to `pk_auth = Poseidon2("auth" || sk_spend)` via commitment preimage constraints, closing the ownership gap that previously allowed alternate nullifier secrets.

### 4. Note encryption details

Given recipient \(\text{Addr}_i\) with `(version, crypto_suite, diversifier_index, pk_enc_i, pk_recipient_i, pk_auth)`:

#### 4.1 Plaintext

Plaintext structure:

```
note_plain = (
  v:      uint64,
  a:      uint64,
  rho:    32 bytes,
  r:      32 bytes,
  pk_recipient: 32 bytes
)
```

The memo is a separate AEAD payload encrypted under the same shared secret.

#### 4.2 KEM + AEAD

Sender:

1. `(ct_kem, ss) = MLKEM.Encaps(pk_enc_i)`
2. `(k, nonce) = HKDF("wallet-aead", ss || label || crypto_suite)`
3. `ct_note = AEAD_Enc(k_note, nonce_note, note_plain, ad = version || crypto_suite || diversifier_index)`
4. `ct_memo = AEAD_Enc(k_memo, nonce_memo, memo, ad = version || crypto_suite || diversifier_index)`

On chain per output:

* `cm` as a 48-byte commitment (6 x 64-bit limbs, canonical encoding)
* `ct_kem` (~1.5 KB for ML-KEM-1024), SCALE-encoded with a compact length prefix and validated against `crypto_suite`
* `ct_note` and `ct_memo` packed into the 579-byte ciphertext container with the header fields above

Recipient with IVK/FVK:

* Recomputes all `sk_enc_i` and `pk_enc_i`.
* For each output:
  * Try `MLKEM.Decaps(sk_enc_i, ct_kem)` → either fail or give `ss`.
  * Derive `k`, attempt AEAD decrypt.
  * If AEAD succeeds, this note belongs to address `i`.

### 5. Main “join–split” circuit in detail

The base transaction circuit in this repository is fixed-size:

* `MAX_INPUTS = 2` input notes (spends)
* `MAX_OUTPUTS = 2` output notes (creates)

(See `circuits/transaction-core/src/constants.rs`.)

Per transaction, you produce one STARK proof that covers up to `MAX_INPUTS + MAX_OUTPUTS` notes. This fixed-size design keeps proof sizes and verifier costs bounded, but it means a wallet cannot directly spend more than 2 notes in a single transaction.

#### 5.0 Note consolidation and block-size-aware batching

When a wallet needs more than `MAX_INPUTS` notes to cover a payment (amount + fee), it must first **consolidate**: perform one or more self-transfers that merge 2 notes into 1 note, reducing the number of notes needed for the final send.

Important constraint: the transaction membership proof anchors to a prior commitment-tree root, so a note created in a transaction cannot be spent again until it is mined and the wallet has synced a later root. That makes consolidation inherently multi-block: it proceeds in **rounds**.

The wallet therefore uses a round-based workflow:

1. Pick just enough notes to cover the target value (including a fee budget for the consolidation transactions themselves).
2. Submit a batch of disjoint 2→1 consolidation transactions in one round, capped by (a) a maximum transactions-per-round and (b) a block-size budget. Consolidation now defaults to DA sidecar submission (ciphertexts staged via `da_submitCiphertexts`) and, by default, proof sidecar staging (`da_submitProofs`) so rounds can include substantially more merges than inline-proof mode.
3. Wait for confirmation, sync, and repeat until the selected notes fit within `MAX_INPUTS`.

This does not change the total number of required consolidation transactions in the worst case (with 2→1 merges it is still `note_count - MAX_INPUTS`), but it reduces wall-clock time by letting miners include multiple independent merges in the same block when space permits. The batch-size budget must stay below the runtime block length (see `runtime/src/lib.rs`). Operators can tune consolidation throughput with `HEGEMON_WALLET_CONSOLIDATION_MAX_TXS_PER_BATCH` and `HEGEMON_WALLET_CONSOLIDATION_MAX_BATCH_BYTES`; sidecar/proof-sidecar behavior is controlled by `HEGEMON_WALLET_CONSOLIDATION_DA_SIDECAR` and `HEGEMON_WALLET_CONSOLIDATION_PROOF_SIDECAR`.

#### 5.1 Public inputs

The circuit's public inputs (fed into its transcript) are:

* `root_before` - Merkle root anchor encoded as six field elements.
* For each input `i`: `input_active[i] ∈ {0,1}` and `nf_in[i]` is a 6-limb nullifier, with inactive inputs using all-zero limbs.
* For each output `j`: `output_active[j] ∈ {0,1}` and `cm_out[j]` is a 6-limb commitment, with inactive outputs using all-zero limbs.
* For each output `j`: `ct_hash[j]` as a 6-limb ciphertext hash (padded with zeros for inactive outputs).
* `fee_native ∈ F_p` and `value_balance` split into a sign bit plus a 61-bit magnitude.
  In production, `value_balance` is required to be zero because there is no transparent pool.
* `balance_slot_asset_ids[0..3]`, where slot `0` is the native asset, active non-native asset ids are strictly increasing, and padding uses `u64::MAX` only as a suffix.

The AIR now binds `ct_hash[j]` at the final-row gate (the hash value itself is still computed outside the circuit from ciphertext bytes).

The transaction envelope still carries the full `balance_slots` vector and a `balance_tag`, which are validated outside the STARK for now.
`root_after` and any `txid` binding are handled at the block circuit layer (or a future transaction-circuit revision).

As an additional integrity check outside the STARK, the runtime and wallet compute a 64-byte binding hash over the public inputs:

```
message = anchor || nullifiers || commitments || ciphertext_hashes
       || balance_slot_asset_ids || fee || value_balance
binding_hash = Blake2_256("binding-hash-v1" || 0 || message)
             || Blake2_256("binding-hash-v1" || 1 || message)
```

Verifiers must compare all 64 bytes; this is a defense-in-depth commitment, not a signature.

#### 5.2 Witness (private inputs)

For each input `i`:

* `v_in[i] ∈ [0, 2^61)`
* `a_in[i]` (asset id) as a single 64-bit field element
* `pk_recipient_in[i]` as 4 field elements (32 bytes split into 4 x 64-bit limbs)
* `pk_auth_in[i]` as 4 field elements
* `rho_in[i]` as 4 field elements
* `r_in[i]` as 4 field elements
* Merkle auth path: `sibling_in[i][d]` is a 6-limb node for `d = 0 .. D-1`
* `pos_in[i]` as a 64-bit field element used by the prover to order left/right siblings
* The spend secret `sk_spend`

For each output `j`:

* `v_out[j] ∈ [0, 2^61)`
* `a_out[j]` as a single 64-bit field element
* `pk_recipient_out[j]` as 4 field elements
* `pk_auth_out[j]` as 4 field elements
* `rho_out[j]` as 4 field elements
* `r_out[j]` as 4 field elements
* `pos_out[j]` (if the transaction is responsible for tree updates; otherwise position is implicit or handled at block level)

#### 5.3 Constraints: input note verification

For each input `i`:

1. **Recompute commitment and check membership**

   * Compute

   \[
   cm_{\text{in}}[i] = H_f(\text{domain}_{cm}, v_{\text{in}}[i], a_{\text{in}}[i], \text{pk\_recipient}_{\text{in}}[i][0..3], \rho_{\text{in}}[i][0..3], r_{\text{in}}[i][0..3], \text{pk\_auth}_{\text{in}}[i][0..3]).
   \]

   * Compute the root via the Merkle path by iterating the sponge with `domain_merkle` using the left/right ordering derived from `pos_in[i]`.
   * Constrain the resulting root to equal `root_before`. (The position bits are not separately constrained in the current AIR.)

2. **Nullifier + ownership binding**

   * Derive the nullifier key once: split `sk_spend` into four field words `ssk_0 .. ssk_3` and compute `nk = H_f(domain_nk, ssk_0, ssk_1, ssk_2, ssk_3)`.
   * Derive the authorization key in-circuit from the same secret and constrain it to match `pk_auth_in[i]` absorbed by the note-commitment phase.
   * For each input note, compute

   \[
   nf_{\text{calc}}[i] = H_f(\text{domain}_{nf}, nk, pos_{\text{in}}[i], \rho_{\text{in}}[i][0..3])
   \]

   and constrain `nf_calc[i] == nf_in[i]`.
   * The AIR now binds `rho_in[i]` across phases with a shared four-limb carry lane: it holds input 0's rho until input 0's nullifier phase finishes, then reuses the same lane for input 1's rho.
   * The AIR also derives `nk` in-circuit from `sk_spend` (first cycle) and constrains each nullifier absorb row to use that derived key.
   * The AIR derives `pk_auth` from the same `sk_spend` derivation state and constrains each active input commitment to absorb that exact `pk_auth`.

#### 5.4 Constraints: output commitments

For each output `j`, enforce

\[
cm_{\text{calc}}[j] = H_f(\text{domain}_{cm}, v_{\text{out}}[j], a_{\text{out}}[j], \text{pk\_recipient}_{\text{out}}[j][0..3], \rho_{\text{out}}[j][0..3], r_{\text{out}}[j][0..3], \text{pk\_auth}_{\text{out}}[j][0..3]) = cm_{\text{out}}[j].
\]

#### 5.5 Value range checks

The transaction AIR enforces monetary range bounds in-circuit using a shared radix-limb region:

* each bounded value is decomposed into 21 radix-8 limbs (`3` bits each, with a boolean top limb),
* note values (`v_in`, `v_out`) use that limb region at note-start rows,
* `fee_native`, `|value_balance|`, and `|stablecoin_issuance_delta|` reuse the same limb region on their dedicated rows near the end of the trace.

This 61-bit cap (`MAX_IN_CIRCUIT_VALUE = 2^61 - 1`) prevents modular-wrap balance equalities under the current 2-input/2-output shape while keeping amounts large enough for practical usage.

Witness validation mirrors the same bound so invalid amounts are rejected before proving.

#### 5.6 MASP: per-asset balance with a small number of slots

Assume each transaction can involve at most `K` distinct assets (e.g., `K = 4`). Allocate `K` asset slots in the circuit.

Witness for MASP:

* Slot 0 is an implicit native-asset slot; the trace stores running `sum_in[k]`, `sum_out[k]` for all `k = 0 .. K-1`, and stores explicit `asset_slot[k]` values only for the non-native slots `k = 1 .. K-1`.
* For each fixed note slot, two selector bits encode the chosen balance slot (`00`, `01`, `10`, `11`).

Constraints:

1. **Selector correctness** - each selector bit is boolean, and inactive padded notes are forced to keep both bits at `0`.
2. **Asset-id consistency** - decode the selector bits into four low-degree slot weights and enforce that each active note's `asset_id` equals the asset stored in its selected slot.
3. **Summation** - update `sum_in` and `sum_out` by adding note values at their note-start rows into the selected slot accumulator.
4. **Conservation per slot** - enforce `net_k = sum_in[k] - sum_out[k]`. For the native asset slot (slot 0 with `asset_id = 0`), constrain `net_0 + value_balance = fee_native`. For other slots, constrain `net_k = 0`. The slot list is derived from witness `balance_slots` and padded with `asset_id = 2^64 - 1` where unused.

This MASP approach is cheaper than sorting an arbitrary `(asset_id, delta)` multiset but restricts how many assets can appear in one transaction.

### 6. Tree evolution and block-level commitment proofs

To avoid putting Merkle tree updates in every transaction circuit, handle them at the block level.

#### 6.1 Per-transaction proof

The transaction proof shows:

* Inputs are members of `root_before`.
* Commitments `cm_out` are well formed.
* Nullifiers `nf_in` are correctly derived.
* Value balance per asset holds.

It does not assert anything about `root_after`.

#### 6.2 Block state

The node maintains a canonical commitment tree with current root `root_state`. A block contains a list of transactions `T_1 .. T_m` and for each transaction a public `root_before` anchor that must appear in the recent anchor window (Merkle root history). Transactions are still applied in order to update the tree, but `root_before` need not equal the running root.

#### 6.3 Block circuit and proof

The repository now wires this design into executable modules. The `state/merkle` crate implements an append-only `CommitmentTree` that precomputes default subtrees, stores per-level node vectors, and exposes efficient `append`, `extend`, and `authentication_path` helpers. It uses the same Poseidon-style hashing domain as the transaction circuit, ensuring leaf commitments and tree updates are consistent with the ZK statement. `TransactionProof::verify` rejects missing STARK proof bytes/public inputs in production builds. On top of that, the `circuits/block` crate treats commitment proofs as the default: `CommitmentBlockProver` builds a `CommitmentBlockProof` that commits to transaction statement hashes via a Poseidon sponge (`tx_statements_commitment`), and consensus verifies the commitment proof alongside per-transaction input checks. In `InlineRequired`, blocks without an aggregation proof use parallel per-transaction verification. In `SelfContained` aggregation mode, proofless transfers remain fail-closed (missing proven-batch payload is invalid), and strict authoring requires a ready `submit_proven_batch` payload for shielded block candidates (no on-demand proving fallback during block assembly). Legacy proofless block compatibility overrides are disabled in strict v0.9 mode. Recursive epoch proofs remain removed; aggregation proofs are the only recursion path in the live system today.

Aggregation payloads are produced from transaction proof bytes alone, never from spend witnesses. Block producers include proof material via a single `submit_proven_batch` payload (legacy runtime encoding: `BlockProofBundle`, fresh-testnet public vocabulary: `CandidateArtifact`). The active hard-cut payload is schema `2` with proof format id `5` and explicit proof modes: `InlineTx`, `MergeRoot`, `ReceiptRoot`, and the now-disabled `FlatBatches` recovery history. Every payload now also carries an explicit backend-neutral `(proof_kind, verifier_profile)` pair beside the legacy `proof_mode`, and consensus routes verification through a verifier registry keyed by artifact kind instead of wiring raw Plonky3 checks directly into import. `consensus::types::Block` now carries `tx_validity_artifacts` plus an optional `block_artifact` envelope rather than a raw `transaction_proofs` vector. `InlineTx` is the live low-TPS lane: the artifact carries the commitment proof plus block-level metadata, while the tx-validity artifacts embed the canonical ordered tx proofs. `MergeRoot` remains an experimental recursive mode bound to tree metadata + leaf manifest commitment (`HEGEMON_MERGE_ARITY`, defaulting to `HEGEMON_AGG_MERGE_FANIN`, so `2` on that experimental lane unless overridden). `ReceiptRoot` is the first additive neutral artifact kind: an experimental parent-independent root over canonical transaction-validity receipts. `FlatBatches` remains only for the legacy witness-batch STARK proof kind and the benchmarked recovery history; the proof-bytes `TxProofManifest` wrapper lost locally and is now dead, so `HEGEMON_BLOCK_PROOF_MODE=flat` falls back to `inline_tx`. Canonical transaction-validity receipts are derived from a tx statement hash, proof digest, serialized public-input digest, and verifier-profile digest, and the experimental `ReceiptRoot` adapter already consumes that exact receipt object. Generic consensus/node code now reaches that backend only through neutral receipt-root helper APIs, not by importing `superneo-*` crates directly. Node authoring uses an asynchronous prover coordinator (`node/src/substrate/prover_coordinator.rs`) that runs a bounded worker queue and exposes open prover-market work packages through additive RPC methods (`prover_getWorkPackage`, `prover_submitWorkResult`, `prover_getWorkStatus`, `prover_getMarketParams`, `prover_getStageWorkPackage`, `prover_submitStageWorkResult`, `prover_getStagePlanStatus`) plus reusable-artifact discovery helpers (`prover_listArtifactAnnouncements`, `prover_getCandidateArtifact`). Work packages are bounded by payload-size caps, per-source limits, per-package submission limits, and expiry windows. The live raw/inline-tx mode does not publish any external proving work at all: it schedules only the parent-bound finalize/commitment job and requires proof-ready transactions with canonical inline tx proofs already attached. The recursive external-worker topology, stage planner, and merge-root layout helpers remain in-tree for experimentation, and they still use one canonical stage namespace plus parent-independent expensive work ids, but they are no longer the default authoring path. Before proving or block assembly, shielded candidate sets are sanitized to remove binding-hash duplicates while retaining nullifier-overlap candidates for runtime-side conflict resolution. The coordinator can overscan and trim to target size using `HEGEMON_BATCH_CANDIDATE_OVERSCAN_FACTOR` (default `4`) so conflict filtering still leaves a dense candidate set. If `HEGEMON_BATCH_TARGET_TXS` is unset, startup caps the default to `min(HEGEMON_MAX_BLOCK_TXS, HEGEMON_BATCH_DEFAULT_TARGET_TXS)` with `HEGEMON_BATCH_DEFAULT_TARGET_TXS=32`. During block assembly, proofless transfers are now a `merge_root` / `receipt_root` experiment gated by `HEGEMON_AGGREGATION_PROOFS`; in the live `inline_tx` lane they are skipped, and block production consumes only proof-ready transactions. The service-level authoring selector resolves `HEGEMON_BLOCK_PROOF_MODE` aliases immediately into `(proof_kind, verifier_profile, legacy_mode)` before choosing a build path, so future backends can reuse the same routing surface. Bundle preparation performs a single shared preprocessing pass per candidate (`decode + transfer extraction + statement hash derivation + DA encoding`) and then runs the commitment stage against that shared context; when `merge_root` or `receipt_root` is selected explicitly, the parent-independent payload stage runs in parallel, but in `inline_tx` mode the aggregation stage is a no-op. Prove-ahead remains active across block transitions: import success immediately re-runs candidate scheduling for the new parent so proving for block `N+1` starts while `N` is already sealed/propagating. The throughput harness exports the three honest comparison surfaces now in use: `raw_shipping` for the frozen tx-proof transport baseline, `raw_active` for canonical tx proofs plus commitment, and `merge_root_active` for recursion plus commitment. It supports `--cold` / `--warm`, `--raw-only`, and `--skip-merge-root`, logs stage attribution and structured lane failures instead of aborting, and uses the same anchor-history-consistent tx fixture plus full commitment public-input layout as the live node.
Aggregation candidate selection now also drops proof-sidecar transfers whose ciphertext bytes are not available in the local pending sidecar store, preventing endless reproving loops on nodes that did not receive the sidecar payloads directly. Mining workers also discard the current template after an import failure, forcing a fresh template/proof bundle instead of repeatedly hashing an invalid block candidate.

Block-proof payload compatibility is now hard-cut to schema `2` + proof format id `5` in active import logic. Nodes reject malformed or legacy payload versions fail-closed. Import now treats the block artifact as a neutral `(proof_kind, verifier_profile, bytes)` object even when the on-chain payload still carries the legacy `proof_mode` selector for compatibility. `InlineTx` is the live import path: consensus verifies the commitment proof, recomputes `tx_statements_commitment` from the canonical transaction-proof statement hashes, then verifies the ordered inline tx validity artifacts directly and rejects mismatched proofs, bad ordering, commitment mismatches, duplicate/nullifier conflicts, or missing inline proof bytes. `ReceiptRoot` is now the first non-inline experimental kind on that same path: import verifies the receipt-root artifact against the ordered receipt set, then checks that the receipt statement hashes commit to the block’s expected `tx_statements_commitment` before accepting the block. `FlatBatches` import validation still enforces deterministic sorted contiguous coverage of `[0, tx_count)` with no gaps/overlaps and verifies every batch artifact against its covered transaction subset, but it now exists only for the old witness-batch STARK proof kind and local/trusted history because the proof-bytes `TxProofManifest` recovery prototype lost to raw tx-proof shipping at every measured `k` (`1,2,4,8`). On an 8-tx release run the wrapper added roughly `66-69 ms` of extra build time, slightly increased payload bytes (`~355.2 KiB/tx` vs `~354.2 KiB/tx` raw), and did not reduce verification time enough to matter, so import rejects that proof kind and `HEGEMON_BLOCK_PROOF_MODE=flat` falls back to `inline_tx`. `MergeRoot` validation still verifies the root proof plus manifest/tree metadata bindings, and the recursive path still derives dependency ids and worker dispatch from one canonical stage namespace while splitting reusable parent-independent aggregation artifacts from the final parent-bound bundle assembly step. Shared merge-root layout helpers compute fan-in, arity, tree levels, and the leaf manifest commitment for consensus, node planning, and the benchmark harness, which removes a silent divergence risk between those paths. The benchmark harness distinguishes the three relevant surfaces explicitly: `raw_shipping` is the frozen transport baseline; `raw_active` is canonical tx proofs plus the live commitment proof path; and `merge_root_active` is aggregation plus commitment. It reports common active-path timing/byte fields across those lanes, supports `--cold` / `--warm`, converts merge-root panics or commitment-stage failures into structured lane errors instead of aborting the process, exposes `--raw-only` for release-fingerprint checks, and exposes `--skip-merge-root` so `raw_active` can still be archived cleanly once merge-root has already crossed the stall line. The benchmark tx fixture feeds both active lanes from a shared anchor-history tree, and the commitment AIR consumes the full 45-element public-input prefix including the kernel-root commitments. With those honesty fixes in place, the low-TPS comparison has already resolved: `raw_active(k=1)` beats `merge_root_active(k=1)` on bytes and active-path latency (`536098 B/tx`, `70812417 ns` prove, `18299167 ns` verify versus `536258 B/tx`, `79701375 ns`, `25680001 ns`), and `merge_root_active(k=2)` fails to clear a `65s` wall-clock budget while `raw_active(k=2)` finishes at `456262 B/tx`, `108371875 ns` active-path prove, and `29954584 ns` active-path verify. That kills merge-root as the low-TPS hot path, and production now defaults to the raw/inline-tx live block-proof mode. Operators tune rollout profiles primarily through `HEGEMON_BATCH_SLOT_TXS` (default `16`, then `32`, then `64`) and mode selection via `HEGEMON_BLOCK_PROOF_MODE` (`inline_tx` default, `merge_root` explicit, `receipt_root` experimental, `flat` forced back to `inline_tx`), while prover-market stage controls remain available for experiments (`HEGEMON_AGGREGATION_PROOFS`, `HEGEMON_AGG_STAGE_QUEUE_DEPTH`, `HEGEMON_AGG_STAGE_LOCAL_PARALLELISM`, `HEGEMON_PROVER_STAGE_MAX_INFLIGHT_PER_LEVEL`, `HEGEMON_PROVER_STAGE_MEM_BUDGET_MB`).
Batch STARK verification now caches `setup_preprocessed()` verifier keys by proof shape (`degree_bits`, inferred FRI blowup) so preprocessed trace commitments are built once and reused across block imports; node startup prewarms the configured shape set via `HEGEMON_BATCH_VERIFY_PREWARM_TXS` (defaults to the current `HEGEMON_BATCH_SLOT_TXS` power-of-two profile).
Prove-ahead block proof preparation now caches parent-independent aggregation artifacts (`FlatBatches` chunk proofs, `MergeRoot` payloads, or `ReceiptRoot` payloads) keyed by the neutral prepared-artifact selector plus `(tx_statements_commitment, tx_count, shape profile)` via `HEGEMON_PROVE_AHEAD_CACHE_CAPACITY`, so parent transitions only pay the commitment-proof step when the candidate set is unchanged. During the tx-proof-manifest recovery experiment, coordinator `candidate_set_id` and chunk `package_id` were derived only from ordered tx content and chunk range, not from `parent_hash` or `block_number`; that parent-independent identity work remains valid design guidance, but the tx-proof-manifest lane itself is now disabled after the benchmark loss. Coordinator scheduling now gates readiness on the current parent/generation only: stale-parent prepared bundles are retained for cache amortization, but they no longer suppress new-parent work-package scheduling. Block assembly and preview readiness checks still require exact-parent prepared bundles (no cross-parent fallback), preserving fail-closed correctness. To keep that exact-parent rule usable on the current external-prover topology, public authors hold local mining while a strict proofless batch waits for a ready bundle (`HEGEMON_AGG_HOLD_MINING_WHILE_PROVING`, default on when aggregation proofs are enabled), so self-mined empty blocks do not invalidate the parent before the recursive proof lands.

The commitment proof binds `tx_statements_commitment` (derived from the ordered list of canonical transaction statement hashes) and proves nullifier uniqueness in-circuit (a permutation check between the transaction-ordered nullifier list and its sorted copy, plus adjacent-inequality constraints). The proof also exposes starting/ending state roots, nullifier root, and DA root as public inputs, but consensus recomputes those values from the block’s transactions and the parent state and rejects any mismatch; this keeps the circuit within a small row budget while preserving full soundness. On Substrate, the `submit_proven_batch` extrinsic carries the computed `da_root` plus `chunk_count` explicitly so importers can fetch DA chunks before reconstructing ciphertexts and archive audits can select valid chunk indices.

Data availability uses a dedicated encoder in `state/da`. The block’s ciphertext blob is serialized as a length-prefixed stream of ciphertexts (ordered by transaction order, then ciphertext order) and erasure-encoded into `k` data shards of size `da_params.chunk_size` plus `p = ceil(k/2)` parity shards. The Merkle root `da_root` commits to all `n = k + p` shards using BLAKE3 with domain tags `da-leaf` and `da-node`. Consensus recomputes `da_root` from the transaction list and rejects any mismatch before verifying proofs. Sampling is per-node randomized: each validator chooses `da_params.sample_count` shard indices, fetches the chunk and Merkle path over P2P, and rejects the block if any sampled proof fails.

Two on-chain policies gate these checks: `DaAvailabilityPolicy` selects between `FullFetch` (reconstruct and verify `da_root`) and `Sampling` (verify randomized chunks against the commitment payload’s `da_root`/`chunk_count` without full reconstruction), and `CiphertextPolicy` toggles whether inline ciphertext bytes are accepted or sidecar-only submissions are enforced. The node consults the runtime API for the active policy on import, so the network can start with full storage and migrate to sampling + sidecar enforcement as the prover/DA markets mature.

Operationally, the node persists DA encodings and ciphertext bytes for a bounded “hot” retention window and prunes old entries by block number. Ciphertexts use `HEGEMON_CIPHERTEXT_DA_RETENTION_BLOCKS` (falling back to legacy `HEGEMON_DA_RETENTION_BLOCKS`). Proof sidecars are no longer consensus-critical in Phase C; retention for proposer staging is operational, not validity-critical.

For throughput benchmarking, the recursive worker-cache lifecycle matters as much as the prover-worker count. `scripts/throughput_scaling_matrix.sh` now keeps worker prewarm disabled only during funded snapshot creation, because snapshots never build recursive proofs. Real strict throughput points default to worker prewarm enabled and, unless the operator overrides `HEGEMON_SCALE_AGG_PREWARM_MAX_TXS`, they prewarm the exact target `tx_count` shape before send. The matrix also defaults to `HEGEMON_AGG_PREWARM_INCLUDE_MERGE=0`, which means startup warms the leaf recursion cache/common-data path without paying a full representative leaf outer proof just to derive merge-prewarm inputs. This prevents the matrix from charging thread-local cache/common-data setup to the first live proofless batch while keeping startup materially lower than the old full-prewarm path. The standalone `hegemon-prover-worker` now follows the same operational rule: it prewarms its aggregation cache on startup unless `HEGEMON_AGG_DISABLE_WORKER_PREWARM=1` is set, and logs stage start/completion timing so operators can distinguish cold setup from actual proving. Operators can still force full prewarm explicitly by setting `HEGEMON_SCALE_AGG_PREWARM_INCLUDE_MERGE=1`.

`verify_block` expects miners to supply the current tree state. It verifies the commitment proof once via `circuits/block::commitment_verifier::verify_block_commitment`, recomputes the transaction-ordered nullifier list (padding each transaction to `MAX_INPUTS`) to ensure the proof’s public inputs match the block’s transactions, checks `tx_statements_commitment` against the canonical transaction statement hash list, and then enforces mode guarantees: `InlineRequired` validates inline tx proofs (with or without an aggregation proof), while `SelfContained` fail-closes proofless transfers by requiring a valid aggregation/proven-batch payload. It then updates the tree to the expected ending root. In `SelfContained` aggregation mode, this path does not require per-transaction proof bytes to be present in the block. Solo miners follow a simple operational loop: sync the tree, run the block verifier on any candidate they plan to extend, update their local `VersionSchedule`, and only then start hashing on top of the verified root. Mining pauses while the node is catching up to peers so local hashing never races against historical imports. Public authoring nodes do the same before broadcasting templates or blocks, so every verifier sees the same state transition without needing an external prover host in the live path. Operators must configure the same `HEGEMON_SEEDS` list across miners to avoid forked peer partitions, and must keep NTP/chrony time sync enabled because PoW headers with timestamps beyond the future-skew bound are rejected. This provides a concrete path from transaction proofs to a block-level proof artifact that consensus can check without per-transaction recursion. The operational growth path for this authoring model is tracked in [docs/SCALABILITY_PATH.md](docs/SCALABILITY_PATH.md): start with one public authoring node running `InlineTx`, raise proof-ready transaction throughput, then add federated authors before attempting any public prover market.

Define a block commitment circuit `C_commitment` with

* Public inputs: `tx_statements_commitment`, `root_prev`, `root_new`, `nullifier_root`, `da_root`, `tx_count`, plus the transaction-ordered nullifier list and its sorted copy (both length `tx_count * MAX_INPUTS`). For Plonky3, the permutation challenges `(alpha, beta)` are included as public inputs derived from a Blake3 hash of the same inputs, and verifiers recompute them off-circuit to avoid embedding Blake3 inside the AIR.
* Witness: the `tx_statement_hashes` and the nullifier columns (unsorted + sorted lists).

Constraints in `C_commitment`:

1. **Commit to statement hashes** – absorb statement-hash limbs into a Poseidon sponge and enforce the 6-limb commitment equals `tx_statements_commitment`.
2. **Check nullifier uniqueness** – enforce a permutation check between the transaction-ordered nullifier list and its sorted copy, then require no adjacent equals in the sorted list (skipping zero padding).
3. **Expose roots and DA** – carry `root_prev`, `root_new`, `nullifier_root`, and `da_root` as public inputs so consensus can recompute them from the block’s transactions and parent state and reject mismatches.

This yields a per-block proof `π_block` showing that the miner committed to the exact list of transaction statement hashes and that the padded nullifier multiset is unique, while leaving deterministic state transitions (commitment tree updates and DA root reconstruction) to consensus checks outside the circuit.

#### 6.4 Circuit versioning

If you introduce a new transaction circuit version, update `C_block` so its verification step accepts both old and new proofs. After some time, consensus can reject new transactions with old-version proofs, but `C_block` retains backward verification code as long as necessary (or you drop it when you no longer need to accept old blocks).

#### 6.5 Epoch proof hashes (removed)

Recursive epoch proofs were removed alongside the previous recursion stack. Reintroducing them requires a Plonky3-native recursion design; until then, there are no epoch proof hashes in the live system.

#### 6.6 Settlement batch proofs

Settlement batch proofs bind instruction IDs and nullifiers into a Poseidon2-based commitment. The public inputs are the instruction count, nullifier count, the padded instruction ID list (length `MAX_INSTRUCTIONS`), the padded nullifier list (length `MAX_NULLIFIERS`), and the commitment itself. The commitment is computed by absorbing input pairs into a Poseidon2 sponge initialized as `[domain_tag, 0, 1]`, adding each pair to the first two state elements, running the full-round permutation per absorb cycle, and repeating for the full padded input list. Nullifiers are Poseidon2-derived from `(instruction_id, index)` under a distinct domain tag, then encoded as 48 bytes with six big-endian limbs; canonical encodings reject any limb \(\ge p\). Settlement verification rejects non-canonical encodings and currently verifies with compile-time Plonky3 production parameters (`log_blowup = 4`, `num_queries = 32`).


---

## 7. Post-quantum crypto module (reference implementations)

The `crypto/` crate provides deterministic reference bindings for the PQ primitives referenced throughout the design. All APIs live in safe Rust and use fixed-length byte arrays so that serialization matches the NIST ML-DSA, SLH-DSA, and ML-KEM parameter sizes without pulling in the full reference C code.

Module layout:

* `crypto::ml_dsa` – exposes `MlDsaSecretKey`, `MlDsaPublicKey`, and `MlDsaSignature` with `SigningKey`/`VerifyKey` trait implementations. Secret keys derive public keys by hashing with domain tag `ml-dsa-pk`, and signatures deterministically expand `ml-dsa-signature || pk || message` to 3293 bytes.
* `crypto::slh_dsa` – mirrors the ML-DSA interface but with SLH-DSA key lengths (32 B public, 64 B secret, 17088 B signatures).
* `crypto::ml_kem` – wraps Kyber-like encapsulation with `MlKemKeyPair`, `MlKemPublicKey`, and `MlKemCiphertext`. Encapsulation uses a seed to deterministically derive ciphertexts and shared secrets, while decapsulation recomputes the shared secret from stored public bytes.
* `crypto::hashes` – contains `sha256`, `sha3_256`, `blake3_256`, `blake3_384`, a Poseidon-style permutation over the Goldilocks prime (width 3, 63 full rounds, NUMS constants), and helpers `commit_note`, `derive_prf_key`, and `derive_nullifier` (defaulting to 48-byte BLAKE3-384 with SHA3-384 fallbacks via `commit_note_with`) that apply the design’s domain tags (`"c"`, `"nk"`, `"nf"`). PQ address hashes remain BLAKE3-256 by default while commitments/nullifiers normalize on 48-byte digests.
* `pallet_identity` – stores optional PQ session keys as `SessionKey::PostQuantum` (Dilithium/Falcon). New registrations supply PQ bundles through the `register_did` call without a one-off rotate extrinsic.
* `pallet_attestations` / `pallet_settlement` – historically stored `StarkVerifierParams` in pallet storage, but the proof-native cut treats these as protocol-release parameters rather than governance-controlled setters. The live Plonky3 transaction/settlement verifier path currently uses compile-time production parameters from `transaction-core` (`log_blowup = 4`, `num_queries = 32`), and runtime defaults should come from the active protocol manifest. With 384-bit digests, PQ collision resistance reaches ~128 bits.

The crate’s `tests/crypto_vectors.rs` fixture loads `tests/vectors.json` to assert byte-for-byte deterministic vectors covering:

* key generation and signing for ML-DSA and SLH-DSA,
* ML-KEM key generation, encapsulation, and decapsulation,
* hash-based commitment, PRF key derivation, nullifier derivation, SHA-256, BLAKE3, and Poseidon outputs.

Run `cargo test` from the `crypto/` directory to regenerate and validate all vectors.

## 6. Monorepo workflows and CI hooks

Implementation hygiene now mirrors the layout introduced in `DESIGN.md §6` and the documentation hub under `docs/`.

### Required commands before every PR

1. **Default blocking gate** – run `./scripts/check-core.sh all`.
   This is the exact fast path enforced by CI: formatting, curated clippy, shipping-path Rust tests, then a release `hegemon-node` build.
2. **What the default test gate covers**:
   - `cargo test -p synthetic-crypto` for deterministic PQ primitive vectors.
   - `cargo test -p consensus`, `cargo test -p network`, `cargo test -p runtime`, and `cargo test -p hegemon-node --lib` for the live node/runtime/network path.
   - `cargo test -p transaction-circuit`, `cargo test -p block-circuit`, and `cargo test -p disclosure-circuit` for the circuits that still back the shipped wallet/disclosure flow.
   - `cargo test -p wallet` plus `cargo test --test security_pipeline -- --nocapture` for the wallet/store/send pipeline.
   The expensive `circuits/batch` proving tests are intentionally `#[ignore]` because that auxiliary batch lane is not part of the live InlineTx authoring path; default CI keeps only cheap structural sanity coverage for that crate.
3. **Manual security harnesses** – run these only when touching the relevant surface:
   - `cargo test -p consensus --test fuzz -- --ignored` (consensus duplicate-nullifier property coverage).
   - `PROPTEST_MAX_CASES=64 cargo test -p transaction-circuit --test security_fuzz` (transaction witness invariants).
   - `PROPTEST_MAX_CASES=64 cargo test -p network --test adversarial` (handshake tampering).
   - `PROPTEST_MAX_CASES=64 cargo test -p wallet --test address_fuzz` (address encode/decode mutations).
4. **Manual performance/profiling harnesses**:
   - `cargo run -p circuits-bench -- --smoke --prove --json` when touching circuit proving/profiling code.
   - `cargo run -p wallet-bench -- --smoke --json` when touching wallet hot paths.
   - `(cd consensus/bench && go test ./... && go run ./cmd/netbench --smoke --json)` when touching the Go simulator.
5. **Auxiliary proving lanes (manual)**:
   - `cargo test -p batch-circuit batch_proof_verifies_for_single_input_witness -- --ignored` and `cargo test -p batch-circuit batch_proof_verifies_for_four_single_input_witnesses -- --ignored` when changing `circuits/batch` or its benchmark harness.
   - `cargo test --manifest-path spikes/recursion/Cargo.toml --test transaction_aggregate -- --ignored` when changing the recursion experiment or recording fresh aggregation metrics.

Document benchmark outputs in pull requests when you intentionally run those manual harnesses and the numbers move noticeably.

### CI job map (`.github/workflows/ci.yml`)

| Job | Purpose |
| --- | --- |
| `rust-lints` | Runs `./scripts/check-core.sh lint` for the curated default lint gate. |
| `core-tests` | Runs `./scripts/check-core.sh test` for the fast shipping-path Rust suite. |
| `release-build` | Runs `./scripts/check-core.sh build` so the release node and embedded WASM runtime still build cleanly. |

Operator-scenario harnesses such as `./scripts/test-substrate.sh restart-recovery` remain available for manual debugging, but they are not part of the default blocking CI gate.
Benchmark, simulator, and profiling harnesses such as `circuits-bench`, `wallet-bench`, `go test ./...` in `consensus/bench`, and `netbench` are also manual, not part of default CI.

All jobs operate on Ubuntu runners with Rust stable and the protobuf/libclang build dependencies installed via `apt`. Adding new languages or toolchains to the blocking gate requires updating this table, the workflow, and `docs/CONTRIBUTING.md`.

## 7. Node, wallet, and UI operations

Follow [runbooks/miner_wallet_quickstart.md](runbooks/miner_wallet_quickstart.md) whenever you need a reproducible demo:

1. Launch the Substrate-based `hegemon-node` binary with `HEGEMON_MINE=1` and `--dev` for fast block times. The node exposes JSON-RPC on port 9944 and P2P on port 30333 by default. Run `make node` to build.
2. Connect the desktop app or Polkadot.js Apps to the node RPC endpoint to view live telemetry. When using the desktop app, prefer a persistent base path (avoid `--tmp`), and set `--listen-addr /ip4/0.0.0.0/tcp/30333` only when you intend to accept IPv4 peer traffic. Expose RPC externally only on trusted networks.
   The desktop app is organized into Overview, Node, Wallet, Send, Disclosure, and Console workspaces. Its global status bar always shows the active node, wallet store, and genesis hash so operators can detect mismatches before sending or mining.
   Use `hegemon_peerGraph` to retrieve connected peer details plus reported peers (address, direction, best height/hash); `system_peers` remains empty on the PQ transport.
3. For multi-node setups, start additional nodes with the same `HEGEMON_SEEDS` list (for local testing, `HEGEMON_SEEDS=127.0.0.1:30333` for the first node endpoint).

### Security assurance workflow

- Follow `docs/SECURITY_REVIEWS.md` whenever commissioning cryptanalysis or third-party audits. Every finding recorded there must reference the code path touched plus the mitigation PR.
- `circuits/formal/README.md` and `consensus/spec/formal/README.md` explain how to run the new TLA+ models. Include the TLC/Apalache output summary in PR descriptions when those specs change.
- `runbooks/security_testing.md` documents how to rerun the `security-adversarial` job locally, capture artifacts, and notify auditors if a regression appears on CI. Treat it as mandatory reading before release tagging.
- Track dependency advisories with `./scripts/dependency-audit.sh --record`; this is advisory-only until release hardening, so treat findings as signals to triage rather than blockers.

### Documentation + threat-model synchronization

Whenever you touch an API, threat mitigation, or performance assumption:

1. Update the component README (e.g., `wallet/README.md`) with the new commands or invariants.
2. Update `docs/API_REFERENCE.md` so integrators can find the function signatures.
3. Update `docs/THREAT_MODEL.md` when security margins move.
4. Reflect the architectural impact in `DESIGN.md §6` (or the relevant subsystem section) and record the operational/testing changes here in METHODS.
5. Mention the change in `docs/CONTRIBUTING.md` so future contributors know which CI jobs/benchmarks cover it.

PRs missing any of these sync points should be blocked during review; CI surfaces the changed docs alongside code so reviewers can verify everything moved together.

### Aggregation runtime update (February 27, 2026)

- Local prover execution in `node/src/substrate/prover_coordinator.rs` now uses a dedicated long-lived worker pool instead of per-job `spawn_blocking` tasks. This keeps thread-local recursion artifacts on stable worker threads and reduces repeated cold cache rebuilds caused by thread churn.
- Aggregation cache warmup is now explicit and checkpointed by default:
  - `HEGEMON_AGG_PREWARM_MAX_TXS` controls whether breadth warmup is attempted at all (unset defaults to no automatic max-target expansion on the hot path).
  - `HEGEMON_AGG_PREWARM_MODE=checkpoint` (default) expands warmup shapes geometrically (`1,2,4,8,...`) when a max tx cap is provided.
  - `HEGEMON_AGG_PREWARM_MODE=linear` restores legacy linear warmup.
  - `HEGEMON_AGG_WARMUP_TARGET_SHAPES` continues to support explicit shape lists.

Operationally, this change removes hidden O(target) warmup churn from live proving and makes warmup policy explicit in runbooks and benchmark configs.
