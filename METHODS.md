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
* `rho` – per‑note secret (random)
* `r` – commitment randomness

We define the note commitment:

```text
cm = Com_note(value, asset_id, pk_recipient, rho, r)
   = Hc("note" || enc(value) || asset_id || pk_recipient || rho || r)
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
>   * `(value_i, asset_i, pk_i, rho_i, r_i, pos_i)`
>   * `sk_nf` (nullifier secret derived from `sk_view`)
> * for each output `j` in `[0..N-1]`:
>
>   * `(value'_j, asset'_j, pk'_j, rho'_j, r'_j)`
>
> such that:
>
> 1. **Note commitments match**
>
>    * For all inputs/outputs:
>
>      ```text
>      cm_i  = Com_note(value_i,  asset_i,  pk_i,  rho_i,  r_i)
>      cm'_j = Com_note(value'_j, asset'_j, pk'_j, rho'_j, r'_j)
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
>      nk = H("nk" || sk_nf)
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

Inside the AIR, the stablecoin slot selector must sum to 1 when the binding is enabled, the selected balance slot must match `stablecoin_asset_id`, and the selected slot delta must equal `issuance_delta`. All other non-native slots are still constrained to zero. The runtime then enforces that the binding matches the on-chain `StablecoinPolicy` hash and version, the oracle commitment is fresh, and the attestation is not disputed. This keeps issuance fully shielded while still tethering it to governance-approved policy inputs.

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

  * `sk_nf = H("view_nf" || sk_view)` used inside the STARK to derive nullifiers.
* **Viewing key material**:

  * `vk_full = (sk_view, sk_enc, sk_nf, public_params…)`
* **Incoming‑only viewing key**:

  * `vk_incoming = (sk_view, sk_enc, diversifier params)`
    (can scan chain and decrypt incoming notes, but can’t produce spends or see nullifiers.)

### 4.2 Nullifier key

Inside proofs we don’t want to expose `sk_nf` or `nk`, but we need a deterministic nullifier.

Define:

```text
sk_nf = H("view_nf" || sk_view)
nk = Hf("nk" || sk_nf)
nf = Hf("nf" || nk || rho || pos)
```

Only someone knowing `sk_nf` can compute `nf` for a given `(rho, pos)`; the STARK proves consistency while the wallet keeps
`sk_spend` separate for authorization/signing.

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
addr_d = EncAddr(version || d || pk_recipient(d) || pk_enc(d))
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

Hegemon chooses the watch‑only path: full viewing keys include `sk_nf = H("view_nf" || sk_view)` so wallets can compute
nullifiers for spentness tracking without embedding `sk_spend`.

### 4.5 Implementation details

*Key derivations and addresses.* `wallet/src/keys.rs` implements `RootSecret::derive()` using the domain-separated label `wallet-hkdf` and SHA-256 to expand `(label || sk_root)` into the 32-byte subkeys for spend/view/enc/diversifier. `AddressKeyMaterial` then uses `addr-seed` plus the diversifier index to deterministically derive the ML-KEM key pair; `pk_recipient` is derived from the view key and diversifier. `wallet/src/address.rs` serializes `(version, crypto_suite, index, pk_recipient, pk_enc)` as a Bech32m string (HRP `shca`) so senders can round-trip addresses through QR codes or the CLI.

*Note encryption.* `wallet/src/notes.rs` consumes the recipient’s Bech32 data, runs ML-KEM encapsulation with a random seed, and stretches the shared secret into two ChaCha20-Poly1305 keys via `expand_to_length("wallet-aead", shared_secret || label || crypto_suite, 44)`. The first 32 bytes drive the AEAD key and the final 12 bytes form the nonce so both note payload and memo use disjoint key/nonce pairs. Ciphertexts record the version, crypto suite, diversifier index, and ML-KEM ciphertext so incoming viewing keys can reconstruct the exact `AddressKeyMaterial` needed for decryption. The AEAD AAD binds `(version, crypto_suite, diversifier_index)` so header tampering fails authentication.

*Viewing keys and nullifiers.* `wallet/src/viewing.rs` defines `IncomingViewingKey` (scan + decrypt), `OutgoingViewingKey` (derive `pk_recipient` for audit), and `FullViewingKey` (incoming + nullifier key). Full viewing keys store the view-derived nullifier key `sk_nf = BLAKE3("view_nf" || sk_view)`, letting watch-only tooling compute chain nullifiers without exposing the spend key itself. `RecoveredNote::to_input_witness` converts decrypted notes into `transaction_circuit::note::InputNoteWitness` values by reusing the same `NoteData` and taking the best-effort `rho_seed = rho` placeholder until the circuit’s derivation is finalized.

*CLI, daemon, and fixtures.* `wallet/src/bin/wallet.rs` now ships three families of commands:

  * Offline helpers (`generate`, `address`, `tx-craft`, `scan`) that mirror the deterministic witness tooling described in DESIGN.md.
* Wallet management over Substrate RPC (`wallet init`, `wallet substrate-sync`, `wallet substrate-daemon`, `wallet substrate-send`, `wallet status`, `wallet export-viewing-key`). `wallet init` writes an encrypted store (Argon2 + ChaCha20-Poly1305) containing the root secret or an imported viewing key. `wallet substrate-sync` and `wallet substrate-daemon` use WebSocket RPC to fetch commitments/ciphertexts/nullifiers and maintain a local Merkle tree/nullifier set, while `wallet substrate-send` crafts witnesses, proves them locally, and submits a shielded transfer before tracking pending nullifiers.
* Substrate RPC wallet management (`substrate-sync`, `substrate-daemon`, `substrate-send`, `substrate-batch-send` gated behind the `batch-proofs` feature) that use the WebSocket RPC for live wallets. `wallet substrate-send` records outgoing disclosure records inside the encrypted store so on-demand payment proofs can be generated later.
  * Compliance tooling (`payment-proof create`, `payment-proof verify`, `payment-proof purge`) that emits disclosure packages and verifies them against Merkle inclusion plus `hegemon_isValidAnchor` and the chain genesis hash.

JSON fixtures for transaction inputs/recipients still follow the `transaction_circuit` `serde` representation so the witness builder plugs directly into existing proving code. `wallet/tests/cli.rs` exercises the offline commands via `cargo_bin_cmd!`, and `wallet/tests/disclosure_package.rs` covers payment-proof package generation plus tamper rejection without requiring a live node. The disclosure circuit itself is tested under `circuits/disclosure/tests/disclosure.rs`.

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

* Nullifier secret: \(sk_{\text{nf}}\) is a 256-bit integer (derived from `sk_view` with a `view_nf` domain tag in the wallet) and never placed on chain.
* Nullifier key: first map \(sk_{\text{nf}}\) to field elements \(ssk_0, \ldots, ssk_3 \in \mathbb{F}_p\) (four 64-bit chunks), then

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
(pk_enc_i, sk_enc_i) = MLKEM.KeyGen(seed = sk_enc || encode(i))
```

The address \(\text{Addr}_i\) is then

```
Addr_i = Encode(version || crypto_suite || i || pk_recipient_i || pk_enc_i)
```

Today, `version = 2` and `crypto_suite = CRYPTO_SUITE_GAMMA` (ML-KEM-1024).

The wallet stores `sk_spend`, `sk_view`, and either `sk_enc` or all `sk_enc_i` derived on demand.

#### 3.3 Viewing keys

* Incoming Viewing Key (IVK): `ivk = (sk_view, sk_enc)` can recompute all `pk_recipient_i` and `sk_enc_i`, decrypt all notes, and see all incoming funds.
* Full Viewing Key (FVK): `fvk = (sk_view, sk_enc, vk_nf)` where `vk_nf = BLAKE3("view_nf" || sk_view)`.

In the circuit we derive `nk = H_f(domain_nk, ssk_0, \ldots, ssk_3)` from the view-derived nullifier secret, and for viewing we derive `vk_nf` with the `view_nf` domain tag so watch-only wallets can detect spent notes without embedding `sk_spend`.

### 4. Note encryption details

Given recipient \(\text{Addr}_i\) with `(version, crypto_suite, diversifier_index, pk_enc_i, pk_recipient_i)`:

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
2. Submit a batch of disjoint 2→1 consolidation transactions in one round, capped by (a) a maximum transactions-per-round and (b) a conservative on-chain block-size budget.
3. Wait for confirmation, sync, and repeat until the selected notes fit within `MAX_INPUTS`.

This does not change the total number of required consolidation transactions in the worst case (with 2→1 merges it is still `note_count - MAX_INPUTS`), but it reduces wall-clock time by letting miners include multiple independent merges in the same block when space permits. The batch-size budget must stay below the runtime block length (see `runtime/src/lib.rs`).

#### 5.1 Public inputs

The circuit's public inputs (fed into its transcript) are:

* `root_before` - Merkle root anchor encoded as six field elements.
* For each input `i`: `input_active[i] ∈ {0,1}` and `nf_in[i]` is a 6-limb nullifier, with inactive inputs using all-zero limbs.
* For each output `j`: `output_active[j] ∈ {0,1}` and `cm_out[j]` is a 6-limb commitment, with inactive outputs using all-zero limbs.
* `fee_native ∈ F_p` and `value_balance` split into a sign bit plus a 64-bit magnitude so all values fit in one field element.
  In production, `value_balance` is required to be zero because there is no transparent pool.

The transaction envelope also carries `balance_slots` and a `balance_tag`, which are validated outside the STARK for now.
`root_after` and any `txid` binding are handled at the block circuit layer (or a future transaction-circuit revision).

As an additional integrity check outside the STARK, the runtime and wallet compute a 64-byte binding hash over the public inputs:

```
message = anchor || nullifiers || commitments || fee || value_balance
binding_hash = Blake2_256("binding-hash-v1" || 0 || message)
             || Blake2_256("binding-hash-v1" || 1 || message)
```

Verifiers must compare all 64 bytes; this is a defense-in-depth commitment, not a signature.

#### 5.2 Witness (private inputs)

For each input `i`:

* `v_in[i] ∈ [0, 2^64)`
* `a_in[i]` (asset id) as a single 64-bit field element
* `pk_recipient_in[i]` as 4 field elements (32 bytes split into 4 x 64-bit limbs)
* `rho_in[i]` as 4 field elements
* `r_in[i]` as 4 field elements
* Merkle auth path: `sibling_in[i][d]` is a 6-limb node for `d = 0 .. D-1`
* `pos_in[i]` as a 64-bit field element used by the prover to order left/right siblings
* The nullifier secret `sk_nf` (view-derived)

For each output `j`:

* `v_out[j]`
* `a_out[j]` as a single 64-bit field element
* `pk_recipient_out[j]` as 4 field elements
* `rho_out[j]` as 4 field elements
* `r_out[j]` as 4 field elements
* `pos_out[j]` (if the transaction is responsible for tree updates; otherwise position is implicit or handled at block level)

#### 5.3 Constraints: input note verification

For each input `i`:

1. **Recompute commitment and check membership**

   * Compute

   \[
   cm_{\text{in}}[i] = H_f(\text{domain}_{cm}, v_{\text{in}}[i], a_{\text{in}}[i], \text{pk\_recipient}_{\text{in}}[i][0..3], \rho_{\text{in}}[i][0..3], r_{\text{in}}[i][0..3]).
   \]

   * Compute the root via the Merkle path by iterating the sponge with `domain_merkle` using the left/right ordering derived from `pos_in[i]`.
   * Constrain the resulting root to equal `root_before`. (The position bits are not separately constrained in the current AIR.)

2. **Nullifier**

   * Derive the nullifier key once: split `sk_nf` into four field words `ssk_0 .. ssk_3` and compute `nk = H_f(domain_nk, ssk_0, ssk_1, ssk_2, ssk_3)`.
   * For each input note, compute

   \[
   nf_{\text{calc}}[i] = H_f(\text{domain}_{nf}, nk, pos_{\text{in}}[i], \rho_{\text{in}}[i][0..3])
   \]

   and constrain `nf_calc[i] == nf_in[i]`.

#### 5.4 Constraints: output commitments

For each output `j`, enforce

\[
cm_{\text{calc}}[j] = H_f(\text{domain}_{cm}, v_{\text{out}}[j], a_{\text{out}}[j], \text{pk\_recipient}_{\text{out}}[j][0..3], \rho_{\text{out}}[j][0..3], r_{\text{out}}[j][0..3]) = cm_{\text{out}}[j].
\]

#### 5.5 Value range checks

The current transaction circuit enforces value bounds in witness validation: note values are `u64` and must be `<= MAX_NOTE_VALUE`. In-circuit range checks (bit decomposition or lookup gates) are planned for a future circuit version.

#### 5.6 MASP: per-asset balance with a small number of slots

Assume each transaction can involve at most `K` distinct assets (e.g., `K = 4`). Allocate `K` asset slots in the circuit.

Witness for MASP:

* For `k = 0 .. K-1`: `asset_slot[k]` (one 64-bit field element) and running `sum_in[k]`, `sum_out[k]` (field elements representing 64-bit totals).
* For each input note `i`, selector flags `sel_in[i][k] ∈ {0,1}` for each slot.
* For each output note `j`, selector flags `sel_out[j][k] ∈ {0,1}` for each slot.

Constraints:

1. **Selector correctness** - each selector flag is boolean, and the selector sum equals `input_active[i]` / `output_active[j]` so padded notes select no slots.
2. **Asset-id consistency** - enforce that each note's `asset_id` equals the asset stored in its selected slot.
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

The repository now wires this design into executable modules. The `state/merkle` crate implements an append-only `CommitmentTree` that precomputes default subtrees, stores per-level node vectors, and exposes efficient `append`, `extend`, and `authentication_path` helpers. It uses the same Poseidon-style hashing domain as the transaction circuit, ensuring leaf commitments and tree updates are consistent with the ZK statement. `TransactionProof::verify` rejects missing STARK proof bytes/public inputs in production builds. On top of that, the `circuits/block` crate now treats commitment proofs as the default: `CommitmentBlockProver` builds a `CommitmentBlockProof` that commits to transaction proof hashes via a Poseidon sponge, and consensus verifies the commitment proof alongside per-transaction input checks. When a block carries an aggregation proof (via `submit_aggregation_proof`), nodes verify the aggregated recursion proof with explicit public-value binding and skip per-transaction STARK verification; otherwise they fall back to parallel verification of every transaction proof. Recursive epoch proofs remain removed; aggregation proofs are the only recursion path in the live system today.

The commitment proof binds `tx_proofs_commitment` (derived from the ordered list of transaction proof hashes) and proves nullifier uniqueness in-circuit (a permutation check between the transaction-ordered nullifier list and its sorted copy, plus adjacent-inequality constraints). The proof also exposes starting/ending state roots, nullifier root, and DA root as public inputs, but consensus recomputes those values from the block’s transactions and the parent state and rejects any mismatch; this keeps the circuit within a small row budget while preserving full soundness.

Data availability uses a dedicated encoder in `state/da`. The block’s ciphertext blob is serialized as a length-prefixed stream of ciphertexts (ordered by transaction order, then ciphertext order) and erasure-encoded into `k` data shards of size `da_params.chunk_size` plus `p = ceil(k/2)` parity shards. The Merkle root `da_root` commits to all `n = k + p` shards using BLAKE3 with domain tags `da-leaf` and `da-node`. Consensus recomputes `da_root` from the transaction list and rejects any mismatch before verifying proofs. Sampling is per-node randomized: each validator chooses `da_params.sample_count` shard indices, fetches the chunk and Merkle path over P2P, and rejects the block if any sampled proof fails.

`verify_block` expects miners to supply the current tree state. It verifies the commitment proof once via `circuits/block::commitment_verifier::verify_block_commitment`, recomputes the transaction-ordered nullifier list (padding each transaction to `MAX_INPUTS`) to ensure the proof’s public inputs match the block’s transactions, checks the `tx_proofs_commitment` against the transaction list, verifies the aggregation proof if present (or verifies all transaction proofs in parallel when it is not), and updates the tree to the expected ending root. Solo miners follow a simple operational loop: sync the tree, run the block verifier on any candidate they plan to extend, update their local `VersionSchedule`, and only then start hashing on top of the verified root. Mining pauses while the node is catching up to peers so local hashing never races against historical imports. Pools do the same before paying shares or relaying templates so that all PoW-only participants agree on state transitions without any staking-committee style coordination. This provides a concrete path from transaction proofs to a block-level proof artifact that consensus can check without per-transaction recursion.

Define a block commitment circuit `C_commitment` with

* Public inputs: `tx_proofs_commitment`, `root_prev`, `root_new`, `nullifier_root`, `da_root`, `tx_count`, plus the transaction-ordered nullifier list and its sorted copy (both length `tx_count * MAX_INPUTS`). For Plonky3, the permutation challenges `(alpha, beta)` are included as public inputs derived from a Blake3 hash of the same inputs, and verifiers recompute them off-circuit to avoid embedding Blake3 inside the AIR.
* Witness: the `tx_proof_hashes` and the nullifier columns (unsorted + sorted lists).

Constraints in `C_commitment`:

1. **Commit to proof hashes** – absorb proof-hash limbs into a Poseidon sponge and enforce the 6-limb commitment equals `tx_proofs_commitment`.
2. **Check nullifier uniqueness** – enforce a permutation check between the transaction-ordered nullifier list and its sorted copy, then require no adjacent equals in the sorted list (skipping zero padding).
3. **Expose roots and DA** – carry `root_prev`, `root_new`, `nullifier_root`, and `da_root` as public inputs so consensus can recompute them from the block’s transactions and parent state and reject mismatches.

This yields a per-block proof `π_block` showing that the miner committed to the exact list of transaction proof hashes and that the padded nullifier multiset is unique, while leaving deterministic state transitions (commitment tree updates and DA root reconstruction) to consensus checks outside the circuit.

#### 6.4 Circuit versioning

If you introduce a new transaction circuit version, update `C_block` so its verification step accepts both old and new proofs. After some time, consensus can reject new transactions with old-version proofs, but `C_block` retains backward verification code as long as necessary (or you drop it when you no longer need to accept old blocks).

#### 6.5 Epoch proof hashes (removed)

Recursive epoch proofs were removed alongside the previous recursion stack. Reintroducing them requires a Plonky3-native recursion design; until then, there are no epoch proof hashes in the live system.

#### 6.6 Settlement batch proofs

Settlement batch proofs bind instruction IDs and nullifiers into a Poseidon2-based commitment. The public inputs are the instruction count, nullifier count, the padded instruction ID list (length `MAX_INSTRUCTIONS`), the padded nullifier list (length `MAX_NULLIFIERS`), and the commitment itself. The commitment is computed by absorbing input pairs into a Poseidon2 sponge initialized as `[domain_tag, 0, 1]`, adding each pair to the first two state elements, running the full-round permutation per absorb cycle, and repeating for the full padded input list. Nullifiers are Poseidon2-derived from `(instruction_id, index)` under a distinct domain tag, then encoded as 48 bytes with six big-endian limbs; canonical encodings reject any limb \(\ge p\). Settlement verification rejects non-canonical encodings and uses the on-chain `StarkVerifierParams` (Poseidon2-384, 43 FRI queries, 16x blowup) to select acceptable proof options.


---

## 7. Post-quantum crypto module (reference implementations)

The `crypto/` crate provides deterministic reference bindings for the PQ primitives referenced throughout the design. All APIs live in safe Rust and use fixed-length byte arrays so that serialization matches the NIST ML-DSA, SLH-DSA, and ML-KEM parameter sizes without pulling in the full reference C code.

Module layout:

* `crypto::ml_dsa` – exposes `MlDsaSecretKey`, `MlDsaPublicKey`, and `MlDsaSignature` with `SigningKey`/`VerifyKey` trait implementations. Secret keys derive public keys by hashing with domain tag `ml-dsa-pk`, and signatures deterministically expand `ml-dsa-signature || pk || message` to 3293 bytes.
* `crypto::slh_dsa` – mirrors the ML-DSA interface but with SLH-DSA key lengths (32 B public, 64 B secret, 17088 B signatures).
* `crypto::ml_kem` – wraps Kyber-like encapsulation with `MlKemKeyPair`, `MlKemPublicKey`, and `MlKemCiphertext`. Encapsulation uses a seed to deterministically derive ciphertexts and shared secrets, while decapsulation recomputes the shared secret from stored public bytes.
* `crypto::hashes` – contains `sha256`, `sha3_256`, `blake3_256`, `blake3_384`, a Poseidon-style permutation over the Goldilocks prime (width 3, 63 full rounds, NUMS constants), and helpers `commit_note`, `derive_prf_key`, and `derive_nullifier` (defaulting to 48-byte BLAKE3-384 with SHA3-384 fallbacks via `commit_note_with`) that apply the design’s domain tags (`"c"`, `"nk"`, `"nf"`). PQ address hashes remain BLAKE3-256 by default while commitments/nullifiers normalize on 48-byte digests.
* `pallet_identity` – stores optional PQ session keys as `SessionKey::PostQuantum` (Dilithium/Falcon). New registrations supply PQ bundles through the `register_did` call without a one-off rotate extrinsic.
* `pallet_attestations` / `pallet_settlement` – persist `StarkVerifierParams` in storage with governance-controlled setters and runtime-upgrade initialization so on-chain STARK verification remains aligned with PQ hash choices. The runtime seeds attestations with Poseidon2-384 hashing, 43 FRI queries, a 16x blowup factor, and quadratic extension over Goldilocks; settlement uses the same hash/query budget. With 384-bit digests, PQ collision resistance reaches ~128 bits. Governance can migrate to new parameters via the `set_verifier_params` call without redeploying code.

The crate’s `tests/crypto_vectors.rs` fixture loads `tests/vectors.json` to assert byte-for-byte deterministic vectors covering:

* key generation and signing for ML-DSA and SLH-DSA,
* ML-KEM key generation, encapsulation, and decapsulation,
* hash-based commitment, PRF key derivation, nullifier derivation, SHA-256, BLAKE3, and Poseidon outputs.

Run `cargo test` from the `crypto/` directory to regenerate and validate all vectors.

## 6. Monorepo workflows and CI hooks

Implementation hygiene now mirrors the layout introduced in `DESIGN.md §6` and the documentation hub under `docs/`.

### Required commands before every PR

1. **Rust formatting and linting** – `cargo fmt --all` then `cargo clippy --workspace --all-targets --all-features -D warnings`.
2. **Workspace tests** – `cargo test --workspace` ensures crypto, circuits, consensus, wallet, and protocol crates are still coherent.
3. **Targeted checks**:
   - `cargo test -p synthetic-crypto` for deterministic PQ primitive vectors.
   - `cargo test -p transaction-circuit && cargo test -p block-circuit` for circuit constraints.
   - `cargo test -p wallet` for CLI/integration fixtures.
4. **Benchmarks (smoke mode)**:
   - `cargo run -p circuits-bench -- --smoke --prove --json` – validates witness → proof → block aggregation loop.
   - `cargo run -p wallet-bench -- --smoke --json` – stresses key derivation, encryption, and nullifier derivations.
   - `(cd consensus/bench && go test ./... && go run ./cmd/netbench --smoke --json)` – ensures the Go simulator compiles/tests while reporting PQ throughput budgets.
5. **Security harnesses** – run the adversarial property tests locally before pushing:
   - `PROPTEST_MAX_CASES=64 cargo test -p transaction-circuit --test security_fuzz` (transaction witness invariants).
   - `PROPTEST_MAX_CASES=64 cargo test -p network --test adversarial` (handshake tampering).
   - `PROPTEST_MAX_CASES=64 cargo test -p wallet --test address_fuzz` (address encode/decode mutations).
   - `cargo test tests::security_pipeline` (root-level cross-component simulation).

Document benchmark outputs in pull requests when they change noticeably; CI will surface them via the `benchmarks` job but reviewers rely on human summaries for regressions.

### CI job map (`.github/workflows/ci.yml`)

| Job | Purpose |
| --- | --- |
| `rust-lints` | Runs fmt + clippy on the entire workspace. |
| `rust-tests` | Executes `cargo test --workspace`. |
| `crypto-tests` | Locks in ML-DSA/ML-KEM behavior with focused tests. |
| `circuits-proof` | Runs the transaction/block tests and ensures `circuits-bench --smoke --prove` succeeds. |
| `wallet` | Runs wallet tests and the wallet benchmark smoke profile. |
| `go-net` | Runs `go test ./...` and the `netbench` simulator. |
| `cpp-style` | Applies `clang-format --dry-run` if any `*.cpp`/`*.h` files exist (no-op otherwise). |
| `benchmarks` | Executes all smoke benchmarks with `continue-on-error: true` so regressions surface as warnings. |
| `security-adversarial` | Runs the property-based harnesses for transaction witnesses, network handshakes, wallet addresses, and the root `tests/security_pipeline.rs` flow. |

All jobs operate on Ubuntu runners with Rust stable, Go 1.21, and clang-format installed via `apt`. Adding new languages or toolchains requires updating this table, the workflow, and `docs/CONTRIBUTING.md`.

## 7. Node, wallet, and UI operations

Follow [runbooks/miner_wallet_quickstart.md](runbooks/miner_wallet_quickstart.md) whenever you need a reproducible demo:

1. Launch the Substrate-based `hegemon-node` binary with `HEGEMON_MINE=1` and `--dev` for fast block times. The node exposes JSON-RPC on port 9944 and P2P on port 30333 by default. Run `make node` to build.
2. Connect the desktop app or Polkadot.js Apps to the node RPC endpoint to view live telemetry. When using the desktop app, prefer a persistent base path (avoid `--tmp`), and set `--listen-addr /ip4/0.0.0.0/tcp/30333` only when you intend to accept IPv4 peer traffic. Expose RPC externally only on trusted networks.
   The desktop app is organized into Overview, Node, Wallet, Send, Disclosure, and Console workspaces. Its global status bar always shows the active node, wallet store, and genesis hash so operators can detect mismatches before sending or mining.
3. For multi-node setups, start additional nodes with `--bootnodes /ip4/127.0.0.1/tcp/30333` pointing to the first node.

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
