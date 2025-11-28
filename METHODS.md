## 1. What a “shielded spend” proves (ZK statement)

We’ll design a *single* canonical shielded pool, with a fixed “join–split” circuit used for all transactions.

Say each transaction supports up to:

* `M` inputs (old notes),
* `N` outputs (new notes),

per proof. Think Sapling/Orchard style: fixed `M, N` for the base circuit, recursion if you need more.

### 1.1 Data model

A **note** is conceptually:

* `value` – integer (e.g. 64‑bit, or 128‑bit if you’re paranoid)
* `asset_id` – 256‑bit label; `0` = native coin (ZEC‑like)
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
>   * `sk_spend` (or a per‑address derived secret)
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

Consensus stitches this MASP output into PoW validation by requiring a coinbase commitment on every block. The `ConsensusBlock`
type now carries `CoinbaseData` that either references a concrete transaction (by index) or supplies an explicit `balance_tag`.
Miners populate `CoinbaseData` with the minted amount, collected fees, and any explicit burns, and full nodes recompute the
running `supply_digest = parent_digest + minted + fees − burns`. If the coinbase is missing, points at an invalid transaction,
or mints more than the scheduled subsidy `R(height)` (50 · 10⁸ base units halving every 840k blocks), the block is rejected
before the fork-choice comparison runs. This keeps the STARK circuit, MASP accounting, and the PoW header’s supply digest in
lockstep.

Substrate nodes wire the same enforcement path into block import. `consensus::substrate::import_pow_block` wraps the `PowConsensus`
state machine with a Substrate-friendly `BlockOrigin` tag and returns an `ImportReceipt` that records the validated proof
commitment, version commitment, and fork-choice result. Node services call this helper inside their block intake path so the
version-commitment and STARK commitment checks run during import (not after the fact), and `/consensus/status` mirrors the latest
receipt alongside miner telemetry to keep the Go benchmarking harness under `consensus/bench` in sync with runtime behavior.

---

## 3. The STARK arithmetization

We don’t need to pick a specific scheme (Plonky2/Winterfell/etc.), but we do need the rough structure.

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

  * `sk_spend` used *only inside the STARK* to derive nullifier keys.
* **Viewing key material**:

  * `vk_full = (sk_view, sk_enc, public_params…)`
* **Incoming‑only viewing key**:

  * `vk_incoming = (sk_enc, some public tag)`
    (can scan chain and decrypt incoming notes, but can’t produce spends or see nullifiers.)

### 4.2 Nullifier key

Inside proofs we don’t want to expose `sk_spend` or `nk`, but we need a deterministic nullifier.

Define:

```text
nk = Hf("nk" || sk_spend)
nf = Hf("nf" || nk || rho || pos)
```

Only someone knowing `sk_spend` can compute `nf` for a given `(rho, pos)`; the STARK proves consistency.

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
addr_d = EncAddr(version || d || pk_enc(d) || addr_tag(d))
```

where `addr_tag(d)` is a public tag used to help scanning (see below).

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
   * an *optional* short **hint tag** `t` to speed up scanning:

     ```text
     t = Hg("hint" || Hf(d || some randomness))
     ```

   (Hint tags are a place where you can get fancy; simplest is “none”: just brute‑force all notes.)

**Scanning with incoming viewing key:**

A wallet with `vk_incoming`:

* Knows `sk_derive`, so can recompute each `sk_enc(d)` and `pk_enc(d)` for its diversified addresses.
* For each new note on chain:

  * Option A (simple / expensive): try decapsulation with every `sk_enc(d)` you care about; if decap succeeds and the AEAD tag verifies, it’s yours.
  * Option B (with hint tags): interpret `t` as a small filter that lets you narrow the set of candidate `d` for which you bother trying KEM decaps.

Given that ML‑KEM decapsulation is not *that* expensive and users don’t have thousands of addresses typically, Option A is acceptable in v1. The scanning cost is similar order of magnitude to Sapling’s trial decryption.

**Full viewing key** `vk_full`:

* Contains everything in `vk_incoming`, plus:

  * enough info to recompute nullifiers (`nk` or a view‑equivalent),
  * so it can see which of “its” notes have been spent.

You can decide whether you want nullifier computation to be *derivable* from viewing keys (like Sapling’s full viewing key) or strictly tied to `sk_spend`. Both are possible:

* If you want watch‑only wallets to see spent status, you derive a “viewing nullifier key” `vnk` from `sk_view` that mirrors `nk` but cannot be used to spend.
* If you want stricter separation, only `sk_spend` can compute nullifiers, and watch‑only wallets infer spentness by tracking spends by inference (less robust).

### 4.5 Implementation details

*Key derivations and addresses.* `wallet/src/keys.rs` implements `RootSecret::derive()` using the domain-separated label `wallet-hkdf` and SHA-256 to expand `(label || sk_root)` into the 32-byte subkeys for spend/view/enc/diversifier. `AddressKeyMaterial` then uses `addr-seed` and `addr-tag` labels to deterministically derive the ML-KEM key pair and 32-byte hint tag for each diversifier index. `wallet/src/address.rs` serializes `(version, index, pk_recipient, pk_enc, hint_tag)` as a Bech32m string (HRP `shca`) so senders can round-trip addresses through QR codes or the CLI.

*Note encryption.* `wallet/src/notes.rs` consumes the recipient’s Bech32 data, runs ML-KEM encapsulation with a random seed, and stretches the shared secret into two ChaCha20-Poly1305 keys via `expand_to_length("wallet-aead", shared_secret || label, 44)`. The first 32 bytes drive the AEAD key and the final 12 bytes form the nonce so both note payload and memo use disjoint key/nonce pairs. Ciphertexts record the diversifier index, hint tag, and ML-KEM ciphertext so incoming viewing keys can reconstruct the exact `AddressKeyMaterial` needed for decryption.

*Viewing keys and nullifiers.* `wallet/src/viewing.rs` defines `IncomingViewingKey` (scan + decrypt), `OutgoingViewingKey` (derive address tags/pk_recipient for audit), and `FullViewingKey` (incoming + nullifier key). Full viewing keys store the SHA-256 nullifier PRF output derived from `sk_spend`, letting watch-only tooling compute chain nullifiers without exposing the spend key itself. `RecoveredNote::to_input_witness` converts decrypted notes into `transaction_circuit::note::InputNoteWitness` values by reusing the same `NoteData` and taking the best-effort `rho_seed = rho` placeholder until the circuit’s derivation is finalized.

*CLI, daemon, and fixtures.* `wallet/src/bin/wallet.rs` now ships two families of commands:

  * Offline helpers (`generate`, `address`, `tx-craft`, `scan`) that mirror the deterministic witness tooling described in DESIGN.md.
  * RPC-backed wallet management (`init`, `sync`, `daemon`, `status`, `send`, `export-viewing-key`). `wallet init` writes an encrypted store (Argon2 + ChaCha20-Poly1305) containing the root secret or an imported viewing key. `wallet sync` and `wallet daemon` talk to `/wallet/{commitments,ciphertexts,nullifiers}` plus `/wallet/notes` and `/blocks/latest` to maintain a local Merkle tree/nullifier set, while `wallet send` crafts witnesses, proves them locally, and submits a `TransactionBundle` to `/transactions` before tracking the pending nullifiers.

JSON fixtures for transaction inputs/recipients still follow the `transaction_circuit` `serde` representation so the witness builder plugs directly into existing proving code. `wallet/tests/cli.rs` exercises the offline commands via `cargo_bin_cmd!`, while `wallet/tests/rpc_flow.rs` spins up a lightweight test node, runs two wallet stores (one full, one watch-only), and asserts end-to-end send/receive plus nullifier tracking.

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
* `circuits/block` accepts a `HashMap<VersionBinding, VerifyingKey>`, folds `(circuit_version, crypto_suite)` into the recursive digest, and records per-version counts so consensus can hash them into the header’s `version_commitment`.
* `consensus::version_policy::VersionSchedule` stores ZIP-style `VersionProposal`s (activation height, optional retirement, optional `UpgradeDirective` that points at the special migration circuit binding). Both BFT and PoW consensus paths call `schedule.first_unsupported(...)` and surface `ConsensusError::UnsupportedVersion` if a block contains an unscheduled binding.
* Governance documentation (`governance/VERSIONING.md`) specifies how to draft a proposal, vote on it, and publish the activation window, while the operational runbook (`runbooks/emergency_version_swap.md`) walks operators through emergency swaps: announce the swap, enable the upgrade circuit, watch `version_counts` to ensure old notes migrate, then retire the deprecated binding at the scheduled height.

### 5.2 Algorithm agility

Keys include algorithm identifiers:

* For KEM: `kem_id` ∈ {ML‑KEM‑768, ML‑KEM‑v2, …}
* For signatures: `sig_id` ∈ {ML‑DSA‑65xx, SLH‑DSA‑1xx, …}

Addresses encode these IDs. The join–split circuit doesn’t care; it just treats `asset_id` and `pk_recipient` as opaque bytes. Only the *note encryption/decryption* layer and wallet code depend on the KEM.

On algorithm deprecation:

* Consensus can forbid new transactions with, say, `kem_id = ML‑KEM‑768` after block X, but still allow spends of existing notes for some grace period.
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

Define a Poseidon-like permutation \(P: \mathbb{F}_p^t \to \mathbb{F}_p^t\):

* Width \(t = 12\) so we can absorb multiple words at once.
* Round constants and MDS matrix chosen per the standard Poseidon recipe for this field.
* Rounds: for example, \(R_F = 8\) full and \(R_P = 56\) partial (numbers can be tuned; assume we choose something with at least a 128-bit post-quantum security margin).

We derive a field hash by sponge:

\[
H_f(x_0, \ldots, x_{k-1}) = \operatorname{Sponge}(P, \text{capacity}=4, \text{rate}=8, x_0, \ldots, x_{k-1})
\]

The output is one field element (the first state word).

Outside the circuit (for block headers, addresses, etc.) we can still use standard SHA-256 as a byte-oriented hash. Inside, we stick to \(H_f\).

#### 1.3 Merkle tree

* Each leaf: one field element \(cm \in \mathbb{F}_p\).
* Parent hash: for children \(L, R \in \mathbb{F}_p\),

\[
\text{parent} = H_f(\text{domain}_{\text{merkle}}, L, R)
\]

where \(\text{domain}_{\text{merkle}}\) is a fixed field element.

* Tree depth: say 32 or 40 (gives capacity for \(2^{32}\)–\(2^{40}\) notes; you can always roll a new tree later via a transition proof).

#### 1.4 PQC choices

To have something specific in mind:

* KEM: ML-KEM-768 (Kyber-768 equivalent) with \(|pk| \approx 1184\) bytes, \(|ct| \approx 1088\) bytes, 192-bit classical and roughly 96-bit post-quantum security.
* Signature: ML-DSA-65xx (Dilithium-level) or category-3 equivalent with approximately 2–3 KB signatures and 1–2 KB public keys. Runtime extrinsics and PoW seals reuse this scheme through `runtime::PqSignature`/`PqPublic`, hashing PQ public keys with BLAKE2 into SS58-prefix-42 AccountId32 values so address encoding stays stable while signatures grow.

We do not need signatures inside the shielded circuit, only for block authentication and possibly transaction-level authentication.

### 2. Object definitions (bits, fields, encodings)

#### 2.1 Value and asset ID

* \(v\): 64-bit unsigned integer, value of note.
* Encoded into one field element \(v \in \mathbb{F}_p\) via the natural embedding (\(0 \le v < 2^{64} \subset \mathbb{F}_p\)).
* \(a\): 256-bit asset ID (for MASP) represented as four field elements \(a_0, a_1, a_2, a_3 \in \mathbb{F}_p\), each encoding 64 bits of the asset ID.

#### 2.2 Address tag and randomness

* \(\text{addr\_tag}\): 256-bit tag derived from the recipient’s view key and diversifier index, represented as four field elements \(t_0, t_1, t_2, t_3\).
* \(\rho\): 256-bit per-note secret, represented as four field elements \(\rho_0, \rho_1, \rho_2, \rho_3\).
* \(r\): 256-bit blinding, represented as four field elements \(r_0, r_1, r_2, r_3\).

#### 2.3 Note commitment

Take the 1-word capacity / 8-word rate sponge and define

\[
\begin{aligned}
cm = H_f(&\text{domain}_{cm},
    v, \\
    &a_0, a_1, a_2, a_3, \\
    &t_0, t_1, t_2, t_3, \\
    &\rho_0, \rho_1, \rho_2, \rho_3, \\
    &r_0, r_1, r_2, r_3)
\end{aligned}
\]

Inputs are a sequence of field elements. \(\text{domain}_{cm}\) is a constant field element. On chain, the note commitment tree leaf is exactly \(cm\).

#### 2.4 Nullifier

* Spend secret: \(sk_{\text{spend}}\) is a 256-bit integer, but never placed on chain.
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

This \(nf \in \mathbb{F}_p\) is the on-chain nullifier.

### 3. Key / address hierarchy with ML-KEM

#### 3.1 Seed and derivations

Let `seed` be a 256-bit root (e.g., from BIP-39). Derive

```
sk_spend = SHA256("spend" || seed)
sk_view  = SHA256("view"  || seed)
sk_enc   = SHA256("enc"   || seed)
```

To get deterministic KEM keypairs, use `sk_enc` as the seed to the KEM keygen’s RNG. In practice:

```
(pk_enc, sk_enc_KEM) = MLKEM.KeyGen(seed = sk_enc || "0")
```

#### 3.2 Diversified addresses

To get multiple addresses from one wallet, for diversifier index \(i \in \{0, \ldots, 2^{32}-1\}\):

```
div_i      = SHA256("div" || sk_view || i)   // 256 bits
addr_tag_i = div_i                            // 256 bits, used directly
(pk_enc_i, sk_enc_i) = MLKEM.KeyGen(seed = sk_enc || encode(i))
```

The address \(\text{Addr}_i\) is then

```
Addr_i = Encode(version || i || pk_enc_i || addr_tag_i)
```

The wallet stores `sk_spend`, `sk_view`, and either `sk_enc` or all `sk_enc_i` derived on demand.

#### 3.3 Viewing keys

* Incoming Viewing Key (IVK): `ivk = (sk_view, sk_enc)` can recompute all `addr_tag_i` and `sk_enc_i`, decrypt all notes, and see all incoming funds.
* Full Viewing Key (FVK): `fvk = (sk_view, sk_enc, vk_nf)` where `vk_nf = SHA256("view_nf" || sk_spend)`.

In the circuit we derive `nk = H_f(domain_nk, ssk_0, \ldots, ssk_3)`, but for viewing we derive a view-only nullifier key `vk_nf` outside the circuit that allows watch-only wallets to detect nullifiers corresponding to their notes but not to spend. You can tune whether `vk_nf` equals `nk` or is a one-way function of it, depending on how tightly you want to tie full viewing to spending.

### 4. Note encryption details

Given recipient \(\text{Addr}_i\) with `(pk_enc_i, addr_tag_i)`:

#### 4.1 Plaintext

Plaintext structure:

```
note_plain = (
  v:      uint64,
  a:      32 bytes,
  rho:    32 bytes,
  r:      32 bytes,
  addr_i: 32-bit index i,
  tag:    32 bytes (addr_tag_i),
  maybe extra fields (memo pointer, etc.)
)
```

#### 4.2 KEM + AEAD

Sender:

1. `(ct_kem, ss) = MLKEM.Encaps(pk_enc_i)`
2. `k = HKDF(ss, info = "note_enc" || txid || output_index)`
3. `ct_aead = AEAD_Enc(k, nonce, note_plain, ad = txid || output_index)`

On chain per output:

* `cm ∈ F_p`
* `ct_kem` (≈1.1 KB)
* `ct_aead` (|note_plain| + tag, say ≈100 bytes)
* Optional small `scan_tag` if you want faster scanning.

Recipient with IVK/FVK:

* Recomputes all `sk_enc_i` and `pk_enc_i`.
* For each output:
  * Try `MLKEM.Decaps(sk_enc_i, ct_kem)` → either fail or give `ss`.
  * Derive `k`, attempt AEAD decrypt.
  * If AEAD succeeds, this note belongs to address `i`.

### 5. Main “join–split” circuit in detail

Assume the base circuit handles up to `M` inputs (e.g., 4) and `N` outputs (e.g., 4). Per transaction, you produce one STARK proof for these `M + N` notes.

#### 5.1 Public inputs

The circuit’s public inputs (fed into its transcript) are:

* `root_before ∈ F_p` – Merkle root at which inputs are valid.
* `root_after ∈ F_p` – Merkle root after adding outputs and any other block-level updates if handled here.
* For each input `i`: `nf_in[i] ∈ F_p`.
* For each output `j`: `cm_out[j] ∈ F_p`.
* For each asset slot `k` (see MASP below): `Δ_native` or some balance tag (optional; could all be enforced privately).
* A domain-separated commitment to transaction metadata (`txid`) to tie the proof to that transaction.

#### 5.2 Witness (private inputs)

For each input `i`:

* `v_in[i] ∈ [0, 2^64)`
* `a_in[i]` (asset id) as 4 field elements
* `addr_tag_in[i]` as 4 field elements
* `rho_in[i]` as 4 field elements
* `r_in[i]` as 4 field elements
* Merkle auth path: `sibling_in[i][d] ∈ F_p` and `bit_in[i][d] ∈ {0,1}` for `d = 0 .. D-1`
* `pos_in[i]` as a field element (or bit decomposition)
* The global spend secret `sk_spend`

For each output `j`:

* `v_out[j]`
* `a_out[j]`
* `addr_tag_out[j]`
* `rho_out[j]`
* `r_out[j]`
* `pos_out[j]` (if the transaction is responsible for tree updates; otherwise position is implicit or handled at block level)

#### 5.3 Constraints: input note verification

For each input `i`:

1. **Recompute commitment and check membership**

   * Compute

   \[
   cm_{\text{in}}[i] = H_f(\text{domain}_{cm}, v_{\text{in}}[i], a_{\text{in}}[i][0..3], \text{addr\_tag}_{\text{in}}[i][0..3], \rho_{\text{in}}[i][0..3], r_{\text{in}}[i][0..3]).
   \]

   * Compute the root via the Merkle path by iterating the sponge with `domain_merkle` and enforcing boolean constraints on each `bit_in[i][d]`.
   * Constrain the resulting root to equal `root_before`.

2. **Nullifier**

   * Derive the nullifier key once: split `sk_spend` into four field words `ssk_0 .. ssk_3` and compute `nk = H_f(domain_nk, ssk_0, ssk_1, ssk_2, ssk_3)`.
   * For each input note, compute

   \[
   nf_{\text{calc}}[i] = H_f(\text{domain}_{nf}, nk, pos_{\text{in}}[i], \rho_{\text{in}}[i][0..3])
   \]

   and constrain `nf_calc[i] == nf_in[i]`.

#### 5.4 Constraints: output commitments

For each output `j`, enforce

\[
cm_{\text{calc}}[j] = H_f(\text{domain}_{cm}, v_{\text{out}}[j], a_{\text{out}}[j][0..3], \text{addr\_tag}_{\text{out}}[j][0..3], \rho_{\text{out}}[j][0..3], r_{\text{out}}[j][0..3]) = cm_{\text{out}}[j].
\]

#### 5.5 Value range checks

For any value `v` (input or output), decompose into 64 bits with boolean constraints `b_k (b_k - 1) = 0` for `k = 0 .. 63` and reconstruct `v = Σ b_k 2^k`. Use PLONK range gates or a custom bit-packing gate to reduce cost.

#### 5.6 MASP: per-asset balance with a small number of slots

Assume each transaction can involve at most `K` distinct assets (e.g., `K = 4`). Allocate `K` asset slots in the circuit.

Witness for MASP:

* For `k = 0 .. K-1`: `asset_slot[k]` (4 field words of a 256-bit asset id) and `sum_in[k]`, `sum_out[k]` (field elements representing 64-bit totals).
* For each input note `i`, a slot index `slot_i ∈ {0 .. K-1}`.
* For each output note `j`, a slot index `slot'_j ∈ {0 .. K-1}`.

Constraints:

1. **Slot index correctness** – represent each `slot_i` as boolean bits and constrain membership in `{0 .. K-1}`; same for `slot'_j`.
2. **Asset-id consistency** – enforce that each note’s `asset_id` equals the asset stored in its assigned slot.
3. **Summation** – accumulate `sum_in` and `sum_out` per slot via chained additions.
4. **Conservation per slot** – enforce `net_k = sum_in[k] - sum_out[k]`. For the native asset slot (say slot 0 with `asset_id = 0…0`), constrain `net_0` to equal `fee_native + issuance_native` (public inputs or constants). For other slots, constrain `net_k = 0`. Optionally require sorted, duplicate-free asset slots for canonicalization.

This MASP approach is cheaper than sorting an arbitrary `(asset_id, delta)` multiset but restricts how many assets can appear in one transaction.

### 6. Tree evolution and block-level recursion

To avoid putting Merkle tree updates in every transaction circuit, handle them at the block level.

#### 6.1 Per-transaction proof

The transaction proof shows:

* Inputs are members of `root_before`.
* Commitments `cm_out` are well formed.
* Nullifiers `nf_in` are correctly derived.
* Value balance per asset holds.

It does not assert anything about `root_after`.

#### 6.2 Block state

The node maintains a canonical commitment tree with current root `root_state`. A block contains a list of transactions `T_1 .. T_m` and for each transaction a public `root_before` that must equal the block’s running root when that transaction is applied in order.

#### 6.3 Block circuit and proof

The repository now wires this design into executable modules. The `state/merkle` crate implements an append-only `CommitmentTree` that precomputes default subtrees, stores per-level node vectors, and exposes efficient `append`, `extend`, and `authentication_path` helpers. It uses the same poseidon-style `Felt` hashing domain as the transaction circuit, ensuring leaf commitments and tree updates are consistent with the ZK statement. On top of that, the `circuits/block` crate processes sequences of `TransactionProof`s. Its `prove_block` entry point re-verifies each transaction against the transaction verifying key, checks that each proof’s published `merkle_root` matches the running tree root, rejects repeated nullifiers by inserting their `as_int()` encodings into a set, appends every non-zero commitment through the `CommitmentTree`, and records the intermediate root trace. It also collapses each transaction’s public inputs, nullifiers, commitments, and native fee into a folded hash recorded as `RecursiveAggregation`, giving consensus a succinct digest of the block contents until full recursive proof composition lands. Mining nodes invoke `prove_block` immediately before attempting a PoW solution so the resulting header already carries the recursive digest and `version_commitment` they derived from their private tree state; no staking committee or delegated quorum is required.

`verify_block` expects miners to supply the current tree state. It replays the same verification and append logic, recomputes the aggregation digest, and only mutates local state when the recomputed root trace and digest match the prover’s output. Solo miners follow a simple operational loop: sync the tree, run `verify_block` on any candidate they plan to extend, update their local `VersionSchedule`, and only then start hashing on top of the verified root. Pools do the same before paying shares or relaying templates so that all PoW-only participants agree on state transitions without any staking-committee style coordination. This provides a concrete path from transaction proofs to a block-level proof artifact that consensus can check in one step.

Define a second circuit `C_block` with

* Public inputs: `root_prev` (root at start of block), `root_new` (root after applying all transactions), and a list or hash of all transaction identifiers and their `nf_in`, `cm_out`, and `root_before` values to tie things together.
* Witness: the sequence of changes to the commitment tree (indices and sibling hashes) and the transaction-level proofs `π_tx` or their verification data.

Constraints in `C_block`:

1. **Verify each transaction proof** – for each transaction `T_i`, feed its public inputs to the embedded STARK verifier and constrain the verifier’s accept flag to 1 (using recursive STARK techniques).
2. **Reproduce tree evolution** – start with `root = root_prev` and iteratively insert each `cm_out[j]` at the next available leaf position (or a consensus-defined position), recomputing the root with `H_f`. After all insertions, enforce that the final root equals `root_new`.
3. **Check transaction ordering** – enforce `root_before[i]` matches the running root before applying `T_i`.

This yields a per-block proof `π_block` showing every transaction adheres to the join–split semantics and that the global note tree root evolves correctly from `root_prev` to `root_new`. Nodes can verify `π_block` once to accept the block or verify transaction proofs individually and recompute the tree themselves.

#### 6.4 Circuit versioning

If you introduce a new transaction circuit version, update `C_block` so its verification step accepts both old and new proofs. After some time, consensus can reject new transactions with old-version proofs, but `C_block` retains backward verification code as long as necessary (or you drop it when you no longer need to accept old blocks).


---

## 7. Post-quantum crypto module (reference implementations)

The `crypto/` crate provides deterministic reference bindings for the PQ primitives referenced throughout the design. All APIs live in safe Rust and use fixed-length byte arrays so that serialization matches the NIST ML-DSA, SLH-DSA, and ML-KEM parameter sizes without pulling in the full reference C code.

Module layout:

* `crypto::ml_dsa` – exposes `MlDsaSecretKey`, `MlDsaPublicKey`, and `MlDsaSignature` with `SigningKey`/`VerifyKey` trait implementations. Secret keys derive public keys by hashing with domain tag `ml-dsa-pk`, and signatures deterministically expand `ml-dsa-signature || pk || message` to 3293 bytes.
* `crypto::slh_dsa` – mirrors the ML-DSA interface but with SLH-DSA key lengths (32 B public, 64 B secret, 17088 B signatures).
* `crypto::ml_kem` – wraps Kyber-like encapsulation with `MlKemKeyPair`, `MlKemPublicKey`, and `MlKemCiphertext`. Encapsulation uses a seed to deterministically derive ciphertexts and shared secrets, while decapsulation recomputes the shared secret from stored public bytes.
* `crypto::hashes` – contains `sha256`, `sha3_256`, `blake3_256`, a Poseidon-style permutation over the Goldilocks prime, and helpers `commit_note`, `derive_prf_key`, and `derive_nullifier` (defaulting to BLAKE3 with SHA3 fallbacks) that apply the design’s domain tags (`"c"`, `"nk"`, `"nf"`). PQ address and note hashes now normalize on BLAKE3-256 by default while keeping SHA3-256 as an opt-in override for circuits that still expect it.
* `pallet_identity` – stores session keys as a `SessionKey` enum (legacy AuthorityId or PQ-only Dilithium/Falcon). The runtime migration wraps any pre-upgrade `AuthorityId` into `SessionKey::Legacy` so existing operators inherit their keys; new registrations can supply PQ-only bundles through the same `register_did` call without a one-off rotate extrinsic.
* `pallet_attestations` / `pallet_settlement` – persist `StarkVerifierParams` in storage with governance-controlled setters and runtime-upgrade initialization so on-chain STARK verification remains aligned with PQ hash choices. The runtime seeds both pallets with Blake3 hashing, 28 FRI queries, a 4× blowup factor, and 128-bit security, and governance can migrate to new parameters via the `set_verifier_params` call without redeploying code.

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
   - `cargo test -p wallet --test rpc_flow` spins up the lightweight test node and runs the RPC-driven send/receive/nullifier flow between a full wallet and a watch-only wallet.
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

## 6. Node, wallet, and UI operations

Follow [runbooks/miner_wallet_quickstart.md](runbooks/miner_wallet_quickstart.md) whenever you need a reproducible two-party demo:

1. Launch two `hegemon` binaries with dedicated API ports and `pow_bits = 0x3f00ffff` so the embedded miners immediately grind blocks. Every PoW header must carry the seal (no “empty” difficulty), and timestamps must pass both the 11-block median-time-past check and the `+90s` future-skew clamp before a candidate is accepted. The reward schedule in `consensus/src/reward.rs` (`INITIAL_SUBSIDY = 50 · 10⁸`, halving every `210_000` blocks; block 0 mints 0) plus the 128-bit `supply_digest = parent + minted + fees − burns` accumulator give you the guard rails to check `/blocks/latest` against. Difficulty retargets every 120 blocks using the clamped timespan (×¼…×4) so reorgs cannot skew `pow_bits` away from the deterministic schedule.
2. Serve the embedded dashboard directly from the node (`hegemon start` already mounts the assets at the API address). `/wallet` exposes shielded balances, committed notes, and transaction history; `/network` charts hash rate, mempool depth, stale share rate, and the recent block/transaction feed.
3. Initialize stores with `wallet init`, then run `wallet daemon` against each node so `WalletSyncEngine` can page through `/wallet/{notes,commitments,ciphertexts,nullifiers}` plus `/blocks/latest`, persisting commitments locally before every poll.
4. Fund Alice (using the deterministic faucet in `tests/node_wallet_daemon.rs` or a bespoke devnet faucet), run `wallet send` with Bob’s Bech32 address, and wait for both daemons to mark the nullifiers as mined.

CI mirrors that flow via `tests/node_wallet_daemon.rs`—two nodes, two daemons, a mined subsidy, and a user-visible transfer—so the RPC contract breaks loudly. `dashboard-ui/tests/screenshot.spec.ts` and `dashboard-ui/tests/smoke.spec.ts` capture SVG snapshots of the mining, wallet, and network routes using the typography and color palette defined in `BRAND.md`, ensuring the analytics rendered to operators match the RPC telemetry the integration test enforces.

### Security assurance workflow

- Follow `docs/SECURITY_REVIEWS.md` whenever commissioning cryptanalysis or third-party audits. Every finding recorded there must reference the code path touched plus the mitigation PR.
- `circuits/formal/README.md` and `consensus/spec/formal/README.md` explain how to run the new TLA+ models. Include the TLC/Apalache output summary in PR descriptions when those specs change.
- `runbooks/security_testing.md` documents how to rerun the `security-adversarial` job locally, capture artifacts, and notify auditors if a regression appears on CI. Treat it as mandatory reading before release tagging.

### Documentation + threat-model synchronization

Whenever you touch an API, threat mitigation, or performance assumption:

1. Update the component README (e.g., `wallet/README.md`) with the new commands or invariants.
2. Update `docs/API_REFERENCE.md` so integrators can find the function signatures.
3. Update `docs/THREAT_MODEL.md` when security margins move.
4. Reflect the architectural impact in `DESIGN.md §6` (or the relevant subsystem section) and record the operational/testing changes here in METHODS.
5. Mention the change in `docs/CONTRIBUTING.md` so future contributors know which CI jobs/benchmarks cover it.

PRs missing any of these sync points should be blocked during review; CI surfaces the changed docs alongside code so reviewers can verify everything moved together.
