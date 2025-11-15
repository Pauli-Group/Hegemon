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

### 5.2 Algorithm agility

Keys include algorithm identifiers:

* For KEM: `kem_id` ∈ {ML‑KEM‑768, ML‑KEM‑v2, …}
* For signatures: `sig_id` ∈ {ML‑DSA‑65xx, SLH‑DSA‑1xx, …}

Addresses encode these IDs. The join–split circuit doesn’t care; it just treats `asset_id` and `pk_recipient` as opaque bytes. Only the *note encryption/decryption* layer and wallet code depend on the KEM.

On algorithm deprecation:

* Consensus can forbid new transactions with, say, `kem_id = ML‑KEM‑768` after block X, but still allow spends of existing notes for some grace period.
* You can also add a “must migrate by height H” rule for certain key types, enforced by a special migration circuit.
