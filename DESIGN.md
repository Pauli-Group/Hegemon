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

Everything else is negotiable.

---

## 1. Cryptographic stack (primitives only)

### 1.1 Signatures

Use *only* NIST PQC signatures:

* Primary: **ML-DSA** (Dilithium, FIPS 204) for “everyday” signatures. ([NIST][1])
* Backup: **SLH-DSA** (SPHINCS+, FIPS 205) for long-lived roots of trust (genesis multisig, governance keys, etc.). ([Cloud Security Alliance][3])

Where they’re used:

* **Consensus / networking**:

  * Block producers sign block headers with ML-DSA.
  * Nodes/validators identity keys = ML-DSA.
* **User layer**:

  * Surprisingly little: within the shielded protocol, we can get rid of *per-input signatures* entirely and instead authorize spends by proving knowledge of a secret key in ZK (like Zcash already does with spend authorizing keys; here we do it with hash/lattice PRFs rather than ECC).

So: signatures are *mostly* a consensus/network thing, not something you see for each coin input.

---

### 1.2 Key exchange / encryption

For note encryption and any “view key” derivation:

* Use **ML-KEM (Kyber, FIPS 203)** as the KEM to establish shared secrets. ([NIST][1])
* Use a standard AEAD like **AES-256-GCM** or **ChaCha20-Poly1305**:

  * Symmetric is already “quantum-ok” modulo Grover; 256-bit keys give you ~128-bit quantum security.

Design pattern:

* Each address has a long-term **KEM public key** `pk_enc`.
* For each note, sender:

  * generates an ephemeral KEM keypair,
  * encapsulates to `pk_enc`,
  * runs a KDF on the shared secret to get the AEAD key and per-note diversifier.

This is directly analogous to ECIES-style note encryption in Zcash, but with ML-KEM.

---

### 1.3 Hashes, commitments, PRFs

To avoid any discrete-log assumptions:

* **Global hash**:

  * Use something boring and well-analyzed like **SHA-256** or **BLAKE3** as the global hash for block headers, Merkle trees, etc.
  * 256-bit outputs ⇒ ~128-bit security under Grover. ([ISACA][4])
* **Field-friendly hash for ZK**:

  * Inside the STARK, use a hash designed for Fp (e.g. Poseidon-ish / Rescue Prime / any modern STARK-friendly permutation).
  * These are *purely algebraic permutations*, so they rely on symmetric-style assumptions and are fine for PQ (again, Grover only).

Commitments:

* **Hash-based commitments** everywhere. A minimal design:

  * `Com(m, r) = H("c" || m || r)`
    is the commitment to `m` with randomness `r`.
* **Note commitment tree**:

  * Same conceptual tree as Zcash, but using the global hash or the STARK hash consistently; no Pedersen, no Sinsemilla, no EC cofactor dance.

PRFs:

* All “note identifiers”, nullifiers, etc. are derived with keyed hashes:

  * `nk = H("nk" || sk_spend)`
  * `nullifier = H("nf" || nk || note_position || rho)`

No group operations anywhere in user-visible cryptography.

### 1.4 Reference module layout

The repository now includes a standalone Rust crate at `crypto/` that collects the post-quantum primitives into a single API suiting the plan above. The crate exposes:

* `ml_dsa` – deterministic key generation, signing, verification, and serialization helpers sized to ML-DSA-65 (Dilithium3) keys (pk = 1952 B, sk = 4000 B, sig = 3293 B).
* `slh_dsa` – the analogous interface for SLH-DSA (SPHINCS+-SHA2-128f) with pk = 32 B, sk = 64 B, signature = 17088 B.
* `ml_kem` – Kyber-768-style encapsulation/decapsulation with pk = 1184 B, sk = 2400 B, ciphertext = 1088 B, shared secret = 32 B.
* `hashes` – SHA-256, BLAKE3-256, and a Poseidon-inspired permutation over the Goldilocks prime, plus helpers for commitments (`b"c"` tag), PRF key derivation (`b"nk"`), and nullifiers (`b"nf"`).

Everything derives deterministic test vectors using a ChaCha20-based RNG seeded via SHA-256 so that serialization and domain separation match the simple hash-based definitions above. Integration tests under `crypto/tests/` lock in the byte-level expectations for key generation, signing, verification, KEM encapsulation/decapsulation, and commitment/nullifier derivation.

---

## 2. ZK proving system: single STARKish stack

Rather than BCTV14 → Groth16 → Halo2, we pick **one** family: hash-based IOP → STARK-style.

Properties:

* **Transparent**: no trusted setup (only hash assumptions). ([C# Corner][2])
* **Post-quantum**: soundness reduces to collision resistance of the hashes + random oracle, so Shor has nothing to grab; Grover just reduces effective hash security by ~½.
* **Recursive-friendly**: pick something in the Plonky2/Plonky3 / Winterfell space that supports efficient recursion and aggregation. ([C# Corner][2])

Concretely:

* Base field: a 64-bit-friendly prime like 2⁶⁴×k−1 suitable for FFTs and FRI.
* Prover:

  * CPU-friendly (no big-integer pairings).
  * Highly parallelizable (good for GPU/prover markets).
* Verifier:

  * Maybe ~tens of milliseconds, proof sizes in the tens of kB (we accept ZK/STARK size inflation vs SNARK).

**Lesson from Zcash:** we do *not* change proving systems mid-flight if we can avoid it. We pick one transparent, STARK-ish scheme and stick with it, using recursion for evolution rather than entire new pools.

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

  * a **commitment** `cm = Com(value, asset_id, pk_view, rho; r)`,
  * a Merkle tree of note commitments,
  * a **nullifier** `nf` when the note is spent.

The ZK proof shows:

* “I know some opening `(value, asset_id, pk_view, rho, r)` and secret key `sk_spend` such that:

  * `cm` is in the tree,
  * `nf = PRF(sk_spend, rho, position, …)`,
  * total inputs = total outputs (value-conservation),
  * overflow conditions don’t happen.”

No ECDSA/EdDSA/RedDSA anywhere; the “authorization” is just knowledge of `sk_spend` inside the ZK proof.

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

No transparent outputs; everything is in this one PQ pool from day 1.

---

## 4. Addresses and keys (PQ analogue of Sapling/Orchard)

We still want:

* **Spending keys**
* **Full viewing keys**
* **Incoming-only viewing keys**
* Public addresses derived from those.

### 4.1 Secret key hierarchy

Let’s define base secret material:

* `sk_root` – master secret for the wallet.
* Derive sub-keys via KDFs:

  * `sk_spend = H("spend" || sk_root)`
  * `sk_view = H("view" || sk_root)`
  * `sk_enc = H("enc" || sk_root)`

From this we derive:

* **Spending authorization material**:

  * The STARK circuit uses `sk_spend` for nullifiers and for a commitment to “this user is allowed to spend this note”.
* **Viewing keys**:

  * `vk_full`: includes enough to derive both incoming and outgoing note info (e.g. seeds to recompute all `pk_view`, plus the PRFs used in the circuit).
  * `vk_incoming`: only the KEM/AEAD decryption info and the ability to scan for your notes, not to reconstruct spends.

Everything is done via hash-based PRFs / KDFs; no ECC.

### 4.2 Address encoding

A **shielded address** contains:

* A version byte (for future evolution).
* A **KEM public key** `pk_enc` (for ML-KEM).
* An **address-id / diversifier** derived from `sk_view` via PRF.

You can have multiple diversified addresses derived from the same underlying key material (like Zcash’s diversified addresses), but each is defined by basically: `(pk_enc, addr_tag)` where `addr_tag = H("addr" || sk_view || index)`.

### 4.3 Wallet crate implementation

The repository now contains a `wallet` crate that wires these ideas into code:

* `wallet/src/keys.rs` defines `RootSecret`, `DerivedKeys`, and `AddressKeyMaterial`. A SHA-256-based HKDF (`wallet-hkdf`) produces `sk_spend`, `sk_view`, `sk_enc`, and `sk_derive`, and diversified addresses are computed deterministically from `(sk_view, sk_enc, sk_derive, index)`.
* `wallet/src/address.rs` encodes addresses as Bech32m (`shca1…`) strings that bundle the version, diversifier index, ML-KEM public key, `pk_recipient`, and a 32-byte hint tag. Decoding performs the inverse mapping so senders can rebuild the ML-KEM key and note metadata.
* `wallet/src/notes.rs` handles ML-KEM encapsulation plus ChaCha20-Poly1305 AEAD wrapping for both the note payload and memo. The shared secret is expanded with a domain-separated label (`wallet-aead`) so note payloads and memos use independent nonces/keys.
* `wallet/src/viewing.rs` exposes `IncomingViewingKey`, `OutgoingViewingKey`, and `FullViewingKey`. Incoming keys decrypt ciphertexts and rebuild `NoteData`/`InputNoteWitness` objects for the transaction circuit, outgoing keys let wallets audit their own sent notes, and full viewing keys add the nullifier PRF material needed for spentness tracking.
* `wallet/src/bin/wallet.rs` ships a CLI with the following flow:
  * `wallet generate --count N` prints a JSON export containing the root secret (hex), the first `N` addresses, and serialized viewing keys.
  * `wallet address --root <hex> --index <n>` derives additional diversified addresses on demand.
  * `wallet tx-craft ...` reads JSON inputs/recipients, creates `TransactionWitness` JSON for the circuit, and emits ML-KEM note ciphertexts for the recipients.
  * `wallet scan --ivk <path> --ledger <path>` decrypts ledger ciphertexts with an incoming viewing key and returns per-asset balances plus recovered note summaries.

Integration tests in `wallet/tests/cli.rs` exercise those CLI flows, so anyone can watch address derivation, note encryption, and viewing-key-based balance recovery stay compatible with the proving system.

---

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

   * Address versioning encodes `(KEM_id, Sig_id)`.
   * Wallets can rotate to, say, ML-KEM-v2 or a code-based KEM if lattices get scary.
3. **Escape hatch**:

   * If some PQ primitive looks shaky, nodes can:

     * stop accepting new TXs using that primitive,
     * require users to “upgrade notes” via a special circuit that proves correct transfer into a new algorithm set.

So you get the “compartmentalization” Zcash achieved by multiple pools, but implemented via *versioning & recursion* rather than parallel pools.

Concrete modules in the repository now reflect this plan. A dedicated `state/merkle` crate maintains the append-only commitment tree with poseidon-style hashing, while a `circuits/block` crate replays ordered transaction proofs, enforces nullifier uniqueness, tracks the root trace, and records a recursive aggregation digest that can later be replaced by a true recursive STARK. Block producers call `prove_block` with their current tree, and validators call `verify_block` with their own state to ensure the final root matches before committing the block. The new `protocol-versioning` crate defines a `VersionBinding { circuit, crypto }` pair plus helpers for recording per-block version matrices. Every transaction now commits to its binding, the block header publishes a 32-byte `version_commitment`, and recursive block proofs expose `version_counts` so consensus can attest exactly how many transactions ran under each circuit/primitive pair.

Consensus enforces version rollouts via `VersionSchedule`, a governance-friendly structure that records which bindings are allowed at which heights. ZIP-style `VersionProposal`s (see `governance/VERSIONING.md`) specify activation heights, optional retirement heights, and any special upgrade circuits required to migrate notes from a deprecated primitive to a fresh one. Both BFT and PoW consensus paths consult the schedule before accepting a block, so validators can mix v1 and v2 proofs during a rollout without ever spawning a parallel privacy pool. When an emergency primitive swap is required, operators follow the runbook in `runbooks/emergency_version_swap.md` to publish an activation proposal, enable the upgrade circuit, and shepherd users through note migrations before the retirement height lands.

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
- `circuits/transaction`, `circuits/block`, and the new `circuits/bench` binary crate – contain the canonical STARK circuits and a CLI (`cargo run -p circuits-bench -- --prove`) that compiles dummy witnesses, produces transaction proofs, and optionally runs block aggregation via the recursive digest described above. The benchmark keeps track of constraint row counts, hash invocations, and elapsed time so that any change to witness construction or proving fidelity can be measured. Section 2 should be updated in lockstep with these outputs.
- `consensus/` and `consensus/bench` – the Rust validator logic still enforces version bindings and PQ signature validation, while the Go `netbench` simulator replays synthetic payloads sized to ML-DSA signatures plus STARK proofs. Its output feeds directly into the threat model’s DoS budgets because it reports achieved messages/second under PQ payload sizes.
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
