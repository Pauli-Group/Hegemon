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

### 0.2 Admin posture (production/testnet)

* **No sudo or session pallets** in production/testnet genesis. The PoW chain runs without validator sessions.
* Any privileged changes must flow through governance pallets or runtime upgrades, not a built‑in superuser key.

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
  * The PQ discovery channel (`/hegemon/discovery/pq/1`) exchanges both dialable addresses (`GetAddrs`/`Addrs`) and bounded connected-peer lists (`GetPeerGraph`/`PeerGraph`) so dashboards can visualize multi-hop peer graphs.
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

STARK verifier parameters (hash function choice, query counts, blowup factors, field extension) should be treated as protocol-release parameters, not live governance knobs. The live Plonky3 transaction/settlement verifier currently runs with production compile-time parameters from `circuits/transaction-core/src/p3_config.rs` (`log_blowup = 4`, `num_queries = 32`), while any runtime defaults are derived from the active protocol manifest. With 384-bit digests, PQ collision resistance reaches ~128 bits for application-level commitments, and 48-byte encodings are used end-to-end.

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

Implementation detail: the Plonky3 backend uses `p3-uni-stark` (v0.4.x). For the transaction AIR, fixed schedule selectors (Poseidon round flags, cycle markers, and row-specific assertions) are embedded as explicit schedule columns in the main trace; this keeps the schedule deterministic while avoiding preprocessed-trace OOD mismatches. The stablecoin binding payload and the fixed four balance-slot asset ids are carried in the STARK public inputs, the native MASP slot remains slot `0`, the witness trace keeps only the per-slot running sums plus the compact 2-bit stablecoin slot selector, and a single shared rho carry lane is reused across the two input-note phases. Runtime/API validation now enforces the canonical slot-asset encoding (`slot 0 = native`, strictly increasing non-native ids, padding only as a suffix) so the binding hash, statement hash, and prover all commit to the same slot layout. Other circuits may still use preprocessed columns where stable.

#### 2.1 Algebraic embeddings that claw back overhead

The transparent stack above is heavier than Groth16/Halo2, but a few circuit-level embeddings keep it manageable:

* **Goldilocks-friendly encodings** – Express the note/balance logic directly in the 64-bit-friendly base field instead of relying on binary gadgets. Packing `(value, asset_id)` pairs into two 64-bit limbs each lets the AIR use cheap addition/multiplication constraints with no Boolean decomposition. This matches Plonky3’s Goldilocks optimizations and avoids the \((\times 32\) blow-up you’d get from bit-constraining every register.
* **Permutation/Ishai–Kushilevitz style lookups** – MASP balance checks need large-domain comparisons (e.g., `asset_id` equality during the in-circuit sort). Encoding those comparisons as STARK-friendly permutation arguments—rather than explicit comparator circuits—reuses the same algebraic lookup table that the prover already commits to for Poseidon rounds. Empirically this trims ~15–20 % of the trace width relative to naive comparison gadgets while remaining transparent.
* **Batched range proofs via radix embeddings** – Instead of per-note binary range proofs, the current production transaction AIR decomposes bounded values into 21 shared radix-8 limbs (`3` bits each, boolean top limb) and reuses one limb region across note, fee, value-balance, and issuance rows. A later lookup-backed higher-radix path remains possible, but the deployed shape already avoids the old 61-bit-per-value blow-up while keeping the constraint degree low.
* **Folded multi-openings for recursion** – Recursively verifying child proofs requires many polynomial openings; batching them through a single FRI transcript with linear-combination challenges keeps the verifier time in the "tens of ms" bucket despite the larger STARK proofs.

None of these tricks negate the inherent bandwidth hit of transparent proofs, but they make the witness columns thinner and the constraint system shallower so that prover time and memory stay near the Zcash baseline even with PQ primitives.

### 2.5 Formal verification and adversarial pipelines

The `circuits/formal/transaction_balance.tla` model captures the MASP balance rules (nullifier uniqueness + per-asset conservation) using a compact TLA+ spec. Any change to the AIR/witness layout must update that spec plus rerun TLC/Apalache, recording the outcome in the associated README and in `docs/SECURITY_REVIEWS.md`. On the implementation side, `circuits/transaction/tests/security_fuzz.rs` performs property-based fuzzing of `TransactionWitness::balance_slots` and `public_inputs` to catch serialization edge cases. Both the formal model and the fuzz harness are wired into the `security-adversarial` CI job, so contributors get immediate feedback when the balance/tag logic drifts.

### 2.6 Aggregation mode (proofless L1 lane)

Per-transaction transparent STARK proofs are too large to ship in every transfer extrinsic if the goal is “world commerce.” The chain therefore supports a per-block **aggregation mode** that moves per-tx proof bytes off-chain while keeping block validity enforced during import:

* Block authors include `pallet_shielded_pool::Call::enable_aggregation_mode` as a **mandatory unsigned** extrinsic early in the block.
* A chain-level `ProofAvailabilityPolicy` now has only two modes: `InlineRequired` and `SelfContained`.
* In aggregation mode + `SelfContained`, `shielded_transfer_unsigned_sidecar` may omit `proof.data` and the runtime skips `verify_stark` (it still enforces binding hashes, nullifier uniqueness, anchor checks, and fee rules).
* In aggregation mode + `SelfContained`, proofless transfers are fail-closed: they require `submit_proven_batch` in the same block. If proof bytes are present inline, import can still verify via the inline path.
* Proof bytes may still be staged to the block author via `da_submitProofs` keyed by `binding_hash` (wallets can enable this via `HEGEMON_WALLET_PROOF_SIDECAR=1`), but this is **off-chain proposer staging only**. It is not part of consensus validity in Phase C.
* The node import pipeline verifies commitment proof + aggregation proof using transaction statement commitments (`tx_statements_commitment`) and does not fetch/validate proof-DA manifests or proof-DA commitments.

This preserves the PQ security bar while shifting “lots of proofs” work off-chain and reducing the on-chain payload to O(1) proofs per block.

---

### 2.7 Experimental post-proof folding stack

For the fresh-chain 0.10.0 line, the shipped transaction-validity path is now direct native `tx_leaf` verification: wallets emit native tx-leaf artifact bytes by default, the runtime accepts only that format on the live unsigned transfer path, and blocks without an explicit block artifact verify those ordered per-transaction artifacts directly. The repo still carries an additive experimental workspace under `circuits/superneo-*` for witness-free post-proof compression and block-artifact research, but those block-level experiments are no longer allowed to define the shipping architecture by implication.

That stack is intentionally split into a Hegemon-owned relation layer (`superneo-ccs`), a backend trait layer (`superneo-core`), Goldilocks pay-per-bit witness packing (`superneo-ring`), a direct in-repo folding backend (`superneo-backend-lattice`), Hegemon-specific relations (`superneo-hegemon`), and a benchmark CLI (`superneo-bench`). The first real relation is a transaction-proof receipt relation rather than a full transaction AIR port. That is deliberate: any future compression win has to come from a post-proof primitive that sits after tx proving, not from re-running the hot witness path in another proof system.

The current backend is no longer a pure digest mock, and it is no longer stuck on the killed single-challenge line or the old assumption-fed commitment rewrite. The active experimental family is now `goldilocks_128b_structural_commitment`, fingerprint `c24ea2de5d61afbe99ccc1befeb7eea3df8ada33965369f22ff220fa377078ef68ce6179a0769e6db2202a989f5eb559`, `security_bits = 128`, `matrix_rows = 74`, `matrix_cols = 8`, `challenge_bits = 63`, `fold_challenge_count = 5`, `max_fold_arity = 2`, `transcript_domain_label = "hegemon.superneo.fold.v3"`, `decomposition_bits = 8`, `opening_randomness_bits = 256`, `commitment_assumption_bits = 0`, `derive_commitment_binding_from_geometry = true`, `max_commitment_message_ring_elems = 513`, and `max_claimed_receipt_root_leaves = 128`. Its manifest exposes `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v3"`, `commitment_scheme_label = "bounded_message_random_matrix_commitment"`, `challenge_schedule_label = "quint_goldilocks_fs_challenge_negacyclic_mix"`, and `maturity_label = "structural_candidate"`. The exact current protocol surface is frozen in [docs/crypto/native_backend_spec.md](docs/crypto/native_backend_spec.md), the current claim model is stated in [docs/crypto/native_backend_security_analysis.md](docs/crypto/native_backend_security_analysis.md), the concrete break ledger is tracked in [docs/crypto/native_backend_attack_worksheet.md](docs/crypto/native_backend_attack_worksheet.md), and the constant-time/canonicality note now lives in [docs/crypto/native_backend_constant_time.md](docs/crypto/native_backend_constant_time.md). Benchmark JSON carries the corresponding `spec_digest` so archived results can be tied to one exact wire/transcript contract instead of only to a prose claim. The older `heuristic_goldilocks_baseline` and `goldilocks_128b_rewrite` families remain in tree only as frozen comparison constructors. Packed witness values are decomposed into low-bit digits, embedded into small negacyclic ring elements over Goldilocks, committed with a deterministic public matrix plus an explicit canonicalized 256-bit mask seed, and then folded with five transcript-derived linear challenges mixed through a negacyclic rotation of the right child commitment rows. The parameter object now covers the full currently implemented regime: setup rejects parameter sets whose advertised security target exceeds the computed security floor, rejects mismatched fold arity or transcript domain, fingerprints those values together with the manifest, and derives a separate `spec_digest` under a distinct hash domain so backend behavior cannot change there without a new parameter fingerprint, new spec identity, and new artifact version. The compact-leaf step was tightened again: native tx-leaf artifacts now carry both the manual hidden-witness opening (`sk_spend`, input witnesses, output witnesses, Merkle paths) and an explicit backend commitment opening object (packed witness, randomness seed, opening digest), and the artifact bytes now also carry the backend `spec_digest`. Verification reconstructs the expected packed witness from the tx opening, checks that against the backend opening, rejects noncanonical randomness seeds for the configured entropy bound, rejects mismatched spec identities, verifies the randomized commitment under the manifest-owned parameter set, and only then accepts the tx-leaf proof. `ReceiptRoot` is now native-only on the experimental lane: consensus folds and verifies only native `TxLeaf` artifacts there and falls back to `InlineTx` rather than accepting the older bridge profile on that path. Import hardening includes exact native artifact-size bounds plus a reusable verified-native-leaf store keyed by native artifact hash. The old native `ReceiptRoot` verifier is intentionally still linear so the repo preserves a baseline, while the experimental `receipt_accumulation` kind wraps the folded native receipt-root bytes together with the ordered native leaf hashes. That wrapper lets import hit the verified-native-leaf store first and re-check the folded root without re-running every hidden-witness opening when those leaves were already verified during candidate preparation or an earlier import attempt, and cached authoring reuse now re-runs that prewarm before it returns a stored accumulation payload so the payload cannot drift away from the verifier-local state it still assumes. Node authoring and import still reject `receipt_root` and `receipt_accumulation` when proof bytes exist only in local sidecar state because those lanes are not cold-self-contained, and `HEGEMON_REQUIRE_NATIVE=1` now adds a fail-closed native-only guard that rejects non-canonical selectors, `InlineTx` fallback outcomes, and non-canonical import payloads. The current `receipt_arc_whir` kind is no longer documented as a receipt-only cold-import win. Review forced a stricter shape: authoring still derives canonical receipt rows from the candidate's native artifacts and builds one sampled Reed-Solomon residual artifact over those rows, but import now verifies the ordered native `TxLeaf` artifacts first, derives the receipts from those verified leaves, checks the block statement commitment against the verified bindings, and only then verifies the residual artifact's Merkle openings plus fold relations. That fix closes the receipt-only soundness hole and keeps the lane off the old aggregation backend, but it also means cold verification replays native leaf verification and therefore does not solve the original import-killing goal. Two colder additive attempts remain negative results on this branch: `receipt_decider`, because it embedded public `TxLeaf` artifacts and replayed per-leaf verification on cold import, and the first synthetic `receipt_arc_whir` pass, because review showed its verifier was still rebuilding the full artifact from public receipts and then byte-comparing the result. The closure pass in `.agent/FINISH_NATIVE_PROOF_LINE_EXECPLAN.md` still stands for the frozen single-challenge baseline, `.agent/NATIVE_BACKEND_128B_SECURITY_PACKAGE_EXECPLAN.md` remains the historical record for the package scaffolding, and `.agent/STRUCTURAL_COMMITMENT_GEOMETRY_EXECPLAN.md` now owns the active geometry fix. The machine-derived `NativeSecurityClaim` for the active family now reports `claimed_security_bits = 128`, `transcript_soundness_bits = 157`, `opening_hiding_bits = 128`, `commitment_codomain_bits = 37296`, `commitment_same_seed_search_bits = 36936`, `commitment_random_matrix_bits = 360`, `commitment_binding_bits = 360`, `composition_loss_bits = 7`, `soundness_floor_bits = 128`, `review_state = candidate_under_review`, and assumption ids `random_oracle.blake3_fiat_shamir`, `serialization.canonical_native_artifact_bytes`, `fs.quint_goldilocks_negacyclic_fold_challenges`, `opening.canonical_256b_mask_seed`, and `commitment.bounded_message_random_matrix_union_bound`. That is the current honest split: the live `128`-bit floor now comes from the geometry-derived commitment term instead of the old `commitment_assumption_bits` override, but it pays materially larger artifacts because the matrix grew to `74 x 8`. The repo now also carries the fixed vector bundle in [testdata/native_backend_vectors](/Users/pldd/Projects/Reflexivity/Hegemon/testdata/native_backend_vectors), the independent verifier in [tools/native-backend-ref](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref) that no longer calls the production verification helpers, the timing harness in [tools/native-backend-timing](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-timing), local and CI fuzz-smoke coverage, and the reproducible review package under [audits/native-backend-128b](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b) plus its checksum file [package.sha256](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/package.sha256). The package still includes `code_fingerprint.json`, which records `HEAD`, tracked/staged diff hashes, untracked file hashes, and a composite `worktree_fingerprint` instead of pretending a dirty worktree is a clean commit. The archived current-tree release benchmark [native_tx_leaf_receipt_root_structural_commitment_20260328.json](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/benchmarks/native_tx_leaf_receipt_root_structural_commitment_20260328.json) records a byte curve of `22,625..27,561 B/tx`; its wall-clock verify numbers remain host/load-sensitive and stay in the archive JSON instead of being frozen into prose. This still does not make the backend paper-equivalent to Neo or SuperNeo, but it does mean the in-repo line now encodes one exact protocol surface, one exact geometry-derived binding story, one exact loss calculation, one exact vector bundle, one exact second verifier, and one exact review-state qualifier in code. The security-package closure still resolves `KEEP`, but only as a 128-bit PQ candidate under external review.

The experimental relation layer now has one explicit linear baseline and a smaller diagnostic bench surface beside it. `TxLeafPublicRelation` is retained as a bridge/comparison relation over nullifiers, commitments, ciphertext hashes, balance tag, version binding, and serialized STARK public inputs. `NativeTxValidityRelation` remains the witness-driven source relation: it consumes `TransactionWitness` directly, checks witness validation plus Merkle membership locally, derives the canonical public-input object without going through a Plonky3 proof, and can feed either the native `TxLeaf -> ReceiptRoot` baseline or the diagnostic `receipt_arc_whir` lane. The benchmark CLI now defaults back to `native_tx_leaf_receipt_root`; `native_tx_leaf_receipt_arc_whir` requires `--allow-diagnostic-relation`. The ARC/WHIR benchmark still emits an `import_comparison` object, but the important current honesty point is structural rather than promotional: the execution trace now measures real cold behavior and shows that the anchored lane replays native leaf verification while still keeping `used_old_aggregation_backend = false`, and the residual verifier still reconstructs queried Reed-Solomon evaluations from the full receipt list so it remains linear in receipt count. The current hardening therefore focuses on honest baseline observability plus a real residual-verifier prototype rather than on claiming the cold-import problem is solved. This is still not Neo/SuperNeo’s full commitment stack and should not be treated as a security-equivalent substitute for the papers: the in-repo backend still stops short of the exact Module-SIS commitment analysis, decomposition reduction, and sum-check machinery. The experiment remains benchmarkable and deletable, and it is still not consensus-relevant beyond the additive receipt-root research path. The naming rule in code follows the same boundary: generic layers speak in `ProofEnvelope`, `TxValidityReceipt`, `TxValidityArtifact`, `TxLeaf`, and `ReceiptRoot` terms, while `superneo-*` names stay confined to the experimental backend crates that implement one concrete receipt-root backend today.

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
  and Merkleized with BLAKE3 under `da-leaf`/`da-node` domain tags. Validators can operate under an on-chain DA policy:
  `FullFetch` recomputes `da_root` from the full blob, while `Sampling` verifies randomized shards only (using the commitment
  proof payload’s `da_root`/`chunk_count`). A companion ciphertext policy controls whether inline ciphertext bytes are accepted
  or sidecar-only submissions are enforced, letting the network start with full storage and progressively tighten to sampling.
* Timestamp guards match the implementation: the header time must exceed the median of the prior 11 blocks and be no more than
  90 seconds into the future relative to the local clock; nodes may re-evaluate future-dated candidates as time advances but
  still reject any header that remains beyond the skew bound or fails median-time-past.
* Block template helpers in `consensus/tests/common.rs` show how miners wire these fields together: compute the note/fee/nullifier
  commitments, attach the coinbase metadata, recompute `supply_digest`, and only then sign + grind the header.

No transparent outputs; everything is in this one PQ pool from day 1.

Substrate RPC extensions in `node/src/substrate/rpc` expose that state machine so operators can monitor the same fields remotely. `/blocks/latest` and `/metrics` stream hash rate, mempool depth, stale share rate, best height, and compact difficulty values that miners compare against the reward policy in `pallets/coinbase/src/lib.rs`. Per `TOKENOMICS_CALCULATION.md`, the initial block reward is ~4.98 HEG (derived from the 60-second block time), and epochs last 4 years (~2.1M blocks). Every mined block updates the header’s `supply_digest`, and the quickstart playbook in [runbooks/miner_wallet_quickstart.md](runbooks/miner_wallet_quickstart.md) walks through querying those endpoints before wiring wallets to the node API. Substrate integrations reuse the same machinery: the `consensus::substrate::import_pow_block` helper executes the PoW ledger checks (version-commitment + STARK commitments + reward checks) as blocks flow through a Substrate import queue, and the node exposes `/consensus/status` to mirror the latest `ImportReceipt` alongside miner telemetry so the benchmarking tools under `consensus/bench` see consistent values.

### 3.3 Shielded stablecoin issuance

Stablecoin issuance and burn are modeled as a non-native MASP asset that lives entirely inside the shielded pool. Instead of exposing a transparent mint, the transaction circuit allows a single asset id to carry a non-zero net delta, but only when the proof binds to a protocol policy hash plus the latest oracle and attestation commitments. The policy is hashed with BLAKE3 under the `stablecoin-policy-v1` domain so the circuit can consume a single 48-byte value. The verifier in `pallets/shielded-pool` checks that the policy hash, policy version, oracle commitment freshness, and attestation dispute status match the active protocol manifest before accepting the proof.

Issuance and burn therefore stay shielded: the proof shows `inputs - outputs = issuance_delta` for the stablecoin asset, and the runtime accepts the binding only through the unsigned proof-native lane. Wallet tooling assembles the binding from the active protocol state and submits it through the Hegemon shielded RPC, not through a signed account extrinsic. Normal stablecoin transfers do not require a binding, but they still ride the same MASP rules and never leave the privacy pool.

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

  * `nk = H_f("nk" || sk_spend)` is derived in-circuit from spend key material.
* **Viewing keys**:

  * `vk_full`: includes enough to derive incoming/outgoing note info plus a spend-derived nullifier PRF output for spentness tracking.
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
* `wallet/src/address.rs` encodes addresses as Bech32m (`shca1…`) strings that bundle the version, crypto suite, diversifier index, ML-KEM public key, `pk_recipient`, and spend-auth key `pk_auth`. Decoding performs the inverse mapping so senders can rebuild the ML-KEM key and note metadata.
* `wallet/src/notes.rs` handles ML-KEM encapsulation plus ChaCha20-Poly1305 AEAD wrapping for both the note payload and memo. The shared secret is expanded with a domain-separated label (`wallet-aead`) plus the crypto suite so note payloads and memos use independent nonces/keys and suite-confusion fails authentication. Runtime validation hard-cuts ciphertext header acceptance to the active version (`v3`); mismatches are rejected fail-closed.
* `walletd/` is a sidecar daemon that opens a wallet store and exposes a versioned newline-delimited JSON protocol over stdin/stdout so GUI clients (like `hegemon-app`) can drive sync, send, and disclosure workflows without re-implementing cryptography. The protocol includes capability discovery plus structured error codes, and `walletd` enforces an exclusive lock file alongside the store to prevent concurrent access. For v0.9 strict operation, `walletd` defaults to self-contained unsigned submission (full proof/ciphertext bytes in the transfer extrinsic) so transactions remain portable across miners; DA/proof sidecar staging is opt-in (`HEGEMON_WALLET_DA_SIDECAR=1` / `HEGEMON_WALLET_PROOF_SIDECAR=1`) for deployments that explicitly coordinate sidecar availability.
* `wallet/src/viewing.rs` exposes `IncomingViewingKey`, `OutgoingViewingKey`, and `FullViewingKey`. Incoming keys decrypt ciphertexts and rebuild `NoteData`/`InputNoteWitness` objects for the transaction circuit, outgoing keys let wallets audit their own sent notes, and full viewing keys add spend-derived nullifier PRF material needed for spentness tracking without carrying `sk_spend`.
* `wallet/src/bin/wallet.rs` ships a CLI with the following flow:
  * `wallet generate --count N` prints a JSON export containing the root secret (hex), the first `N` addresses, and serialized viewing keys.
  * `wallet address --root <hex> --index <n>` derives additional diversified addresses on demand.
  * `wallet tx-craft ...` reads JSON inputs/recipients, creates redacted `TransactionWitness` JSON (omits `sk_spend`), and emits ML-KEM note ciphertexts for the recipients.
  * `wallet scan --ivk <path> --ledger <path>` decrypts ledger ciphertexts with an incoming viewing key and returns per-asset balances plus recovered note summaries.
  * `wallet substrate-sync`, `wallet substrate-daemon`, and `wallet substrate-send` are the live Substrate RPC flows; `wallet substrate-send` now wraps the proof-backed shielded transfer in a kernel action and submits it through `hegemon_submitAction`.

Integration tests in `wallet/tests/cli.rs` exercise those CLI flows, so anyone can watch address derivation, note encryption, and viewing-key-based balance recovery stay compatible with the proving system.

Long-lived wallets rely on the Substrate WebSocket RPC client (`wallet/src/substrate_rpc.rs`) and async sync engine (`wallet/src/async_sync.rs`) rather than ad-hoc scripts. `AsyncWalletSyncEngine` pages through commitments/ciphertexts/nullifiers plus the latest block height, storing commitments inside the encrypted `WalletStore` so daemons can resume after crashes. The runbook in [runbooks/miner_wallet_quickstart.md](runbooks/miner_wallet_quickstart.md) walks through starting those daemons against two nodes.

Consolidation workflows are also sidecar-aware: wallet note merges default to DA sidecar submission and can stage proof bytes out-of-band for self-contained aggregation blocks, with throughput controlled by explicit per-round tx/byte caps (`HEGEMON_WALLET_CONSOLIDATION_MAX_TXS_PER_BATCH`, `HEGEMON_WALLET_CONSOLIDATION_MAX_BATCH_BYTES`) plus sidecar toggles (`HEGEMON_WALLET_CONSOLIDATION_DA_SIDECAR`, `HEGEMON_WALLET_CONSOLIDATION_PROOF_SIDECAR`).

Ciphertext availability is policy-dependent: ciphertext bytes may be served from on-chain storage (inline) or from sidecar/DA stores. In the sidecar path, the ciphertext stream can contain gaps (retention) or non-canonical ciphertexts (forks). Wallet sync therefore treats decrypted notes as valid only when their commitment can be found in the locally-synced commitment list; otherwise the note is skipped and sync continues. Nodes should report `walletNotes.next_index` as the maximum ciphertext index they can serve (which may exceed `leaf_count`), while `leaf_count` remains the canonical commitment tree size.

The Polkadot.js Apps dashboard (https://polkadot.js.org/apps/) can still connect to the node's standard Substrate RPC endpoint for block exploration and raw chain-state inspection, but it should not be treated as the transaction-submission interface because the live protocol no longer exposes a normal account-transaction lane.

---

### 4.4 Disclosure on demand (payment proofs)

When a sender must prove a specific shielded payment to an exchange or auditor without revealing a viewing key, the wallet can generate a targeted **payment proof**. A disclosure package includes a STARK proof from `circuits/disclosure` binding `(value, asset_id, pk_recipient, pk_auth, commitment)` to the note-opening secrets `(rho, r)`, plus non-ZK confirmation data (Merkle inclusion path, anchor root) and the chain `genesis_hash`. The wallet stores outgoing note openings in the encrypted `WalletStore`, then `wallet payment-proof create` produces the package on demand. `wallet payment-proof verify` checks the STARK proof, Merkle path, `hegemon_isValidAnchor`, and the disclosed chain identity. Optional `disclosed_memo` fields are treated as user-supplied context and are not bound by the ZK proof.

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

Concrete modules in the repository now reflect this plan. A dedicated `state/merkle` crate maintains the append-only commitment tree with Poseidon-style hashing, while the `circuits/block` crate treats commitment proofs as an optional parent-bound block-validity artifact for the explicit experimental block-artifact lanes: `CommitmentBlockProver` builds a `CommitmentBlockProof` that commits to transaction statements (`tx_statements_commitment`) via a Poseidon sponge, and consensus verifies the commitment proof alongside per-transaction input checks whenever a block carries one. The commitment proof binds `tx_statements_commitment` plus the starting/ending state roots, nullifier root, DA root, and the transaction-ordered + sorted nullifier lists as public inputs; consensus enforces the actual state-transition Merkle updates because naive in-circuit updates exceed the ~2^14 row target by two orders of magnitude (each depth-32 append costs ~10k rows). Nullifier uniqueness is proven in-circuit to prevent double-spend without per-tx consensus work, and consensus recomputes the padded transaction-ordered nullifier list to ensure the proof’s public inputs match the block’s transactions before accepting that uniqueness claim. In `InlineRequired`, blocks without an aggregation proof use parallel per-transaction verification, and on the fresh-chain 0.10.0 shipped path those per-transaction artifacts are native `TxLeaf` bytes rather than legacy inline STARK proofs. In `SelfContained` aggregation mode, proofless transfers are fail-closed (`submit_proven_batch` required), and strict authoring requires a ready proven batch for shielded candidate sets (no on-demand proving fallback in block assembly). Consensus validates a block by deriving commitment-proof public inputs from the block’s transactions, verifying the `CommitmentBlockProof`, recomputing `tx_statements_commitment` from canonical transaction statement hashes, then verifying the aggregation proof under the selected mode before applying commitments to the state tree; in the Substrate node path, proof bytes are carried on-chain via unsigned `ShieldedPool::submit_proven_batch` and checked during block import. Block authors no longer generate proofs in the synchronous block-builder closure: an in-node asynchronous prover coordinator prebuilds proven batches keyed by parent hash + statement commitment + tx count, and block assembly only attaches ready payloads. The prebuild path now uses a single candidate preprocessing pass (`decode + extract + statement hashes + DA encoding`) and then runs commitment-proof and aggregation-proof generation in parallel against shared context state, with explicit `context_stage_ms`, `commitment_stage_ms`, and `aggregation_stage_ms` timings logged for attribution. Prove-ahead aggregation artifacts are cached across parent changes, while scheduler readiness remains current-parent scoped so stale-parent bundles never block rescheduling. Operators running the experimental recursive lane also hold local mining while a strict proofless batch waits on a ready proven bundle; otherwise self-mined empty blocks rotate the parent faster than the first recursive leaf can finish. When pending proofless traffic outpaces proving, assembly includes only the ready proofless subset and defers the rest, preserving liveness without violating self-contained validity. Commitment-proof jobs seed from runtime compact Merkle snapshots (leaf count/root/frontier/history) instead of replaying all commitments per job, keeping setup cost bounded as chain height grows. The coordinator runs a bounded background queue of candidate batches and uses checkpointed deterministic upsizing by default (for example `1/2/4/8/.../target`), which avoids building a new expensive recursion shape for every `+1` mempool increment while preserving a singleton liveness lane when queue capacity is at least 2. For open prover-market scaling, the coordinator now publishes deterministic fan-out chunk packages for the largest candidate (`candidate_set_id` and chunk offsets/counts) and rotates package serving across the queue; once all expected chunk results arrive, it assembles one contiguous `FlatBatches` payload for block inclusion. In the recursive external-worker topology, that same scheduler now publishes the singleton recursive liveness lane into the stage-work queue ahead of the larger candidate, and for the main throughput lane it materializes an arbitrary-depth fixed-fan-in merge tree instead of a hard-coded `leaf -> one root merge` shortcut. Merge nodes now recurse over either leaf proofs or lower merge proofs, and each subtree is published as soon as its direct children finish, so independent provers can work on different parts of the same batch instead of idling behind a monolithic root leaf. Prover-side recursion caches are split into thread-local full entries and a process-wide singleflight `CommonData` layer: full circuit artifacts stay local because they are not thread-safe, while the dominant preprocessing commitment (`commit_preprocessed`) is shared across workers per shape to avoid duplicate cold builds. Remote `hegemon-prover` measurements showed why the old wide-leaf defaults were wrong: a `tx_count=2` root leaf measured `30404798 / 18437798 / 12147322` witness/add/mul rows with `296913 ms` cold and `227329 ms` warm wall-clock, while a binary merge over singleton leaves measured only `19616022 / 11935172 / 7859506` rows with `176068 ms` cold and `133886 ms` warm. The live recursion lane therefore now defaults to `leaf_fan_in=1`, `merge_fan_in=2`, transaction recursion `num_queries=2`, transaction recursion `log_blowup=2`, and outer aggregation `num_queries=2` / `log_blowup=2`: singleton leaves keep the leaf stage on the cheap verifier shape, and binary merges give parallel provers actual subtree work without recreating the same blow-up at the next level. V5 leaf payloads now special-case the singleton root: when the full recursive tree has one transaction, the payload carries the direct tx public inputs and omits the outer proof entirely, and when the whole tree fits in one root leaf the prover/verifier shape uses the actual active child count instead of padding to the configured global leaf fan-in. Operators can restore legacy per-step upsizing with `HEGEMON_BATCH_INCREMENTAL_UPSIZE=1`, disable liveness with `HEGEMON_PROVER_LIVENESS_LANE=0`, and tune throughput with `HEGEMON_AGG_STAGE_LOCAL_PARALLELISM`/`HEGEMON_PROVER_WORKERS`, `HEGEMON_BATCH_TARGET_TXS`, `HEGEMON_AGG_STAGE_QUEUE_DEPTH`/`HEGEMON_BATCH_QUEUE_CAPACITY`, and `HEGEMON_PROVER_STAGE_MAX_INFLIGHT_PER_LEVEL`; `HEGEMON_PROVER_ADAPTIVE_LIVENESS_MS` is opt-in (default disabled) so strict throughput mode does not silently downshift to singleton proving unless explicitly requested. If `HEGEMON_BATCH_TARGET_TXS` is unset startup caps the default to `min(HEGEMON_MAX_BLOCK_TXS, HEGEMON_BATCH_DEFAULT_TARGET_TXS)` with `HEGEMON_BATCH_DEFAULT_TARGET_TXS=32`. The aggregation prover prewarms target shapes by default from `HEGEMON_BATCH_TARGET_TXS` when `HEGEMON_AGG_PREWARM_MAX_TXS` is not set, which removes first-user cold-start stalls in strict batching mode. The `protocol-versioning` crate defines a `VersionBinding { circuit, crypto }` pair plus helpers for recording per-block version matrices. The deployment path from the fresh-chain native direct path to any later federated authors or PQ-authenticated prover market is documented in [docs/SCALABILITY_PATH.md](docs/SCALABILITY_PATH.md); the short version is that throughput should first grow through proof-ready native transactions and honest authoring before any new public prover layer is treated as product surface.

Block-proof compatibility is now hard-cut to `BlockProofBundle` schema `2` with proof format id `5`. Import fail-closes on legacy payloads. The legacy payload field still supports explicit proof modes such as `InlineTx`, `MergeRoot`, and `FlatBatches`, but on the fresh-chain 0.10.0 product path that selector is no longer the architecture-defining fact. The live shielded path is direct ordered native `TxLeaf` verification with no required block artifact. In other words: the compatibility name `InlineTx` survives in routing, but the shipped per-transaction bytes are native tx-leaf artifacts rather than the old inline STARK proofs.

`MergeRoot` validation still verifies the root artifact and bound metadata under the same `tx_statements_commitment` and `tx_count` constraints, but it remains an explicit recursion experiment instead of the default hot path. The coordinator path keeps one canonical recursive stage namespace (`leaf_batch_prove`, `merge_node_prove`, `root_aggregate_prove`, `finalize_bundle`) so dependency ids and worker dispatch cannot silently diverge, and it still separates parent-independent expensive artifacts from parent-bound final bundle assembly. Shared merge-root layout helpers still eliminate the previous risk of three incompatible tree layouts in three crates. The local benchmark harness still exposes the relevant comparison surfaces (`raw_shipping`, `raw_active`, `merge_root_active`, and the native receipt-root diagnostics), but those are benchmark and research surfaces, not the definition of the shipped 0.10.0 architecture.

The practical product split is now cleaner. Native `TxLeaf` submission is the only shipped shielded transaction-validity format on the fresh chain. `HEGEMON_BLOCK_PROOF_MODE` remains as an operator selector for explicit experimental block-artifact lanes such as `merge_root`, `receipt_root`, `receipt_accumulation`, and `receipt_arc_whir`; `flat` still falls back to `inline_tx`, and sync admission remains strict: unknown peers must pass a compatibility probe that matches local `genesis_hash`, `sync_protocol_version`, and proof format id before discovery/sync traffic treats them as eligible.

For the open prover market, coordinator work identity is now parent-independent on the heavy lane: the previously published tx-proof-manifest chunk `package_id` depended only on the ordered transaction set and chunk range, not on `parent_hash` or `block_number`. Parent binding is deferred to the final commitment proof stage, which remains the only parent-specific proof artifact on the live lane. The tx-proof-manifest work package path is kept only as benchmarked recovery history; it is no longer an enabled proving mode.

Update (2026-03-26): read the receipt-root-family operator surface through the newer proof-kind routing described above, not through the older three-mode summary in the previous paragraph. The active explicit selectors are `inline_tx` by default, `merge_root` for recursion experiments, `receipt_root` as the native linear baseline, `receipt_accumulation` as the warm-store experiment, `receipt_arc_whir` as a diagnostic native-leaf-backed residual lane, and `flat` forced back to `inline_tx`.

Internally, the legacy runtime encoding still uses `BlockProofBundle` (schema tag `BLOCK_PROOF_BUNDLE_SCHEMA`) for compatibility, but the fresh-testnet public vocabulary is now `CandidateArtifact` plus `ArtifactAnnouncement` / `ArtifactClaim`, and the consensus block boundary itself is proof-backend-neutral. `consensus::types::Block` now carries `tx_validity_artifacts: Option<Vec<TxValidityArtifact>>` and `block_artifact: Option<ProofEnvelope>` instead of direct `transaction_proofs`, and import resolves proof verification through a registry keyed by `(proof_kind, verifier_profile)` rather than hard-coding raw Plonky3 calls everywhere. The registered adapters are the current shipping `InlineTx` tx-proof family, the experimental `MergeRoot` block artifact, the native `ReceiptRoot` baseline, the warm-store `receipt_accumulation` adapter, and the diagnostic `receipt_arc_whir` adapter that still derives its residual claim from canonical `TxValidityReceipt`s but now requires native `TxLeaf` verification on import. Runtime/network payloads still carry legacy `proof_mode` for compatibility, but new code keys on the neutral tuple, and node authoring now resolves `HEGEMON_BLOCK_PROOF_MODE` aliases immediately into that neutral `(proof_kind, verifier_profile, legacy_mode)` selector before deciding which artifact path to build. The node exposes additive artifact-market RPC surfaces on top of the existing proving path (`prover_listArtifactAnnouncements`, `prover_getCandidateArtifact`) so template builders can discover reusable artifacts without another consensus rewrite. Fee accounting is split deterministically into miner and prover buckets, and block reward minting supports a miner note plus optional prover/artifact note in the same block reward bundle. The node also exposes an additive `prover_*` RPC namespace for open market participation (`prover_getWorkPackage`, `prover_submitWorkResult`, `prover_getWorkStatus`, `prover_getMarketParams`, `prover_getStageWorkPackage`, `prover_submitStageWorkResult`, `prover_getStagePlanStatus`) with coordinator-level payload caps, bounded submissions per package, per-source submission limits, and strict package expiry.

Consensus enforces version rollouts via `VersionSchedule`, a protocol-release structure that records which bindings are allowed at which heights. ZIP-style `VersionProposal`s (see `governance/VERSIONING.md`) specify activation heights, optional retirement heights, and any special upgrade circuits required to migrate notes from a deprecated primitive to a fresh one. The PoW network consults the schedule before accepting a block, so solo miners and pools can mix v1 and v2 proofs during a rollout without coordination beyond rebasing on the canonical chain. When an emergency primitive swap is required, operators follow the runbook in `runbooks/emergency_version_swap.md` to publish an activation proposal, enable the upgrade circuit, and shepherd users through note migrations before the retirement height lands; pools can track adoption by computing per-block version counts from transaction bindings.

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

## 9. Aggregation Runtime Update (February 27, 2026)

When operators explicitly enable the experimental recursive lane, the prover coordinator runs local proving work on a dedicated long-lived worker pool (`hegemon-prover-worker-*`) instead of spawning one-off blocking tasks for each candidate. This keeps thread-local aggregation caches resident on stable worker threads and avoids cache churn under repeated candidate proving.

Aggregation cache prewarm behavior was also tightened for throughput stability:

- `HEGEMON_AGG_PREWARM_MAX_TXS` is now explicit-only (unset means no automatic breadth prewarm expansion on the proving hot path).
- `HEGEMON_AGG_PREWARM_MODE=checkpoint` is the default when warmup targets are derived from a max tx count, using geometric checkpoints (for example `1,2,4,8,...`) instead of linear `1..N`.
- Operators can still request linear warmup with `HEGEMON_AGG_PREWARM_MODE=linear` or explicit shapes with `HEGEMON_AGG_WARMUP_TARGET_SHAPES`.

This preserves fail-closed proof semantics while removing avoidable O(target) recursion-shape churn from live transaction paths.

Two additional liveness hardening changes were added after burst-load failures on sidecar traffic:

- Prover candidate selection now drops proof-sidecar transfers whose ciphertext bytes are not present in the local pending sidecar store. This prevents nodes that did not receive sidecar payload bytes from repeatedly scheduling impossible proof jobs.
- Mining workers now invalidate the active template after any import failure. This avoids hashing the same invalid (stale/mismatched) proof bundle repeatedly and forces fresh template/proof construction on the next round.
