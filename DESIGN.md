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
6. **Secure, seamless, delighting UX**: wallet, release-coordination, and miner/operator touchpoints must keep the PQ stack invisible,
   provide ergonomic flows across devices, and surface positive confirmation cues so users feel safe and delighted without
   facing operational friction.

Everything else is negotiable.

---

### 0.2 Admin posture (production/testnet)

* **No sudo or session pallets** in production/testnet genesis. The PoW chain runs without validator sessions.
* The live chain has no on-chain governance path. Protocol changes ship through socially adopted release lines and PoW uptake, not a built‑in superuser key.

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
* Backup: **SLH-DSA** (SPHINCS+, FIPS 205) for long-lived roots of trust (genesis multisig, release-signing keys, etc.). ([Cloud Security Alliance][3])

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

STARK verifier parameters (hash function choice, query counts, blowup factors, field extension) should be treated as protocol-release parameters, not live runtime knobs. The live transaction-proof family is now also a version-owned protocol parameter: `protocol/versioning` and `runtime/src/manifest.rs` commit the active tx proof backend and any legacy per-backend verifier profiles that still need to be decoded. The active default binding now resolves to `backend = SmallwoodCandidate`. The old Plonky3 line remains explicitly versioned for historical decoding and comparison work, carrying its release FRI profile `(log_blowup = 4, num_queries = 32, query_pow_bits = 0)` on that legacy binding rather than on the active default. The backend seam is real: a tx proof can be wrapped into a native `tx_leaf`, dispatched by backend id, and aggregated without touching the lattice folding layer. The important current caveat is now exactly located. The repo has both:

* a real scalar semantic SmallWood prover over the native tx-validity witness surface, and
* a real packed Rust frontend material builder for the frozen `64`-lane target statement (`raw_witness_len = 3991`, `poseidon_permutation_count = 145`, `expanded_witness_len = 59749`, `lppc_row_count = 934`, `lppc_packing_factor = 64`), and
* a separate live integrated `64`-lane bridge statement that the current backend actually proves (`raw_witness_len = 295`, `poseidon_permutation_count = 143`, `poseidon_state_row_count = 4576`, `expanded_witness_len = 92608`, `lppc_row_count = 1447`, `lppc_packing_factor = 64`).

The SmallWood branch is now past the old scalar fallback and is the repo’s active default transaction-proof family. The Rust engine exposes sparse linear constraints, the active packed semantic bridge over the native witness is real, the packed witness satisfies the LPPC checks, and the integrated prover/verifier roundtrip exists on the live backend seam. The old vendored C bridge is no longer part of the active backend path. The important distinction is now explicit: the failed flat `934 x 64` chunked direct layout is no longer treated as a live proving target on this PCS. Both legacy packed baselines, `Bridge64V1` and `DirectPacked64V1`, still use the same row-aligned `1447`-row local-gate geometry (`raw_witness_len = 295`, `poseidon_permutation_count = 143`, `poseidon_state_row_count = 4576`, `expanded_witness_len = 92608`, `lppc_packing_factor = 64`) because that is the geometry the current row-polynomial PCS can actually prove succinctly. The shipped default is now the leaner compact-binding inline-Merkle branch, `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1`, with `raw_witness_len = 72`, `poseidon_permutation_count = 143`, `poseidon_state_row_count = 4433`, `expanded_witness_len = 76032`, `lppc_row_count = 1188`, and `lppc_packing_factor = 64`. The latest redteam hardening pass added dedicated row-aligned secret rows and sparse public bindings for active output ciphertext hashes plus stablecoin policy version / policy hash / oracle / attestation commitments, so the live SmallWood relation now binds the same public tx-statement fields that the higher-layer receipt hash commits. The latest backend pass then moved the Merkle aggregate helper surface off the opened-row witness and into the inner proof’s auxiliary witness channel, tightened the tx-candidate profile selection so the shipped inline-Merkle line uses the smaller `decs_nb_opened_evals = 23` point while the older Bridge/direct lines stay on `24`, compacted DECS auth paths by omitting sibling hashes that are already opened elsewhere in the same batch, and then replaced the nested inner bincode proof object with a flat compact wire format that writes one checked shape header per section instead of per-row `Vec` length metadata. The engine/native boundary is explicit too: prove, verify, and projected-size calls consume a `SmallwoodConstraintAdapter` statement object instead of raw bridge-layout tuples, so bridge-specific nonlinear assumptions are isolated to one adapter seam. `DirectPacked64V1` is no longer a witness-carrying alternate envelope; it is now a second succinct statement mode on the normal row-scalar PCS/opening path, with the arithmetization tag bound in the proof wrapper but no raw-witness payload and no matrix-opening side payload. Proof-specific verifier-profile digests now hash the actual SmallWood arithmetization tag from the proof wrapper instead of assuming bridge mode, and the version-only helper is now pinned to canonical `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` so the shipped default matches the version-owned receipt profile. Under the current exact no-grinding `128-bit` profile for the shipped default (`rho = 2`, `nb_opened_evals = 3`, `beta = 2`, `decs_nb_evals = 32768`, `decs_nb_opened_evals = 23`, `decs_eta = 3`, zero grinding bits), the shipped structural upper bound now projects in-repo to `90830` bytes, and the checked exact sampled release proofs on the current benchmark witness land in the `87246 .. 87278` byte band. That is about `4.1x` smaller than the legacy `354081`-byte Plonky3 proof, about `13.6%` smaller than the old `100956`-byte bridge baseline, about `11.4% .. 11.5%` smaller than the former `98532`-byte shipped default, and still below the current `524288`-byte native `tx_leaf` cap. The checked profile sweep in `docs/crypto/tx_proof_smallwood_profile_sweep.json` now covers the live bridge, the older compact-binding branch, the former `DirectPacked64CompactBindingsSkipInitialMdsV1` branch, and the shipped `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` default, and it shows that Bridge/direct still prefer the realistic `32768 / 24 / 3` DECS point while the shipped inline-Merkle default now has one smaller realistic passing point at `32768 / 23 / 3`. `Bridge64V1` remains a measured baseline at `100956` bytes. `DirectPacked64CompactBindingsV1` remains a working intermediate branch at `99828` bytes. `DirectPacked64CompactBindingsSkipInitialMdsV1` remains a measured predecessor at `98532` bytes. The shipped default is now `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` with a `90830`-byte structural upper bound and checked exact sampled proofs in the `87246 .. 87278` byte band, with the current sampled size report checked in at `docs/crypto/tx_proof_smallwood_current_size_report.json`. The expensive semantic witness self-check still exists for regression/debug runs and explicit preflight, but the shipped production prover no longer pays that duplicate pass on every wallet send. The repo now also carries a semantic LPPC seam in `circuits/transaction/src/smallwood_lppc_frontend.rs`: it materializes the exact `NativeTxValidityRelation` witness order from `TransactionWitness`, binds the same native statement/public-input digests the shipped tx proof uses, fixes the v1 semantic LPPC window at `4096` elements, and runs those shapes through the current SmallWood structural projection and soundness path. The checked structural frontier in `docs/crypto/tx_proof_smallwood_semantic_lppc_frontier_report.json` is `1024x4=54240`, `512x8=37776`, and `256x16=32712`, all still clearing the no-grinding `128-bit` structural floor. The repo now also has an exact current-engine opening-layer spike over that same witness window in `docs/crypto/tx_proof_smallwood_semantic_lppc_identity_spike_report.json`, and it matches those projected bytes exactly. The full auxiliary-Poseidon fallback is still dead on economics: `docs/crypto/tx_proof_smallwood_semantic_lppc_auxiliary_poseidon_spike_report.json` shows that carrying the whole current Poseidon subtrace as auxiliary witness lands at `472008 .. 493536` bytes, and the exact `512x8` spike now matches that projection after fixing the auxiliary replay bug in the engine. The semantic helper-floor result in `docs/crypto/tx_proof_smallwood_semantic_helper_floor_report.json` still lands at `102120` bytes once lane-visible helper rows come back as explicit opened rows, and the compact helper-aux floor in `docs/crypto/tx_proof_smallwood_semantic_helper_aux_report.json` lands at `94728` bytes. That floor mattered while the shipped line was `98532`; it no longer beats the current shipped line. So the backend picture is sharper again: the current engine already got its real win by moving the helper surface off the opened-row witness inside the shipped bridge statement, tightening the shipped DECS opening count for that one arithmetization, compacting DECS auth paths for overlapping opened leaves, and then flattening the inner proof wire format. Any future semantic-adapter branch now has to beat the `90830`-byte structural upper bound and the `87246 .. 87278` checked exact band, not just the older `98532` object.

The latest runtime/front-end attack therefore was not another loop trick; it combined the smaller `1447`-row bridge, the secure `beta = 2` LVCS geometry, the new `32768 / 24 / 3` DECS point, the earlier preallocated DECS row buffers with thread-local scratch, the proof-object cleanup for explicit arithmetization tags without witness-carrying alternate payloads, and the new public-field binding rows for ciphertext hashes plus stablecoin policy metadata. The verifier also now fail-closes on exact inner proof shapes, requires distinct DECS opening indices, binds the full PCS commitment transcript into the PIOP transcript, hashes full opened combis for the DECS challenge, derives both commitment-time and verifier-time polynomial openings from the exact interpolation domain rather than the earlier broken shortcut helpers, rejects bridge/direct opening-mode mismatches explicitly, rejects wrapper/public-input surface mismatches before replay, and fails closed when a SmallWood wrapper cannot be decoded for arithmetization/profile binding. The public `tx_leaf` bridge now validates the canonical receipt profile it is actually given instead of incorrectly recomputing a bridge-only SmallWood profile from version alone, while the native artifact path still verifies the backend selector and proof bytes directly. So malformed candidate proofs no longer panic the release verifier, forged self-consistent PCS layers are rejected, the implemented query count matches the note, and higher-layer verifier-profile digests can no longer silently alias bridge vs direct SmallWood modes. The branch is therefore no longer blocked on raw proof size, and the realistic no-grinding profile branch now comes back clean: the checked sweep shows no smaller passing point in the tested grid than the active `32768 / 24 / 3` line. The earlier `75 KB .. 121 KB` SmallWood numbers remain a separate structural research target for a future PCS-aware layout change, not the current proving object. The exact current SmallWood profile note lives in `docs/crypto/tx_proof_smallwood_no_grinding_soundness.md`, while the old Plonky3 sweep and soundness note remain checked in under `docs/crypto/tx_proof_profile_sweep.json` and `docs/crypto/tx_proof_soundness_analysis.md` as legacy comparison material. The first conservative STIR replacement spike is also checked in under `docs/crypto/tx_proof_stir_spike.json` / `docs/crypto/tx_proof_stir_soundness.md`; it clears the security gate but only projects to about a `1.30x` total-byte reduction, so it is not currently a sufficient reason to replace even the legacy Plonky3 opening layer on its own. With 384-bit digests, PQ collision resistance reaches ~128 bits for application-level commitments, and 48-byte encodings are used end-to-end.

The hostile proof-surface review also closed the malformed-byte/stale-assumption class that still existed around the shipped SmallWood and recursive lanes. Outer `TransactionProof` wrappers and SmallWood candidate wrappers now exact-consume and require canonical serialization before backend/profile routing; shipped proof carriers (`tx-proof-manifest`, disclosure, batch, block-commitment, and tx-leaf artifacts) now do the same on their trust boundaries; recursive witness reconstruction canonicalizes the compact inner SmallWood proof bytes instead of assuming the retired nested-`bincode` object; recursive prove/verify helpers derive the no-grinding profile from the arithmetization tag; the local recursive verifier accepts the compact DECS auth-path encoding used by the live tx backend; and the outer fixed-width recursive artifact verifier now decodes a canonical compact proof prefix from the padded proof field and requires zero padding after the consumed prefix.

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

  * Proof sizes are materially larger than SNARKs; with 48-byte digests and a 128-bit PQ target, single-transaction Plonky3 proofs are currently hundreds of kB (≈354KB for the active release `TransactionAirP3` e2e profile, with about 349KB of that in the opening layer alone). The first measured conservative STIR spike only projects that down to about 273KB, so the next serious `2x` or `3x` proof-size attempt needs a stronger PCS branch than “swap in STIR and hope.”

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

### 2.6 Aggregation mode (native product lane)

The fresh-chain 0.10.x product path is now a mandatory same-block native recursive aggregation lane for every non-empty shielded block. Wallets submit native `tx_leaf` artifacts in each transfer extrinsic, and block authors must also include the native constant-size `recursive_block` artifact in the same block so import verifies the block through `SelfContainedAggregation` instead of the removed `InlineRequired` product path. On this lane the legacy `commitment_proof` field is required to be empty; consensus derives the semantic tuple directly from the ordered verified `tx_leaf` stream plus parent state and verifies the recursive artifact against that tuple. The older native `receipt_root` object remains available as an explicit compatibility/research lane, not the shipped default.

* Block authors include `pallet_shielded_pool::Call::enable_aggregation_mode` as a mandatory unsigned extrinsic early in every non-empty shielded block.
* A chain-level `ProofAvailabilityPolicy` still has the wire values `InlineRequired` and `SelfContained`, but the fresh-chain product manifest defaults to `SelfContained` and consensus rejects non-empty shielded blocks that try to rely on the legacy inline-required lane.
* The shipped unsigned transfer format remains native `tx_leaf`; there is no product fallback to legacy inline STARK transfer verification.
* Non-empty shielded blocks fail closed unless a ready same-block `submit_candidate_artifact` / `submit_proven_batch` payload carrying the native `recursive_block` artifact is present and valid.
* Authoring pauses on shielded candidates until the prepared native bundle is ready, rather than sealing a hybrid block with `proven_batch: None`.
* Network-originated shielded kernel transfers are quarantined until full native `tx_leaf` artifact verification succeeds; only then do they become relay- and block-eligible. Local RPC submissions keep the direct author-local path.
* The runtime admission cap for native shielded transfer payloads is pegged to the exact live `tx_leaf` artifact envelope, while the inner embedded STARK proof remains separately capped at `512KiB`.
* Proof sidecars (`da_submitProofs`) remain optional off-chain proposer coordination only. They are not part of consensus validity on the product path. The DA staging RPC (`da_submitCiphertexts`, `da_submitProofs`) is unsafe-only and must stay on a trusted local/proposer control plane behind `--rpc-methods=unsafe`; it is not a public submission surface.
* Import verifies the ordered native `tx_leaf` artifacts plus the native `recursive_block` artifact against the block’s canonical `tx_statements_commitment`, state roots, kernel roots, `nullifier_root`, and `da_root` derived from the block body and parent state. It no longer accepts non-empty product blocks that only provide ordered tx artifacts, and it rejects recursive-lane payloads that try to smuggle legacy commitment-proof bytes alongside the constant-size artifact.

This keeps the product path honest: native shielded transactions are now matched by native block verification instead of a hidden inline-required fallback.

---

### 2.7 Experimental post-proof folding stack

For the fresh-chain 0.10.0 line, the shipped shielded path is now native end to end: wallets emit native `tx_leaf` artifact bytes by default, the runtime accepts only that format on the live unsigned transfer path, and every non-empty shielded block must also carry a same-block native `recursive_block` artifact that import verifies through `SelfContainedAggregation`. The repo still carries an additive workspace under `circuits/superneo-*`, but that workspace is now the implementation of the live constant-size block-artifact lane rather than an optional experiment hidden behind an inline-required product fallback.

That stack is intentionally split into a Hegemon-owned relation layer (`superneo-ccs`), a backend trait layer (`superneo-core`), Goldilocks pay-per-bit witness packing (`superneo-ring`), a direct in-repo folding backend (`superneo-backend-lattice`), Hegemon-specific relations (`superneo-hegemon`), and a benchmark CLI (`superneo-bench`). The first real relation is a transaction-proof receipt relation rather than a full transaction AIR port. That is deliberate: any future compression win has to come from a post-proof primitive that sits after tx proving, not from re-running the hot witness path in another proof system.

The current backend is the structural native candidate `goldilocks_128b_structural_commitment`. It is the only in-tree native backend family still treated as live engineering surface. Its manifest-owned parameter set binds the exact transcript domain, challenge schedule, commitment geometry, and spec identity; setup rejects overclaims against the computed security floor; tx-leaf artifacts now carry only the public tx view, serialized STARK public inputs, STARK proof bytes, the derived lattice commitment, and the native leaf proof; and verification fail-closes on mismatched `spec_digest`, malformed public bytes, STARK proof failure, or deterministic commitment mismatch. The live claim for that family is now explicitly tied to the deterministic public-witness commitment path the product actually ships and to an exact bounded-kernel Module-SIS reduction for the implemented bounded live message class plus one explicit coefficient-space Euclidean SIS estimate of that active instance: it counts transcript soundness, the estimator-backed commitment binding floor, and receipt-root composition loss, and it does not count an opening-hiding term from the backend's separate non-product opening API. The exact protocol surface is captured in [docs/crypto/native_backend_spec.md](docs/crypto/native_backend_spec.md), the reduction note lives in [docs/crypto/native_backend_commitment_reduction.md](docs/crypto/native_backend_commitment_reduction.md), the code-derived claim model lives in [docs/crypto/native_backend_security_analysis.md](docs/crypto/native_backend_security_analysis.md), and the reproducible review package remains under [audits/native-backend-128b](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b). The active `v8` spec keeps the `512KiB` native tx-leaf STARK-proof admission cap, exports the theorem-backed `verified_leaf_aggregation` claim, and keeps the external-review surface tied to the packaged claim bundle rather than to repo-local prose. Historical hardening and closure plans were moved under [.agent/archive/proof-history](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/archive/proof-history) so the active repo surface does not advertise killed baselines as current product work.

On the product side, authoring now treats the tree-reduced `recursive_block_v2` build as the default same-block lane. The builder consumes the ordered verified native `tx_leaf` records, derives the semantic tuple directly from parent state plus canonical tx order, and emits one padded `recursive_block_v2` artifact with empty legacy `commitment_proof` bytes. A current diagnostic report makes the old limitation explicit instead of pretending otherwise: the legacy `recursive_block_v1` envelope width of `699,404` bytes is only validated through the first `StepA` terminal (`2` shielded tx on the current linear chain). The current backend projects `BaseA = 41,371`, first `StepB = 162,763`, first `StepA = 561,075`, and steady-state `StepB = 1,868,811`, so `v1` is not a true general constant-size recursive lane on the current backend and is now legacy-only. The explicit native `receipt_root` lane remains available behind mode selection as a compatibility/research surface; that builder still uses deterministic `8`-leaf mini-roots, verified-leaf reuse, cached chunk folds keyed by native artifact identity, and a dedicated local Rayon pool sized by `HEGEMON_RECEIPT_ROOT_WORKERS`. Native `tx_leaf` artifacts now also carry an explicit tx-proof-backend selector byte after the embedded proof payload so the verifier can dispatch cleanly between proof families while keeping the lattice folding layer unchanged. The new `SmallwoodCandidate` backend already uses that seam: a candidate tx proof can be wrapped into a native `tx_leaf`, verified independently, and then fed into either the shipped `v2` recursive lane, the legacy `v1` compatibility lane, or the explicit receipt-root compatibility lane. The tree-reduced `recursive_block_v2` lane now owns the actual bounded-domain invariant: its verifier exact-decodes the canonical compact proof prefix from the padded proof field before checking the tree relation, it uses `TREE_RECURSIVE_CHUNK_SIZE_V2 = 1000`, it supports at most `1000` txs per recursive artifact version, and the current derived fixed artifact size is `522,159` bytes. That point wins because the bounded domain collapses the tree to a single chunk relation instead of paying an extra merge level, while still staying inside the same `v2` public artifact and verification contract. That is the shipped constant-size recursive block lane on the current backend.

Import also no longer pays the native leaf verifier twice by default. Consensus derives verified native leaf records while checking the ordered `tx_leaf` artifacts, and both the shipped recursive verifier and the explicit receipt-root verifier consume that verified stream instead of re-running the leaf verifier. The older replay-heavy root verifier remains in-tree as a diagnostic and cross-check lane, not as the default product verifier.

The experimental relation layer is now deliberately narrow. `TxLeafPublicRelation` remains the bridge/comparison relation over nullifiers, commitments, ciphertext hashes, balance tag, version binding, and serialized STARK public inputs. `NativeTxValidityRelation` remains the witness-driven source relation: it consumes `TransactionWitness` directly, checks witness validation plus Merkle membership locally, derives the canonical public-input object without going through a Plonky3 proof, and feeds the native `TxLeaf` baselines that back both the shipped recursive lane and the explicit receipt-root compatibility lane. The explicit node/consensus research surface is now only that alternate native `ReceiptRoot` baseline. The old warm-store accumulation and residual ARC/WHIR lanes were removed from product routing, consensus verification, and operator selection after they failed the cold-import goal. The proof-carrying wrapper surfaces are now fail-closed too: SmallWood candidate wrappers and legacy inline `TransactionProof` artifacts must exact-consume and reserialize canonically before any verifier-profile or proof-body routing happens, and recursive block witness reconstruction now canonicalizes the compact SmallWood inner proof bytes instead of assuming the retired nested-`bincode` proof object.

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
  Shielded transfer `fee` values are interpreted as optional miner tips, so `fee = 0` remains valid and any provided tip is paid
  to the miner through the shielded coinbase note rather than a transparent balance credit. Nodes update the running
  `supply_digest = parent_digest + minted + fees − burns` inside a 128-bit little-endian counter that
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

Concrete modules in the repository now reflect the cleaned split. A dedicated `state/merkle` crate maintains the append-only commitment tree with Poseidon-style hashing, `circuits/block-recursion` owns the shipped constant-size recursive block artifact, and `circuits/block` now remains only for the explicit parent-bound `ReceiptRoot` compatibility lane. The shipped fresh-chain 0.10.0 path is simpler: ordered native `TxLeaf` artifacts are the only shielded transaction-validity bytes wallets submit by default, block import verifies that ordered artifact stream plus the constant-size recursive block artifact, and the node’s prove-ahead coordinator prepares either recursive bundles or explicit native `ReceiptRoot` bundles depending on the selected native lane. The coordinator keeps a bounded local worker queue, exact proof-lane identity on prepared-bundle lookup, deterministic candidate upsizing, and bounded stale-parent reuse for cache amortization, but it no longer publishes external work packages, dead recursive-stage placeholders, or accepts unverified remote prepared-bundle imports into the authoring cache.

Block-proof compatibility is still hard-cut to `BlockProofBundle` schema `2` with proof format id `5`, and import still fail-closes on legacy payloads. But the product meaning of those compatibility fields is now narrow: `RecursiveBlock` is the shipped constant-size block-artifact mode, `ReceiptRoot` is the explicit native compatibility/research block artifact, and `InlineTx` survives only as historical vocabulary for archived tests and metrics. The old recursive `MergeRoot`, manifest-style `FlatBatches`, warm-store accumulation wrapper, and residual ARC/WHIR block lanes are gone from consensus, node routing, tests, and operator selectors. The node still exposes additive local artifact-market RPC surfaces (`prover_listArtifactAnnouncements`, `prover_getCandidateArtifact`) so builders can discover reusable prepared artifacts without another consensus rewrite, but the old external prover-worker market surface was deleted with the dead proof lanes and remote artifact-protocol responses are no longer admitted into the local prepared cache.

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

## 9. Native Artifact Preparation Runtime Update (April 5, 2026)

The product no longer carries an external prover-worker market. For the fresh-chain 0.10.x line, the shipped shielded path is the same-block native `tx_leaf -> recursive_block` lane, and the prover coordinator prepares that block artifact on a dedicated long-lived local worker pool (`hegemon-artifact-worker-*`) instead of spawning one-off blocking tasks for each candidate.

Recursive-block authoring is now the default product path. The node derives the semantic tuple directly from the ordered verified-leaf stream plus parent state, emits a constant-size `recursive_block` artifact, and keeps the legacy `commitment_proof` bytes empty on that lane. Receipt-root authoring remains hierarchy-aware on the explicit alternate native lane: the node plans deterministic `8`-leaf mini-roots, the circuit builder reuses verified-leaf and chunk-fold caches keyed by native artifact identity, and the aggregation stage can run on a dedicated Rayon pool sized by `HEGEMON_RECEIPT_ROOT_WORKERS` (falling back to the local artifact-worker count). The coarse prove-ahead prepared-bundle cache still serves exact repeats, while the lower-level leaf/chunk caches make one-leaf and near-repeat rebuilds materially cheaper without changing consensus semantics.

Artifact preparation is now bounded to the only product-relevant choice:

- shipped and enforced path: `HEGEMON_BLOCK_PROOF_MODE=recursive_block`
- explicit alternate native lane: `HEGEMON_BLOCK_PROOF_MODE=receipt_root`

Unknown proof-mode values now clamp back to the canonical native recursive selector instead of reviving removed lanes. The old recursive `MergeRoot`, manifest-style `FlatBatches`, warm-store accumulation wrapper, and residual ARC/WHIR path are gone from live routing, tests, and operator selectors.

Import was hardened in parallel with authoring. Non-empty shielded blocks now fail closed unless they carry a canonical native `recursive_block` payload with empty `commitment_proof` bytes, and the verifier derives the recursive semantic tuple directly from the verified native leaf records already produced during tx-artifact validation plus the parent state and block body. The older `receipt_root` verifier remains available on its explicit alternate lane, and its default path still consumes the already verified leaf records (`verified_records`) rather than replaying the full leaf verifier a second time. Replay-heavy root verification remains available as a diagnostic cross-check path for that alternate lane.

Two liveness hardening changes remain relevant after the purge:

- Candidate selection drops proof-sidecar transfers whose ciphertext bytes are not present in the local pending sidecar store. This prevents nodes that did not receive sidecar payload bytes from repeatedly scheduling impossible preparation jobs.
- Mining workers invalidate the active template after any import failure. This avoids hashing the same invalid stale artifact repeatedly and forces fresh template construction on the next round.
