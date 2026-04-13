# Constant-Size Recursive Block Proof

This note states the construction at theorem level and fixes the points raised by hostile review. It now distinguishes the current block semantics from the current proof-visible auxiliaries, specifies the internal sparse nullifier set exactly, maps the design onto concrete SuperNeo relation objects, repairs the root-only soundness hole by exposing constant-size append-state digests, replaces the old self-referential segment-proof sketch with a SuperNeo accumulator/decider construction that does not require a hidden `N_max` cap, and states the exact strengthened recursive backend construction the repo still lacks. The acceptable outcomes remain binary: either future code realizes the object below, or the claim "Hegemon has a constant-size recursive block proof" is false.

The visual blackboards live in [docs/assets/constant-recursive-block-proof-blackboards.svg](/Users/pldd/Projects/Reflexivity/Hegemon/docs/assets/constant-recursive-block-proof-blackboards.svg). The implementation plan lives in [.agent/CONSTANT_SIZE_RECURSIVE_BLOCK_PROOF_EXECPLAN.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/CONSTANT_SIZE_RECURSIVE_BLOCK_PROOF_EXECPLAN.md).

## 1. Hard Invariant

Let `B = (tx_1, ..., tx_n)` be any non-empty shielded block accepted by consensus under one fixed protocol line, and let `Pi_block(B)` be the proof artifact shipped on chain for that block.

The hard invariant is:

1. There exists one constant `C_block` such that `|Pi_block(B)| = C_block` for every admissible `n`.
2. The verifier-facing public tuple has constant arity and constant serialized length.
3. The serialized artifact contains no linear payloads: no per-transaction proof bytes, no per-transaction public inputs, no `packed_public_values`, no representative child proofs, no nullifier vectors, no sorted-nullifier vectors, and no `receipt_root` record lists.
4. Acceptance of the full verifier implies the real block truth surface:
   - every included transaction proof is valid;
   - the ordered transaction statement hashes absorb to the published `tx_statements_commitment`;
   - the append-only commitment-tree state evolves from the parent state to the child state by appending the block commitments in order;
   - every transaction anchor is a member of the bounded accepted-root history at the point where that transaction is processed;
   - every non-zero nullifier is unique within the block.
5. The recursive product path preserves the current block semantics exactly:
   - `tx_statements_commitment`,
   - `starting_state_root`,
   - `ending_state_root`,
   - `starting_kernel_root`,
   - `ending_kernel_root`,
   - `nullifier_root`,
   - `da_root`,
   - `tx_count`.
6. Any extra recursive-proof-visible coordinates must be:
   - constant-size;
   - recomputable by consensus from the parent state, block body, and the externally verified tx-artifact stream that current import already derives before checking the block artifact;
   - semantically inert auxiliaries rather than replacements for the tuple above.

This invariant says nothing about prover time. Prover work may grow linearly with `n`. Only the shipped artifact and its public tuple must stay constant-size.

## 2. Fixed Repo Semantics

The construction below is pinned to the current repo semantics, not to an abstract privacy pool.

### 2.1 Constants

Let:

- `F` be the Goldilocks field.
- `C = {0,1}^384` be the 48-byte commitment/nullifier/root encoding space.
- `M_in = 2` be the maximum nullifiers per transaction.
- `M_out = 2` be the maximum commitments per transaction.
- `D = 32` be the shielded commitment-tree depth.
- `H = 100` be the bounded accepted-root history limit.
- `BAL = 4 = MAX_INPUTS + MAX_OUTPUTS` be the fixed number of balance slots.
- `w = 12` and `r = 6` be the Poseidon2 width and rate used by the current statement-commitment sponge.

These are live repo constants in:

- [circuits/transaction-core/src/constants.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction-core/src/constants.rs)
- [consensus/src/commitment_tree.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/commitment_tree.rs)

### 2.2 Transaction statement hash

For transaction public inputs `P`, define the statement hash `H_stmt(P) in C` exactly as the current code does:

`H_stmt(P) = BLAKE3-384("tx-statement-v1" || merkle_root || nf_1 || nf_2 || cm_1 || cm_2 || ct_1 || ct_2 || native_fee || value_balance || balance_tag || circuit_version || crypto_suite || stable_enabled || stable_asset_id || stable_policy_hash || stable_oracle_commitment || stable_attestation_commitment || stable_issuance_delta || stable_policy_version)`

This is the formula in [circuits/transaction/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs#L157).

### 2.3 Statement-commitment sponge

Let `enc: C -> F^6` be the canonical 48-byte-to-six-field map already used in the block commitment prover. Let `iota: F^6 -> F^12` inject into the first six coordinates and set the last six coordinates to zero. Let `P2: F^12 -> F^12` be one full Poseidon2 permutation under the live parameters. Let `d_stmt` be the block-commitment domain tag.

Define:

`tau_0 = (d_stmt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) in F^12`

and for ordered transactions `tx_1, ..., tx_n` with public inputs `P_1, ..., P_n`,

`tau_i = P2(tau_{i-1} + iota(enc(H_stmt(P_i))))`

for `1 <= i <= n`, and

`C_stmt(B) = proj_6(tau_n) in C`

where `proj_6` returns the first six field elements re-encoded to 48 bytes.

This is algebraically equivalent to the current sequential Poseidon2 absorption in [circuits/block/src/p3_commitment_prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block/src/p3_commitment_prover.rs#L150).

### 2.4 Commitment-tree append state

Define the raw append state as:

`T = (ell, root, F_frontier, m, R_hist)`

with:

- `ell in {0, ..., 2^D - 1}` the current leaf count,
- `root in C` the current tree root,
- `F_frontier = (f_0, ..., f_{D-1}) in C^D` the Merkle frontier,
- `m in {1, ..., H}` the number of valid history entries,
- `R_hist = (r_0, ..., r_{H-1}) in C^H` the ordered accepted-root history buffer, zero-padded after index `m - 1`.

The append transition is exactly [consensus/src/commitment_tree.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/commitment_tree.rs#L72):

- append the non-zero commitments of `tx` in order;
- update frontier nodes according to the parity bits of `ell`;
- update `root`;
- increment `ell`;
- record the new root into the bounded history deque and truncate to the last `H` roots.

Write that deterministic transition as:

`T' = Append*(T, tx)`

### 2.5 Current semantic tuple, external verified-leaf stream, and recursive proof-visible auxiliaries

The current block semantics are captured by the fixed semantic tuple:

`Y_sem(B) = (n, C_stmt(B), root_prev(B), root_new(B), kernel_prev(B), kernel_new(B), nullifier_root(B), da_root(B))`

with exact meanings:

- `n = tx_count(B)`;
- `C_stmt(B) = tx_statements_commitment(B)`;
- `root_prev(B)` is the parent shielded commitment-tree root;
- `root_new(B)` is the post-block shielded commitment-tree root;
- `kernel_prev(B) = kernel_root_from_shielded_root(root_prev(B))`;
- `kernel_new(B) = kernel_root_from_shielded_root(root_new(B))`;
- `nullifier_root(B) = BLAKE3-384(concat(sort_unique(NZ_nf(tx_1), ..., NZ_nf(tx_n))))`, exactly as [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L1768) computes it;
- `da_root(B)` is the current deterministic DA-root reconstruction over the block body, exactly as [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L685) checks it.

Its serialized length is:

- `4` bytes for `n` as `u32`,
- `7 * 48 = 336` bytes for the seven 48-byte roots and commitments,
- total `340` bytes.

The current Plonky3 commitment proof exposes a larger proof-visible object:

`Y_p3(B) = (Y_sem(B), alpha_perm(B), beta_perm(B), N(B), Sort(N(B)))`

where:

- `N(B)` is the transaction-ordered padded nullifier list of length `n * M_in`;
- `Sort(N(B))` is its sorted copy;
- `alpha_perm(B), beta_perm(B)` are Plonky3 permutation auxiliaries derived by [circuits/block/src/p3_commitment_verifier.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/block/src/p3_commitment_verifier.rs#L58).

Those extra coordinates are proof-system auxiliaries, not additional block semantics.

The live product boundary matters here. On the current shipped path, consensus first verifies each ordered tx-validity artifact and derives one ordered verified-leaf stream before it touches the block artifact. Write that stream as:

`L(B) = (L_1, ..., L_n)`

with

`L_i = (R_i, V_i, Xi_i)`

where:

- `R_i = (statement_hash_i, proof_digest_i, public_inputs_digest_i, verifier_profile_i)` is the canonical receipt object `CanonicalTxValidityReceipt`;
- `V_i` is the fixed public tx view `TxLeafPublicTx = (nullifiers_i, commitments_i, ciphertext_hashes_i, balance_tag_i, version_i)`;
- `Xi_i` is the fixed serialized STARK public-input object `SerializedStarkInputs`.

This is the output of the current per-transaction tx-artifact verification stage described in [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md#L902) and implemented through [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L364) plus [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L3167). The recursive block proof replaces the current linear `receipt_root` block artifact. It does not replace the external tx-artifact verifier.

The recursive path cannot get away with publishing only `Y_sem(B)`. Three extra constant-size bindings are needed:

1. exact append-state binding, because anchor admissibility depends on the full frontier/history state, not only on start/end roots;
2. exact verified-leaf-stream binding, because the current product accepts a block only after it has checked one specific ordered receipt/tx-view stream against the block’s tx artifacts;
3. exact receipt-stream binding, because the current product’s block-artifact truth surface is still phrased in terms of canonical ordered tx-validity receipts.

So the recursive proof-visible tuple is:

`Y_rec(B) = (Y_sem(B), C_leaf(B), C_receipt(B), Sigma_tree(T_0), Sigma_tree(T_n))`

where:

- `C_leaf(B)` is the constant-size Poseidon2 commitment to the exact ordered verified-leaf stream from Section 2.7;
- `C_receipt(B)` is the constant-size Poseidon2 commitment to the ordered verified receipt list from Section 2.7;
- `C_receipt(B)` is retained even though `C_leaf(B)` already binds the receipt fields, because the current product already treats the canonical receipt stream as a first-class block-artifact truth surface and `C_receipt(B)` is the direct constant-size replacement for the current linear `receipt_root` payload;
- `T_0` is the exact pre-block append state reconstructed from the parent state;
- `T_n` is the exact post-block append state obtained by deterministic append replay;
- `Sigma_tree(T)` is the six-field Poseidon2 digest from Section 3.3.

This adds four constant-size auxiliaries:

- `C_leaf(B)` serialized as `6 * 8 = 48` bytes;
- `C_receipt(B)` serialized as `6 * 8 = 48` bytes;
- `Sigma_tree(T_0)` serialized as `6 * 8 = 48` bytes;
- `Sigma_tree(T_n)` serialized as `6 * 8 = 48` bytes.

Therefore:

- `|Y_sem(B)| = 340` bytes;
- `|Y_rec(B)| = 340 + 48 + 48 + 48 + 48 = 532` bytes.

This is the honest split:

- `Y_sem(B)` preserves the current block semantics exactly;
- `Y_rec(B)` is the recursive proof-visible tuple;
- `(alpha_perm, beta_perm)` are correctly demoted to proof-system auxiliaries of the current Plonky3 proof surface;
- `C_leaf(B)` binds the exact ordered verified-leaf stream `L(B)` without forcing BLAKE3 into recursive arithmetic;
- `C_receipt(B)` is the constant-size replacement for the current linear receipt-root payload;
- `Sigma_tree(T_0)` / `Sigma_tree(T_n)` bind the exact append state rather than only the exposed roots.

### 2.6 Hash boundary

The corrected split is:

1. `BLAKE3-384` remains the hash for existing external semantics:
   - `H_stmt(P)`;
   - canonical receipt fields `proof_digest` and `public_inputs_digest`;
   - `nullifier_root(B)`;
   - `da_root(B)`;
   - legacy byte-oriented `statement_digest = digest_statement(serialized_public_statement)` where current artifact formats still use it.
2. `Poseidon2` is the only hash used inside recursive arithmetic for:
   - the verified-leaf-stream commitment `C_leaf(B)`;
   - the receipt commitment `C_receipt(B)`;
   - hidden state binding;
   - internal nullifier-set updates;
   - recursive Fiat-Shamir transcript derivation;
   - field-native statement commitments for the recursive step relation and its terminal decider.
3. The recursive step relation and terminal decider path do not arithmetize BLAKE3. They consume the already verified external verified-leaf stream `L(B)` and use Poseidon2 only for constant-size recursive commitments to that stream.
4. Consensus continues to recompute `nullifier_root(B)`, `da_root(B)`, kernel roots, and the ordered receipt stream outside the recursive proof and reject mismatches exactly as it does on the current path.

This split is mandatory. Any design that requires the recursive step/seal verifier to recompute a BLAKE3 statement hash, BLAKE3 receipt digest, or BLAKE3 Fiat-Shamir transcript inside recursion is fake until the corresponding arithmetic gadget exists.

### 2.7 Exact verified-leaf-stream commitment

The critical repair for the hostile review is this: the recursive state machine must bind the exact ordered verified-leaf stream `L(B)`, not only the ordered receipt substream. That binding cannot honestly come from in-relation BLAKE3 recomputation, so it is carried by one additional Poseidon2 commitment over the exact fixed-width canonical leaf encoding already used by the `TxLeafPublicRelation` seam.

For one transaction index `i`, define the exact canonical field encoding

`pack_L(L_i) in F^114`

to be the concatenation of:

1. the 24-limb receipt public statement encoding for `R_i`;
2. the 90-limb tx/stark witness assignment for `(V_i, Xi_i)`;

using exactly the current `TxLeafPublicRelation` encoding surface described in Section 4.3.

Define the verified-leaf sponge state:

`lambda_0 = (d_leaf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) in F^12`

and define `AbsorbLeaf(lambda_{i-1}, L_i)` to be the 19-step rate-6 Poseidon2 absorption of `pack_L(L_i) in F^114`.

Then:

- `lambda_i = AbsorbLeaf(lambda_{i-1}, L_i)`;
- `C_leaf(B) = proj_6(lambda_n) in C`.

Outer consensus recomputes `C_leaf(B)` from the exact ordered verified-leaf stream `L(B)` already produced by the live tx-artifact verifier and rejects any mismatch. This is the extra constant-size binding that closes the old "receipt stream bound, tx/stark witness stream underbound" hole.

### 2.8 Exact receipt commitment

Write the canonical receipt

`R_i = (h_i, p_i, d_i, rho_i)`

with:

- `h_i = statement_hash_i in C`;
- `p_i = proof_digest_i in C`;
- `d_i = public_inputs_digest_i in C`;
- `rho_i = verifier_profile_i in C`.

Define the canonical field packing:

`pack_R(R_i) = pack_C(h_i) || pack_C(p_i) || pack_C(d_i) || pack_C(rho_i) in F^24`

Define the receipt-sponge state:

`eta_0 = (d_receipt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) in F^12`

and the four-absorb receipt update:

- `eta_i^(0) = eta_{i-1}`
- `eta_i^(1) = P2(eta_i^(0) + iota(pack_C(h_i)))`
- `eta_i^(2) = P2(eta_i^(1) + iota(pack_C(p_i)))`
- `eta_i^(3) = P2(eta_i^(2) + iota(pack_C(d_i)))`
- `eta_i = P2(eta_i^(3) + iota(pack_C(rho_i)))`

Then define the constant-size verified-receipt commitment:

`C_receipt(B) = proj_6(eta_n) in C`

Outer consensus recomputes `C_receipt(B)` from the ordered verified receipt list `R_1, ..., R_n` produced by the existing tx-artifact verifier and rejects any mismatch. This is the exact constant-size object that replaces the current linear receipt-root payload.

### 2.9 Exact internal sparse nullifier set

The current public `nullifier_root(B)` stays unchanged. Inside recursion, uniqueness is enforced with an internal Poseidon sparse set keyed by the nullifier bits.

Define the key bits of `nf in C` by big-endian bit order:

`bit_j(nf) = ((nf[floor(j / 8)] >> (7 - (j mod 8))) mod 2)` for `0 <= j < 384`

Define a 48-byte Poseidon hash output helper:

`P2Hash_C(tag; x_1, ..., x_k) = proj_6(P2Hash_F(tag; x_1, ..., x_k)) in C`

where `P2Hash_F` is the Poseidon2 sponge over `F` with width `12`, rate `6`, initial state `(tag, 0, ..., 0, 1)`, and sequential absorption of the field elements `x_1, ..., x_k`.

Define the leaf values:

- absent leaf `z_0 = 0^48`;
- present leaf `o_0 = P2Hash_C(d_nf_present; 1)`.

Define the internal node hash:

`Node(l, r) = merkle_node_bytes(l, r)`

using exactly the current Poseidon2 Merkle node hash from [circuits/transaction-core/src/hashing_pq.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction-core/src/hashing_pq.rs#L98).

Define the empty-subtree defaults:

- `z_h in C` for `0 <= h <= 384`,
- `z_{h+1} = Node(z_h, z_h)`.

Define a sparse Merkle path witness for one nullifier as:

`W_nf = (s_0, ..., s_383) in C^384`

listed from leaf level to root level.

Given `nf`, `leaf in C`, and witness `W_nf`, define:

- `x_0 = leaf`;
- for `0 <= j < 384`,
  - if `bit_j(nf) = 0`, set `x_{j+1} = Node(x_j, s_j)`;
  - if `bit_j(nf) = 1`, set `x_{j+1} = Node(s_j, x_j)`.

Then:

`PathRoot(nf, leaf, W_nf) = x_384`

Define non-membership and insertion exactly by:

- `NonMember(U, nf, W_nf)` iff `PathRoot(nf, z_0, W_nf) = U`;
- `InsertRoot(U, nf, W_nf) = PathRoot(nf, o_0, W_nf)` when `NonMember(U, nf, W_nf)` holds.

For one transaction with nullifiers `(nf_1, nf_2)`, define `NZ_nf(tx)` to be the subsequence of non-zero nullifiers. Then:

`Insert*(U, tx) = Fold(InsertRoot, U, NZ_nf(tx))`

with the two path witnesses applied sequentially. If `nf_1 = nf_2 != 0`, the second non-membership witness fails against the updated root.

For public deterministic replay, define the canonical sparse-set root of any finite set `X subseteq C \ {0^48}` by the full sparse-tree leaf assignment

- `Leaf_X(nf) = o_0` if `nf in X`,
- `Leaf_X(nf) = z_0` otherwise,

and recursive bottom-up node rule `Node(l, r)` over depth `384`. Write the resulting unique root as:

`SparseSetRoot(X) in C`

Then for any duplicate-free ordered insertion stream of non-zero nullifiers starting from `U_0 = z_384`,

`Fold(InsertRoot, z_384, X_ordered) = SparseSetRoot(Set(X_ordered))`

where `Set(X_ordered)` is the underlying set of inserted non-zero nullifiers. The outer verifier therefore does not need sparse Merkle witnesses: it checks public duplicate-freedom directly and then computes

`U_pub(B) = SparseSetRoot(Set(NZ_nf(tx_1), ..., NZ_nf(tx_n)))`

from the ordered verified tx views alone.

## 3. Internal Recursive State

### 3.1 Raw state

After processing `i` verified leaves, define the raw recursive state:

`S_i = (i, lambda_i, tau_i, eta_i, T_i, U_i)`

with:

- `i` the processed verified-leaf count;
- `lambda_i in F^12` the exact verified-leaf-stream sponge state after leaf `i`;
- `tau_i in F^12` the exact statement-sponge state after transaction `i`;
- `eta_i in F^12` the exact receipt-sponge state after receipt `i`;
- `T_i` the full append-state tuple from Section 2.4;
- `U_i in C` the internal sparse-set root from Section 2.9.

Base state:

- `S_0 = (0, lambda_0, tau_0, eta_0, T_0, U_0)`;
- `T_0` is the canonical append state before the block starts;
- `U_0 = z_384`.

### 3.2 Exact fixed limb counts

Write every 48-byte element of `C` as six Goldilocks limbs via the canonical `bytes48 -> F^6` map.

Then:

- one append state `T_i` occupies
  - `1` limb for `ell`,
  - `6` limbs for `root`,
  - `32 * 6 = 192` limbs for the frontier,
  - `1` limb for `m`,
  - `100 * 6 = 600` limbs for the history buffer,
  - total `800` limbs;
- one full recursive state `S_i` occupies
  - `1` limb for `i`,
  - `12` limbs for `lambda_i`,
  - `12` limbs for `tau_i`,
  - `12` limbs for `eta_i`,
  - `800` limbs for `T_i`,
  - `6` limbs for `U_i`,
  - total `843` limbs.

One two-nullifier sparse-set witness occupies:

- `2 * 384 * 6 = 4608` sibling limbs,
- plus at most two non-zero flags.

Those exact counts matter because they make the one-step transition relation fixed-shape instead of aspirationally fixed-shape.

### 3.3 Internal state digests

Let `pack_C: C -> F^6` be the canonical 48-byte-to-six-field map.

Define the internal tree digest:

`Sigma_tree(T) = P2Hash_F(d_tree; ell, pack_C(root), pack_C(f_0), ..., pack_C(f_{D-1}), m, pack_C(r_0), ..., pack_C(r_{H-1})) in F^6`

Define the internal recursive-state digest:

`Sigma_state(S) = P2Hash_F(d_state; i, lambda_i, tau_i, eta_i, Sigma_tree(T_i), pack_C(U_i)) in F^6`

These are not consensus-visible outputs. They are the six-limb fixed-size handles threaded through recursion.

## 4. Concrete SuperNeo Objects

### 4.1 Fixed protocol line and product boundary

Fix one protocol line:

- `v* = SMALLWOOD_CANDIDATE_VERSION_BINDING = (CIRCUIT_V2, CRYPTO_SUITE_BETA)`;
- `b* = tx_proof_backend_for_version(v*) = SmallwoodCandidate`;
- `a* = SmallwoodArithmetization::Bridge64V1`;
- `rho_leaf* = experimental_native_tx_leaf_verifier_profile_for_params(native_backend_params())`.

This is the live default line today in:

- [protocol/versioning/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/protocol/versioning/src/lib.rs#L174)
- [circuits/transaction/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs#L227)

The recursive construction is for one fixed protocol line. Any change to version, tx backend, tx-leaf verifier profile, or Smallwood arithmetization creates a new recursive relation id, new shape digest, and new verification key.

The product boundary is explicit:

- ordered tx artifacts are still individually verified outside the recursive block proof;
- the recursive block proof consumes the ordered verified-leaf stream `L(B)`;
- on the recursive product lane, the recursive block proof is the one constant-size replacement for the current block-level pair `(commitment proof, receipt_root)`, not a replacement for the tx-artifact verifier.

### 4.2 The exact strengthened backend object required

The repo does not currently have the following object. The corrected recursive backend is not "a CCS relation that verifies child proofs of itself inside the same CCS shape," and it is not a homegrown accumulator invented in this note. The hard step should be a direct instantiation of the CCS folding line introduced in HyperNova and adapted to the lattice setting in Neo:

- CCS gives the fixed relation structure for one compiled step relation;
- HyperNova gives the `RCCCS x RLCCCS -> RLCCCS` folding object for CCS over additively homomorphic commitments;
- Neo adapts that object to pay-per-bit Ajtai commitments over a small prime field and explicitly pushes the decomposition reduction onto the running instance-witness pair only.

Primary sources:

- HyperNova: <https://eprint.iacr.org/2023/573>
- Neo: <https://eprint.iacr.org/2025/294>

In the notation of this note, the missing object is a SuperNeo-style accumulator/decider backend:

`RecursiveBackend_v2(v*) = (Setup_step, InitAccumulator_step, Reduce_step_to_me, Fold_me, Normalize_me, Prove_decide_step, Verify_decide_step)`

with:

- one fixed CCS relation `BlockStepRelation_v*`;
- one fixed-size running accumulator `Accumulator_step(v*)` made of low-norm linearized committed CCS instances.

For every exact or relaxed carrier on this path, use one common column order

`z = (w, s, x)`

where `w` is the witness block, `s` is the scalar slot, and `x` is the public-input block. The exact committed CCS claim uses `s = 1`; the running linearized committed CCS carrier uses `s = u`, the relaxation scalar.

For the fixed step relation let:

- `shape_step(v*) = CompileCCS(C_step(v*))`;
- `x_step` be the fixed public statement vector;
- `w_step` be the fixed witness vector;
- `z_step = (w_step, 1, x_step)` padded to length `N_step = 2^{ell_step}`.

Write the compiled CCS instance for `shape_step(v*)` as fixed sparse matrices

`M_{step,1}, ..., M_{step,t_step}`

and fixed selector tuples

`(c_{step,q}, S_{step,q})` for `1 <= q <= Q_step`

so relation satisfaction is:

`H_step(b; z_step) = sum_{q=1}^{Q_step} c_{step,q} * prod_{j in S_{step,q}} (M_{step,j} z_step)_b = 0`

for every Boolean row index `b in {0,1}^{ell_step}`.

Now define the structured step summary for any `0 <= a <= b`:

`Q[a,b] = (m[a,b], sigma_a, sigma_b)`

with:

- `m[a,b] = b - a in {0, ..., 2^32 - 1}`;
- `sigma_a = Sigma_state(S_a) in F^6`;
- `sigma_b = Sigma_state(S_b) in F^6`.

The summary composition law is:

`Compose((m_1, sigma_0, sigma_1), (m_2, sigma_1, sigma_2)) = (m_1 + m_2, sigma_0, sigma_2)`

This law is defined for every adjacent pair of summaries whose count sum still fits the live `u32` transaction-count encoding already present in `Y_sem(B)`. There is no extra proof-system `N_max`, no padded empty suffix, and no consensus cap introduced just to make recursion work.

Write the explicit compatibility predicate

`ComposeCheck((m_1, sigma_0, sigma_1), (m_2, sigma_1', sigma_2), (m_3, sigma_0', sigma_2')) = 1`

iff all of the following hold:

- `sigma_1 = sigma_1'`;
- `m_3 = m_1 + m_2`;
- `sigma_0' = sigma_0`;
- `sigma_2' = sigma_2`.

For the unary path in this note, `Q_i = (1, Sigma_state(S_{i-1}), Sigma_state(S_i))`, so

`ComposeCheck(Q_pref[i - 1], Q_i, Q_pref[i]) = 1`

is exactly the deterministic law

- `i = (i - 1) + 1`;
- the prefix start digest stays `Sigma_state(S_0)`;
- the prefix end digest becomes `Sigma_state(S_i)`;
- the shared midpoint digest is `Sigma_state(S_{i-1})`.

The previous draft tried to invent a local accumulator over arbitrary affine verifier systems. That was the mathematical bug. The hard step should instead use the exact `CCCS` / `LCCCS` object from HyperNova/Neo on the fixed CCS structure above.

Write:

- `CCCS_step(Q)` for the exact committed CCS claim corresponding to one step statement `Q`;
- `LCCCS_step(Q_pref)` for the running linearized committed CCS claim corresponding to one prefix summary `Q_pref`.

The local backend names in this note are only aliases for the paper objects:

- `Reduce_step_to_me := Pi_CCS`, the CCS-to-linearized-CCS reduction;
- `Fold_me := Pi_RLC`, the random-linear-combination folding step;
- `Normalize_me := Pi_DEC`, the decomposition reduction that restores the bounded running message class after folding.

### 4.2.1 Ambient commitment module and low-norm class

The linear-homomorphic commitment is not over abstract field vectors. It is the active pay-per-bit Ajtai-style matrix commitment already implemented in `superneo-backend-lattice`.

Fix the active ring/module parameters from the native backend line:

- `q = 2^64 - 2^32 + 1`;
- `R_q = Z_q[X] / (X^54 + X^27 + 1)`, the active `GoldilocksFrog` quotient from [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md#L228);
- `digit_bits = 8`;
- `max_commitment_message_ring_elems = 76`;
- `opening_randomness_bits = 256`.

Let `M_low(v*)` be the bounded message class obtained by the active pay-per-bit embedding/packing into at most `76` ring elements, with coefficient digits bounded by the live backend envelope. Let `M_hi(v*)` be the one-round post-fold message class obtained by taking one valid low-norm running witness message from `M_low(v*)`, one valid exact-step witness message from the fixed step relation, and one Fiat-Shamir fold challenge `rho_i in F`, and forming the resulting linear-combination witness message before decomposition reduction. `M_hi(v*)` is therefore a deterministic, fixed-definition superset of `M_low(v*)` for the fixed protocol line `v*`, not an unbounded ambient space.

Let `Com_mat_v*` be the additively homomorphic random-matrix commitment of that backend over the full message module containing both `M_low(v*)` and `M_hi(v*)`, with the live binding claim stated on `M_low(v*)` and `Pi_DEC` responsible for returning the running witness to `M_low(v*)` after any temporary excursion into `M_hi(v*)`.

Write commitment openings as `Commit(pp_step, m; rho)` with explicit opening randomness `rho` drawn from the backend's fixed `opening_randomness_bits = 256` domain. Any witness for a committed relation on this path therefore includes both the committed message and the commitment opening randomness.

Low norm means membership in `M_low(v*)`. High norm means membership in the temporary post-fold class `M_hi(v*)` before decomposition reduction. This is the exact place where Neo differs from the elliptic-curve HyperNova line: the decomposition reduction is needed only for the running instance-witness pair in the lattice setting. The repo's own security note already names the missing objects `Pi_CCS`, `Pi_RLC`, and `Pi_DEC` explicitly and states that the checked-in backend does not implement them yet. See [native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md#L132).

### 4.2.2 Exact one-step claim: `CCCS_step(Q_i)`

For one exact step statement `Q_i = (1, Sigma_state(S_{i-1}), Sigma_state(S_i))`, let

`x_i = public_inputs(Q_i)`

and define the exact committed CCS claim

`u_i = CCCS_step(Q_i) = (relation_id_step(v*), shape_digest_step(v*), x_i, mu_step(Q_i), C_i)`

with witness `W_step[i]` together with exact commitment opening randomness `rho_i^com`, equivalently witness polynomial `ew_i` together with `rho_i^com`, such that:

1. `relation_id_step(v*)` and `shape_digest_step(v*)` are exactly the ones named in the tuple;
2. `x_i = public_inputs(Q_i)`;
3. `mu_step(Q_i) = P2Hash_F(d_rel_step; enc_vk(vk_step(v*)), x_i)`;
4. `Commit(pp_step, ew_i; rho_i^com) = C_i` under `Com_mat_v*`;
5. `W_step[i]` satisfies `BlockStepRelation_v*`;
6. equivalently, the committed witness-and-statement carrier `z_i = (w_i, 1, x_i)` satisfies `H_step(b; z_i) = 0` for every Boolean row index `b in {0,1}^{ell_step}`.

This is the incoming exact claim for one real verified leaf. It is not the running accumulator.

### 4.2.3 Running prefix accumulator: `LCCCS_step(Q_pref[i])`

For one prefix summary

`Q_pref[i] = (i, Sigma_state(S_0), Sigma_state(S_i))`

and in particular

`Q_pref[0] = (0, Sigma_state(S_0), Sigma_state(S_0))`

define the running linearized committed CCS instance

`A_i = U_i = LCCCS_step(Q_pref[i]) = (relation_id_step(v*), shape_digest_step(v*), x_pref[i], mu_step(Q_pref[i]), C_i^acc, u_i^acc, r_i, v_{i,1}, ..., v_{i,t_step})`

where

`x_pref[i] = public_inputs(Q_pref[i])`

with witness `W_i^acc` together with running commitment opening randomness `rho_i^acc`, equivalently witness polynomial `ew_i^acc` together with `rho_i^acc`.

Write the standard HyperNova committed linearized CCS relation on the fixed compiled structure `S_step(v*)` as

`RLCCCS_step(shape_step(v*); (u, x, r, v_1, ..., v_{t_step}), ew)`

which holds iff, with `z = (w, u, x)` and `ez` the multilinear extension of `z`, for every `1 <= j <= t_step`,

`v_j = sum_{y in {0,1}^{ell_step}} f_{M_{step,j}}(r, y) * ez(y)`.

An object

`U = (relation_id, shape_digest, x, mu, C, u, r, v_1, ..., v_{t_step})`

is a valid member of `LCCCS_step(Q_pref)` iff all of the following hold under the fixed CCS structure `S_step(v*)`:

1. `x = public_inputs(Q_pref)`;
2. `mu = mu_step(Q_pref)`;
3. `relation_id = relation_id_step(v*)` and `shape_digest = shape_digest_step(v*)`;
4. `Commit(pp_step, ew^acc; rho^acc) = C`;
5. `RLCCCS_step(shape_step(v*); (u, x, r, v_1, ..., v_{t_step}), ew^acc)` holds.

This is the exact paper-level `RLCCCS` carrier instantiated on the fixed CCS structure `S_step(v*)`: the public statement enters through the explicit vector `x = public_inputs(Q_pref)`, the relaxation scalar is `u`, the witness is `w^acc`, and the evaluation vector `(v_1, ..., v_{t_step})` is computed from the multilinear extension of `z^acc = (w^acc, u, x)`. The semantics of "this carrier represents the prefix summary `Q_pref`" are not being smuggled in through prose: they are the conjunction of `x = public_inputs(Q_pref)`, `mu = mu_step(Q_pref)`, the fixed compiled relation id/shape, and the protocol-level soundness chain `CCCS_step -> Pi_CCS -> Pi_RLC -> Pi_DEC -> Verify_decide_step`. `RLCCCS_step` itself is the standard linearized carrier relation from HyperNova; it is not supposed to restate the nonlinear CCS equation a second time.

For the active running object `A_i`, the witness above is `ew_i^acc`, the commitment opening randomness is `rho_i^acc`, the public input vector is `x_pref[i]`, the challenge point is `r_i`, and the evaluation vector is `(v_{i,1}, ..., v_{i,t_step})`.

Use one injective canonical byte-to-field map everywhere recursive Fiat-Shamir absorbs byte objects.

For any fixed-width byte string `b in {0,1}^{4k}`, define

`pack_words32_le(b) in F^k`

to be the sequence of `k` little-endian `u32` words interpreted as Goldilocks field elements. This map is injective on its domain because every limb is `< 2^32 < p_Goldilocks`.

For arbitrary protocol byte strings of length `< 2^32`, define

`pack_bytes32_len(b) = (|b|, pack_words32_le(pad_4(b)))`

where `pad_4` appends zero bytes to the next multiple of four. The leading length limb makes this map injective on all finite byte strings.

In particular:

- `pack32(d) = pack_words32_le(d) in F^8` for every 32-byte digest;
- `pack48(d) = pack_words32_le(d) in F^12` for every 48-byte digest.

For every fixed-shape recursive proof object on this path, let `ser_*` be its canonical byte serialization under the fixed proof schema for `v*`, and let `enc_* = pack_bytes32_len(ser_*(...))`.

Write the canonical field-native digest of any typed `LCCCS_step` carrier

`U = (relation_id, shape_digest, x, mu, C, u, r, v_1, ..., v_{t_step})`

as

`DigestLCCCS_step(U) = P2Hash_F(d_lcccs_step; pack32(relation_id), pack32(shape_digest), x, mu, pack48(digest_commitment(C)), u, r, v_1, ..., v_{t_step}) in F^6`

This digest is part of the recursive protocol, not presentation sugar. Every Fiat-Shamir challenge on the recursive path binds the full typed instance through `DigestLCCCS_step`, not only isolated coordinates like `C` or `mu`.

### 4.2.4 Initialization

`A_0` is not magical, and it is not allowed to come from a different relation family.

Define

`A_0 = InitAccumulator_step(v*, Q_pref[0])`

to be the canonical empty-prefix neutral running instance in the same `LCCCS_step` family:

`A_0 in LCCCS_step(Q_pref[0]) = (relation_id_step(v*), shape_digest_step(v*), x_pref[0], mu_step(Q_pref[0]), C_0^acc, u_0^acc, r_0, v_{0,1}, ..., v_{0,t_step})`

with the explicit neutral-instance data:

- `x_pref[0] = public_inputs(Q_pref[0])`;
- `ew_0^acc = 0`, the all-zero committed running witness polynomial over the fixed witness domain of `shape_step(v*)`;
- `rho_0^acc = 0^{opening_randomness_bits}`, the canonical zero opening randomness for the initializer;
- `C_0^acc = Commit(pp_step, ew_0^acc; rho_0^acc)`;
- `u_0^acc = 1`;
- `r_0 = 0^{ell_step}`;
- with `z_0^acc = (0, u_0^acc, x_pref[0])` and `ez_0^acc` its multilinear extension,

  `v_{0,j} = sum_{y in {0,1}^{ell_step}} f_{M_{step,j}}(r_0, y) * ez_0^acc(y)`

  for every `1 <= j <= t_step`.

This is a valid `RLCCCS` instance because the witness part is fixed to zero while the public statement part `x_pref[0]` and relaxation scalar `u_0^acc = 1` are carried exactly through the standard paper carrier `z_0^acc = (w_0^acc, u_0^acc, x_pref[0])`; the evaluation vector is therefore determined, not guessed. `InitAccumulator_step` therefore has no hidden prover choice: it deterministically emits this exact tuple for the exact summary `Q_pref[0]`, including the canonical opening randomness `rho_0^acc = 0^{opening_randomness_bits}`. Equivalently:

- `A_0` uses the same `relation_id_step(v*)` and `shape_step(v*)` as every later `A_i`;
- no fold ever combines different compiled CCS relations;
- round `1` folds `A_0` with `B_1` inside one homogeneous `LCCCS_step` family.

The initializer also has the exact neutrality law required by the first recursive round: for every valid temporary linearized first-step instance `B_1 in LCCCS_step(Q_1)` and every valid target prefix summary `Q_pref[1]` with `ComposeCheck(Q_pref[0], Q_1, Q_pref[1]) = 1`, valid `pi_rlc[1]` for

`Fold_me(pk_step, Q_pref[0], A_0, Q_1, B_1, Q_pref[1], rho_1; ew_0^acc, rho_0^acc, ew_1, rho_1^com)`

implies that the resulting `H_1` represents exactly the one-step prefix `Q_pref[1]`, and valid `pi_norm[1]` then yields `A_1 in LCCCS_step(Q_pref[1])` for that same prefix. So `A_0` is not merely a valid empty-prefix carrier; it is the left-identity accumulator for unary prefix extension.

The recursive carrier for this base object is `DigestLCCCS_step(A_0)`. The separate on-wire header binding is the canonical byte digest of the serialized initializer:

`init_acc_digest_step(v*) = digest_init_acc(ser_lcccs(A_0))`

This is a canonical bootstrap object, not a separate `BlockBaseRelation_v*` claim and not a second relation id.

### 4.2.5 The hard step

Given:

- the previous running accumulator `A_{i - 1} = U_{i-1} in LCCCS_step(Q_pref[i - 1])`;
- the new exact one-step claim `u_i in CCCS_step(Q_i)`;
- the checked compatibility condition `ComposeCheck(Q_pref[i - 1], Q_i, Q_pref[i]) = 1`;

one recursive round has three paper-defined substeps.

1. `Pi_CCS` / `Reduce_step_to_me`

   `Reduce_step_to_me(pk_step, Q_i, u_i; W_step[i], ew_i, rho_i^com) -> (B_i, pi_ccs[i])`

   where `B_i = U_i^lin` is the temporary linearized step instance for `Q_i`:

   `B_i = (relation_id_step(v*), shape_digest_step(v*), x_i, mu_step(Q_i), C_i, 1, r_i^lin, v_{i,1}^lin, ..., v_{i,t_step}^lin) in LCCCS_step(Q_i)`

   with `x_i = public_inputs(Q_i)`.

   Here `u_i` is not optional metadata: it is the exact committed CCS step claim from Section 4.2.2, deterministically formed from `(Q_i, W_step[i], ew_i, rho_i^com)` by computing `x_i = public_inputs(Q_i)` and `C_i = Commit(pp_step, ew_i; rho_i^com)`. The reduction does not get to change either the exact witness commitment or the exact scalar slot: the output linearized instance carries the same `C_i` and the exact scalar value `1`. The verifier recomputes the unique CCS-reduction challenge

   `chi_i = chi_step(Q_i, C_i)`

   and checks `pi_ccs[i]` against that exact transcript, the exact committed claim `u_i`, and the output `B_i`. This is the exact CCS-to-LCCCS reduction from HyperNova/Neo. The soundness contract is:

   if `pi_ccs[i]` verifies, then `B_i` is a valid `LCCCS_step(Q_i)` instance induced by a satisfying witness to the exact step claim `u_i`.

2. `Pi_RLC` / `Fold_me`

   derive one fold challenge

   `rho_i = FS_P2(d_rlc_step; enc_vk(vk_step(v*)), mu_step(Q_pref[i - 1]), mu_step(Q_i), mu_step(Q_pref[i]), DigestCompose_step(Q_pref[i - 1], Q_i, Q_pref[i]), DigestLCCCS_step(A_{i - 1}), DigestLCCCS_step(B_i), DigestProofCCS_step(pi_ccs[i]))`

   and run the exact Neo/HyperNova fold of one running `LCCCS` instance with one new linearized step instance:

   `Fold_me(pk_step, Q_pref[i - 1], A_{i - 1}, Q_i, B_i, Q_pref[i], rho_i; ew_{i-1}^acc, rho_{i-1}^acc, ew_i, rho_i^com) -> (H_i, ew_i^hi, rho_i^hi, pi_rlc[i])`

   where `H_i = U_i^hi` is the temporary high-norm running instance for the composed prefix `Q_pref[i]`:

   `H_i = (relation_id_step(v*), shape_digest_step(v*), x_pref[i], mu_step(Q_pref[i]), C_i^hi, u_i^hi, r_i^hi, v_{i,1}^hi, ..., v_{i,t_step}^hi)`

   The fold law is the exact `RLCCCS x LCCCS -> RLCCCS` object imported from the Neo/HyperNova line for the fixed structure `S_step(v*)`. This note does not abbreviate that object into partial coordinate formulas anymore because the recursive soundness boundary is the full typed carrier above, not only `(C, u, v)`. Any implementation of `Fold_me` on this path must therefore:

   - take the full source carriers `A_{i - 1}` and `B_i`,
   - take the target summary `Q_pref[i]` as explicit typed input,
   - check `ComposeCheck(Q_pref[i - 1], Q_i, Q_pref[i]) = 1` as part of the typed fold statement,
   - derive `rho_i` from their full digests `DigestLCCCS_step(A_{i - 1})` and `DigestLCCCS_step(B_i)`,
   - privately consume the opening witness pairs `(ew_{i-1}^acc, rho_{i-1}^acc)` and `(ew_i, rho_i^com)` for the two source committed instances,
   - output the full target carrier `H_i` together with its high-norm witness/opening pair `(ew_i^hi, rho_i^hi)`,
   - and prove the fold equations for that full typed instance under the fixed CCS structure `S_step(v*)`.

   This is the actual parent satisfiability claim. If:

   - `A_{i - 1}` is a valid running `LCCCS_step(Q_pref[i - 1])` instance,
   - `B_i` is a valid linearized `LCCCS_step(Q_i)` instance induced from a satisfying exact step claim,
   - `ComposeCheck(Q_pref[i - 1], Q_i, Q_pref[i]) = 1`,

   then valid `pi_rlc[i]` implies `H_i` is a valid high-norm running `LCCCS_step(Q_pref[i])` instance. There is no cross-term bug here because the folded object is the standard typed `RLCCCS` accumulator from the paper line, not an ad hoc affine system.

3. `Pi_DEC` / `Normalize_me`

   `Normalize_me(pk_step, Q_pref[i], H_i; ew_i^hi, rho_i^hi) -> (A_i, ew_i^acc, rho_i^acc, pi_norm[i])`

   This is Neo's decomposition reduction. It acts only on the running instance-witness pair. It decomposes the temporary high-norm message behind `H_i` back into the bounded message class `M_low(v*)`, updates the committed running witness accordingly, and outputs the next low-norm running instance

   `A_i in LCCCS_step(Q_pref[i])`.

   The soundness contract is:

   if `pi_norm[i]` verifies and `H_i` is a valid high-norm running instance for `Q_pref[i]`, then `A_i` is a valid low-norm running instance for the same prefix summary `Q_pref[i]`, together with the bounded witness/opening pair `(ew_i^acc, rho_i^acc)` used by the next round.

The hard step is therefore not "prior accumulator plus exact step magically becomes `k_acc + 1` ME claims." It is the standard CCS folding line:

`exact CCCS step -> Pi_CCS -> temporary linearized step -> Pi_RLC with running LCCCS -> temporary high-norm running instance -> Pi_DEC -> next low-norm running LCCCS`

The final decider object is:

`pi_dec[0,n] = Prove_decide_step(pk_step, Q_pref[n], A_n; T_acc[0,n])`

with verifier:

`Verify_decide_step(vk_dec_step(v*), Q_pref[n], A_n, pi_dec[0,n])`

The decider proof is constant-size for fixed `(v*, shape_step(v*))`. It certifies that `A_n` is the terminal accumulator of one valid private unary accumulation transcript

`T_acc[0,n] = ((Q[i - 1, i], u_i, Q_pref[i], W_step[i], ew_i, rho_i^com, B_i, ew_i^hi, rho_i^hi, H_i, ew_i^acc, rho_i^acc, A_i, pi_ccs[i], pi_rlc[i], pi_norm[i]))_{i=1}^n`

starting from `A_0`, such that every round obeys the exact CCS reduction, random-linear-combination fold, and low-norm normalization laws above.

This is the corrected backend soundness claim:

- `Reduce_step_to_me = Pi_CCS` soundly linearizes one exact `CCCS_step(Q_i)` claim into one temporary `LCCCS_step(Q_i)` instance under the recomputed transcript `chi_i = chi_step(Q_i, C_i)`;
- `Fold_me = Pi_RLC` soundly folds the previous running `LCCCS_step(Q_pref[i - 1])` instance and the new temporary `LCCCS_step(Q_i)` instance into one high-norm running `LCCCS_step(Q_pref[i])` instance, with `Q_pref[i]` supplied explicitly to the fold statement and checked by `ComposeCheck`;
- `Normalize_me = Pi_DEC` soundly restores the bounded running message class without changing the represented prefix claim and outputs the bounded witness/opening pair for the next accumulator state;
- `Verify_decide_step` closes the full private unary accumulation transcript into one constant-size proof object.

The checked-in SuperNeo backend is not this object. It currently exposes:

- a deterministic public-witness replay verifier `verify_leaf(..., expected_packed, ...)`, not a witness-sound hidden-witness `pi_step`;
- a digest-only fold canonicalization check `fold_pair` / `verify_fold` over `FoldedInstance`, not a checked accumulator fold carrying linear-homomorphic opening commitments plus structured summary composition;
- no decider proof that closes a hidden fold history into one constant-size proof object;
- BLAKE3 transcript/digest helpers for byte-oriented artifacts, not a field-native recursive transcript.

See [circuits/superneo-core/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-core/src/lib.rs#L28), [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs#L1122), [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs#L1491), and [docs/crypto/native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md#L132).

The concrete recursive relation object carried on this path is the fixed step relation:

`RelationObject_step(v*) = (relation_id_step, shape_step(v*), witness_schema_step(v*), encode_statement_step, build_assignment_step)`

with:

- `relation_id_step` the exact `RelationId::from_label(...)` value named below;
- `shape_step(v*) = CompileCCS(C_step(v*))`, the fixed CCS shape obtained by compiling one fixed one-transaction transition circuit into Goldilocks CCS;
- `witness_schema_step(v*)` the fixed witness layout induced by that compiled circuit;
- `encode_statement_step` the exact public-input serialization into Goldilocks limbs;
- `build_assignment_step` the witness assignment builder for that same fixed circuit.

That is the bridge from theorem notation to the repo’s `Relation<Goldilocks>` API in [circuits/superneo-ccs/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-ccs/src/lib.rs#L64): the recursive proof system certifies one concrete compiled CCS relation object, not an informal predicate.

Define the verifier-key constant tuple:

`vk_step(v*) = (params_fingerprint_v*, spec_digest_v*, relation_id_step(v*), shape_digest_step(v*), security_tuple_step(v*))`

where:

- `params_fingerprint_v* = native_backend_params().parameter_fingerprint()`;
- `spec_digest_v* = native_backend_params().spec_digest()`;
- `shape_digest_step(v*) = digest_shape(shape_step(v*))`;
- `security_tuple_step(v*) = (security_bits, challenge_bits, fold_challenge_count, max_fold_arity, transcript_domain_digest, ring_profile, commitment_rows, ring_degree, digit_bits, opening_randomness_bits)` exactly in the style of [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs#L1156).

Its canonical recursive field encoding is

`enc_vk(vk_step(v*)) = pack48(params_fingerprint_v*) || pack32(spec_digest_v*) || pack32(relation_id_step(v*)) || pack32(shape_digest_step(v*)) || enc_security_tuple(security_tuple_step(v*))`

where

`enc_security_tuple(security_tuple_step(v*)) = (security_bits, challenge_bits, fold_challenge_count, max_fold_arity) || pack32(transcript_domain_digest) || (ring_profile_id_step(v*), commitment_rows, ring_degree, digit_bits, opening_randomness_bits)`

with `ring_profile_id_step(v*) = 1` for `GoldilocksFrog`. So every component of `enc_vk(vk_step(v*))` is now either a single field element or an explicitly packed digest under the same canonical encoding rules.

Likewise, for any witness commitment `C_w`, write

`enc_commit_digest(C_w) = pack48(digest_commitment(C_w))`.

The field-native Fiat-Shamir transcript for the recursive step relation is the deterministic challenge function

`chi_step(Q, C_w) = FS_P2(d_fs_step; enc_vk(vk_step(v*)), public_inputs(Q), mu_step(Q), enc_commit_digest(C_w))`

where:

- `enc_vk(vk_step(v*))` is the canonical field encoding of the verifier-key constants above;
- `public_inputs(Q)` is the exact statement vector carried by the relation API;
- `mu_step(Q)` is the field-native statement commitment for the step relation;
- `enc_commit_digest(C_w)` is the canonical digest encoding of the witness commitment.

For recursive challenges that must absorb proof objects rather than commitments, use the same discipline:

`DigestProofCCS_step(pi_ccs) = P2Hash_F(d_pi_ccs_step; enc_proof_ccs(pi_ccs)) in F^6`

where `enc_proof_ccs = pack_bytes32_len(ser_proof_ccs(pi_ccs))` and `ser_proof_ccs` is the fixed canonical byte serialization of the CCS-linearization proof under the unique proof schema for `v*`. The recursive transcript never absorbs an untyped byte hash directly.

Likewise define the typed composition digest

`DigestCompose_step(Q_pref[i - 1], Q_i, Q_pref[i]) = P2Hash_F(d_compose_step; public_inputs(Q_pref[i - 1]), public_inputs(Q_i), public_inputs(Q_pref[i])) in F^6`

This digest is not a substitute for `ComposeCheck`. It binds the exact triple of summaries into Fiat-Shamir; the typed fold statement still separately requires `ComposeCheck(Q_pref[i - 1], Q_i, Q_pref[i]) = 1`.

This is the exact point where the recursive construction stops inheriting the current byte-oriented BLAKE3 transcript. The recursive verifier absorbs the same backend identity ingredients the current code binds into `BackendKey`, but under a field-native Poseidon2 transcript instead of `digest_statement(...)` or Blake3-XOF.

For statement compatibility with the repo’s `Relation<Goldilocks>` interface, the recursive step relation carries both:

- `stmt_bytes_step(Q)`, a canonical byte serialization used only for `statement_digest_step(Q) = digest_statement(stmt_bytes_step(Q))`;
- `public_inputs(Q)`, the field vector returned by `encode_statement_step`;
- `mu_step(Q) = P2Hash_F(d_rel_step; enc_vk(vk_step(v*)), public_inputs(Q)) in F^6`, the field-native statement commitment used by recursion itself.

The terminal decider is a second fixed verification object over the same step family, so its identity must also be on wire. Define the decider profile:

`decider_profile_step(v*) = (decider_id_step(v*), decider_vk_digest_step(v*), decider_transcript_digest_step(v*), init_acc_digest_step(v*))`

where:

- `decider_id_step(v*)` identifies the exact `Verify_decide_step` algorithm and proof format;
- `decider_vk_digest_step(v*)` binds the decider verifier key and any structured decider parameters;
- `decider_transcript_digest_step(v*)` binds the decider Fiat-Shamir domain separation;
- `init_acc_digest_step(v*)` binds the canonical initializer `A_0`.

Write the full decider verifier key as:

`vk_dec_step(v*) = (vk_step(v*), decider_profile_step(v*))`

The terminal on-chain decider header follows the same identity discipline as the current native artifacts:

`artifact_version_dec_step(v*) = native_backend_params().artifact_version(b"recursive-block-step-decider-v1")`

`Header_dec_step(v*, Q_pref[n]) = (artifact_version_dec_step(v*), params_fingerprint_v*, spec_digest_v*, relation_id_step(v*), shape_digest_step(v*), decider_id_step(v*), decider_vk_digest_step(v*), decider_transcript_digest_step(v*), init_acc_digest_step(v*), statement_digest_step(Q_pref[n]))`

with exact byte widths:

- `artifact_version_dec_step(v*): u16`;
- `params_fingerprint_v*: [u8; 48]`;
- `spec_digest_v*: [u8; 32]`;
- `relation_id_step(v*): [u8; 32]`;
- `shape_digest_step(v*): [u8; 32]`;
- `decider_id_step(v*): [u8; 32]`;
- `decider_vk_digest_step(v*): [u8; 32]`;
- `decider_transcript_digest_step(v*): [u8; 32]`;
- `init_acc_digest_step(v*): [u8; 32]`;
- `statement_digest_step(Q_pref[n]): [u8; 48]`.

The terminal accumulator object `A_n` has one fixed serialized width `L_acc(v*)` because it is one fixed-width `LCCCS_step(Q_pref[n])` instance for one fixed compiled relation. The terminal decider proof has one fixed serialized width `L_dec(v*)` for the same fixed relation and protocol line. Therefore the full terminal decider artifact

`Artifact_step(B) = (Header_dec_step(v*, Q_pref[n]), A_n, pi_dec[0,n])`

has one fixed serialized length

`|Artifact_step(B)| = L_art_step(v*)`

for every admissible block size `n`.

### 4.3 External verified-leaf input object

The recursive backend does not recursively re-prove transaction validity. It consumes the ordered verified-leaf stream already produced by the current tx-artifact verifier.

For one transaction index `i`, define the fixed verified-leaf input object:

`L_i = (R_i, V_i, Xi_i)`

with:

- `R_i = CanonicalTxValidityReceipt_i`;
- `V_i = TxLeafPublicTx_i`;
- `Xi_i = SerializedStarkInputs_i`.

Its exact public/witness source is the current checked-in `TxLeafPublicRelation` seam:

- the receipt public statement is the 24-limb encoding from [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L852);
- the tx public view plus serialized STARK public inputs use the fixed witness layout from [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L893) and [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L1936).

Because `MAX_INPUTS = 2`, `MAX_OUTPUTS = 2`, and `BALANCE_SLOTS = 4`, the full encoded `L_i` slice has fixed length `W_leaf(v*)`. No part of the recursive backend depends on transaction count through this object.

For the current `TxLeafPublicRelation`, that fixed-width witness slice is already exact:

- receipt public statement: `24` Goldilocks limbs;
- tx/stark witness assignment: `90` Goldilocks limbs from the schema in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L400);
- total fixed recursive leaf payload: `W_leaf(v*) = 114` Goldilocks limbs.

The checked-in `TxLeafPublicWitness` struct still carries transport fields like `proof_backend` and `smallwood_arithmetization`, but the live validator binds only the canonical receipt object, the serialized STARK inputs, and the fixed verifier profile/protocol line when it checks tx-leaf validity. The recursive leaf object therefore consumes exactly the canonical verified-leaf payload above, not those redundant transport fields. See [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L1481) and [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L1823).

The only trust boundary here is the live one already used by consensus:

- external tx-artifact verification establishes that `L_i` is the canonical verified representation of tx `i`;
- the recursive block proof is only allowed to consume that ordered verified stream, not an arbitrary hidden alternative.

### 4.4 Concrete block-step relation

The recursive arithmetic relation is one fixed one-transaction transition relation. Arbitrary block length comes from private accumulation, not from widening the relation.

Use one common summary encoding for any structured summary

`Q = (m, sigma_in, sigma_out)`

and write the one-transaction leaf case as

`Q_i = Q[i - 1, i] = (1, sigma_{i-1}, sigma_i)`

with:

- `sigma_{i-1} = Sigma_state(S_{i-1}) in F^6`;
- `sigma_i = Sigma_state(S_i) in F^6`.

Its exact relation encoding is:

- `artifact_version_step(v*) = native_backend_params().artifact_version(b"recursive-block-step-v1")`;
- `relation_id_step(v*) = RelationId::from_label("hegemon.superneo.block-step.v1.c2.k2.smallwood.bridge64")`;
- `shape_digest_step(v*) = digest_shape(shape_step(v*))`;
- `stmt_bytes_step(Q) = u32_le(m) || le_u64^6(sigma_in) || le_u64^6(sigma_out)`;
- `public_inputs(Q) = m || sigma_in || sigma_out`, exactly `13` field elements;
- `statement_digest_step(Q) = digest_statement(stmt_bytes_step(Q))`;
- `mu_step(Q) = P2Hash_F(d_rel_step; enc_vk(vk_step(v*)), public_inputs(Q)) in F^6`.

Its compiled recursive circuit is one fixed transition relation:

`C_step(v*) = CheckLeafTransition_v*`

so `shape_step(v*) = CompileCCS(C_step(v*))` is one fixed CCS shape for the fixed protocol line.

Define the witness object:

`W_step[i] = (S_{i-1}, S_i, L_i, a_i, M_i)`

with:

- `S_{i-1}`, `S_i` the raw boundary states;
- `L_i = (R_i, V_i, Xi_i)` the exact fixed-width verified-leaf object from Section 4.3;
- `a_i in {0, ..., H - 1}` the anchor-slot witness;
- `M_i` the at-most-two-nullifier sparse-set witness bundle.

The exact fixed-shape mapping to the repo’s `Relation<Goldilocks>` API is:

- `type Statement_step = StepStatement { segment_len: u32, sigma_in: [u64; 6], sigma_out: [u64; 6] }`;
- `type Witness_step = StepWitness { state_in, state_out, leaf_input, anchor_slot, nullifier_paths }`;
- `encode_statement_step` returns `public_inputs(Q)` only;
- `build_assignment_step` serializes the raw boundary states, one fixed-width leaf-input slice, one anchor slot, and one fixed-width sparse-set path bundle into one witness vector of fixed schema `witness_schema_step(v*)`.

`BlockStepRelation_v*` accepts iff:

1. `m = 1`;
2. `Sigma_state(S_{i-1}) = sigma_{i-1}`;
3. `Sigma_state(S_i) = sigma_i`;
4. `i(S_i) = i(S_{i-1}) + 1`;
5. `R_i.verifier_profile = rho_leaf*`;
6. `V_i.version = v*`;
7. `lambda_i = AbsorbLeaf(lambda_{i-1}, L_i)` using the exact canonical field packing `pack_L(L_i)` from Section 2.7;
8. `tau_i = P2(tau_{i-1} + iota(pack_C(R_i.statement_hash)))`;
9. `eta_i = AbsorbReceipt(eta_{i-1}, R_i)`;
10. `anchor(Xi_i) = Xi_i.merkle_root` appears in `R_hist(T_{i-1})` at index `a_i`;
11. `T_i = Append*(T_{i-1}, V_i)` where the appended commitments are the non-zero commitments from `V_i.commitments`;
12. `U_i = Insert*(U_{i-1}, V_i)` using the path witnesses in `M_i`.

The hostile-review holes are therefore closed explicitly:

- a valid step instance must expose `segment_len = 1`, not an unconstrained count field;
- a valid step instance must advance the hidden transaction counter by exactly one;
- the hidden recursive execution must absorb the exact fixed-width verified-leaf payload `L_i`, not only its receipt projection `R_i`.

### 4.5 Recursive accumulator and final block artifact

For every block with ordered verified leaves `L_1, ..., L_n`, the prover runs the unary accumulation cycle from Section 4.2. At round `i` it combines:

- the previous prefix accumulator `A_{i - 1}` for `Q_pref[i - 1]`,
- the exact one-step claim `Q[i - 1, i]`,
- the exact committed CCS claim `u_i = CCCS_step(Q_i)`,
- the exact step witness `W_step[i]`,

and produces:

- one temporary linearized step instance `B_i = U_i^lin`,
- one folded high-norm running instance `H_i = U_i^hi`,
- one normalized low-norm prefix accumulator `A_i` for `Q_pref[i]`.

The private unary accumulation transcript is witness data only. It is never serialized on chain. The only summary that survives to the on-chain artifact is the terminal prefix summary:

`Q_pref[n] = (n, Sigma_state(S_0), Sigma_state(S_n))`

The key consequence is the one the hostile review demanded: the recursion does not require a proof-system block-size bound. Increasing `n` adds more private CCS-reduction, RLC-fold, and normalization work, but it does not change the step relation shape, the accumulator width, or the terminal artifact width.

Define the public tuple:

`Z(B) = Y_rec(B)`

and write it as:

`Z(B) = (n, C_stmt, root_prev, root_new, kernel_prev, kernel_new, nullifier_root, da_root, C_leaf, C_receipt, sigma_tree_prev, sigma_tree_new)`

with:

- `C_leaf = proj_6(lambda_n)`;
- `C_stmt = proj_6(tau_n)`;
- `C_receipt = proj_6(eta_n)`;
- `sigma_tree_prev = Sigma_tree(T_0)`;
- `sigma_tree_new = Sigma_tree(T_n)`.

The public tuple is not itself another recursive relation statement. That was the last fake fixed point. The final recursive object shipped on chain is the terminal accumulator plus its decider proof:

- `Q_pref[n] = (n, Sigma_state(S_0), Sigma_state(S_n))`;
- `A_n in LCCCS_step(Q_pref[n])`, the terminal low-norm running accumulator;
- `pi_dec[0,n]`, the constant-size decider proof that closes the full private unary accumulation transcript from `A_0` to `A_n`.

The final recursive artifact is therefore:

`Artifact_step(B) = (Header_dec_step(v*, Q_pref[n]), A_n, pi_dec[0,n])`

and the full on-chain block proof is:

`Pi_block(B) = (Artifact_step(B), Z(B))`

There is no second recursive seal relation and no outer wrapper proof assumed here. Instead, the full verifier deterministically reconstructs the terminal hidden summary from public data and then checks the terminal decider directly.

Concretely, the outer verifier reconstructs:

- `T_0` from the parent state;
- `lambda_n`, `tau_n`, and `eta_n` by replaying the verified-leaf, statement-hash, and receipt sponges over the ordered verified-leaf stream;
- `T_n = Append*(T_0, B)` by deterministic append replay over the ordered verified tx views;
- the ordered non-zero nullifier list `N_pub(B)` from the ordered verified tx views, checks `|sort_unique(N_pub(B))| = |N_pub(B)|`, and sets `U_n = SparseSetRoot(Set(N_pub(B)))`;
- `S_0 = (0, lambda_0, tau_0, eta_0, T_0, z_384)`;
- `S_n = (n, lambda_n, tau_n, eta_n, T_n, U_n)`;
- `Q_pref[n] = (n, Sigma_state(S_0), Sigma_state(S_n))`.

It then checks:

1. `Header_dec_step(v*, Q_pref[n])` matches the artifact header;
2. `Verify_decide_step(vk_dec_step(v*), Q_pref[n], A_n, pi_dec[0,n]) = 1`;
3. `Z(B) = Y_rec(B)` matches the same recomputed terminal data:
   - `C_leaf = proj_6(lambda_n)`;
   - `C_stmt = proj_6(tau_n)`;
   - `C_receipt = proj_6(eta_n)`;
   - `sigma_tree_prev = Sigma_tree(T_0)`;
   - `sigma_tree_new = Sigma_tree(T_n)`;
   - `root_prev = root(T_0)`;
   - `root_new = root(T_n)`;
   - `kernel_prev = kernel_root_from_shielded_root(root(T_0))`;
   - `kernel_new = kernel_root_from_shielded_root(root(T_n))`;
   - `nullifier_root` and `da_root` from the current deterministic consensus recomputations.

## 5. On-Chain Artifact And Full Verifier

### 5.1 Private accumulation schedule

For a block with ordered verified leaves `L_1, ..., L_n`, the prover executes the fixed unary accumulation cycle:

1. initialize the empty-prefix accumulator `A_0`;
2. for each `1 <= i <= n`, run `Reduce_step_to_me`, then `Fold_me`, then `Normalize_me` to obtain `A_i`;
3. end with the terminal accumulator `A_n` and the private transcript `T_acc[0,n]`.

The transcript affects only private prover work. It does not affect:

- the public tuple `Z(B)`;
- the step relation shape `shape_step(v*)`;
- the accumulator width `L_acc(v*)`;
- the terminal decider proof width `L_dec(v*)`;
- the serialized artifact size `L_art_step(v*)`.

That is the answer to "there is no reason to assume it must be bounded to a fixed size": the proof system does not impose a separate maximum recursive block size. The only count bound present here is the existing `u32` `tx_count` encoding already part of current consensus semantics.

### 5.2 On-chain artifact

The on-chain artifact is:

`Pi_block(B) = (Artifact_step(B), Z(B))`

with serialized size:

`|Pi_block(B)| = L_art_step(v*) + 532`

provided `|Artifact_step(B)| = L_art_step(v*)` is constant for the fixed step relation and protocol line.

Here `Artifact_step(B)` contains only the terminal step-decider header, the terminal low-norm accumulator `A_n`, and the constant-size decider proof `pi_dec[0,n]`. It does not serialize:

- the `n` CCS-reduction proofs `pi_ccs[i]`;
- the `n` random-linear-combination fold proofs `pi_rlc[i]`;
- the `n` normalization proofs `pi_norm[i]`;
- the temporary linearized step instances `B_i` or folded high-norm running instances `H_i`;
- the hidden accumulator sequence `A_0, ..., A_n`;
- the private unary accumulation transcript `T_acc[0,n]`.

### 5.3 Full verifier

Define `VerifyBlockRecursive(B, parent_state, verified_leaves, Pi_block)` as:

1. parse `Pi_block` into `(Artifact_step, Z(B))`;
2. parse `Artifact_step` into `(Header_dec_step, A_n, pi_dec[0,n])`;
3. check that `verified_leaves = (L_1, ..., L_n)` is exactly the ordered output of the current tx-artifact verifier for block `B`;
4. check `len(verified_leaves) = n`;
5. replay the exact verified-leaf sponge over `verified_leaves` to obtain the full terminal state `lambda_n` and compare `proj_6(lambda_n)` against `C_leaf`;
6. replay the exact statement-hash sponge over the canonical ordered statement-hash list from `verified_leaves` to obtain the full terminal state `tau_n` and compare `proj_6(tau_n)` against `C_stmt`;
7. replay the exact receipt sponge over the canonical ordered receipt stream to obtain the full terminal state `eta_n` and compare `proj_6(eta_n)` against `C_receipt`;
8. reconstruct the exact pre-block append state `T_0` from `parent_state` and compare `root_prev(B)` plus `Sigma_tree(T_0)` against `(root_prev, sigma_tree_prev)`;
9. recompute the exact post-block append state `T_n = Append*(T_0, B)` and compare `root_new(B)` plus `Sigma_tree(T_n)` against `(root_new, sigma_tree_new)`;
10. extract the ordered public non-zero nullifier list `N_pub(B)` from the verified tx views, check `|sort_unique(N_pub(B))| = |N_pub(B)|`, and set `U_n = SparseSetRoot(Set(N_pub(B)))`;
11. recompute `kernel_prev(B)` and `kernel_new(B)` from the corresponding shielded roots and compare;
12. recompute `nullifier_root(B)` with the current sorted-unique BLAKE3 rule and compare;
13. recompute `da_root(B)` with the current DA-root rule and compare;
14. form `S_0 = (0, lambda_0, tau_0, eta_0, T_0, z_384)` and `S_n = (n, lambda_n, tau_n, eta_n, T_n, U_n)`, then derive `Q_pref[n] = (n, Sigma_state(S_0), Sigma_state(S_n))`;
15. check that `Header_dec_step` matches `(artifact_version_dec_step(v*), params_fingerprint_v*, spec_digest_v*, relation_id_step(v*), shape_digest_step(v*), decider_id_step(v*), decider_vk_digest_step(v*), decider_transcript_digest_step(v*), init_acc_digest_step(v*), statement_digest_step(Q_pref[n]))`;
16. verify `Verify_decide_step(vk_dec_step(v*), Q_pref[n], A_n, pi_dec[0,n]) = 1`.

This is the honest verifier boundary. Tx-artifact validity stays where the current product already checks it: outside the recursive block proof. The recursive proof certifies ordered absorption of the exact verified-leaf stream, ordered absorption of the verified receipt stream, ordered statement absorption, append-state evolution, anchor membership, and uniqueness. Consensus keeps deterministic public recomputations outside the proof, exactly as it does now, but now also checks the constant-size verified-leaf commitment, receipt commitment, and append-state digests so the recursive witness cannot drift to a different `(R_i, V_i, Xi_i)` stream or a different frontier/history with the same exposed roots.

## 6. Theorems

### Theorem 6.1: soundness of the full verifier

Assume:

1. the current tx-artifact verifier is sound, `verified_leaves = (L_1, ..., L_n)` is exactly its ordered output for block `B`, and `len(verified_leaves) = n`;
2. the domain-separated commitments and digests used as recursive handles are binding on their valid encoded domains:
   - `pack_L` and the resulting terminal commitment `C_leaf = proj_6(lambda_n)`,
   - `pack_R` and the resulting terminal commitment `C_receipt = proj_6(eta_n)`,
   - the statement-hash compression `H_stmt` together with the resulting terminal commitment `C_stmt = proj_6(tau_n)`,
   - `enc_vk`,
   - `enc_security_tuple`,
   - `enc_commit_digest`,
   - `enc_proof_ccs`,
   - `pack_words32_le`, `pack_bytes32_len`, `pack32`, and `pack48`,
   - `Sigma_tree`,
   - `Sigma_state`,
   - `mu_step`,
   - `DigestLCCCS_step`,
   - `DigestProofCCS_step`,
   - `DigestCompose_step`,
   - `statement_digest_step`,
   - `decider_vk_digest_step`,
   - `decider_transcript_digest_step`,
   - `init_acc_digest_step`,
   - the commitment digests carried by the strengthened backend;
3. `RecursiveBackend_v2(v*)` is sound in five senses:
   - `InitAccumulator_step(v*, Q_pref[0])` returns exactly the canonical neutral running instance from Section 4.2.4:
     `x_pref[0] = public_inputs(Q_pref[0])`, `ew_0^acc = 0`, `rho_0^acc = 0^{opening_randomness_bits}`, `C_0^acc = Commit(pp_step, 0; rho_0^acc)`, `u_0^acc = 1`, `r_0 = 0^{ell_step}`, and `v_{0,j} = sum_y f_{M_{step,j}}(r_0, y) * ez_0^acc(y)` for every `j`, with `z_0^acc = (0, u_0^acc, x_pref[0])`, recursive carrier `DigestLCCCS_step(A_0)`, on-wire binding `init_acc_digest_step(v*) = digest_init_acc(ser_lcccs(A_0))`, and the explicit left-identity law stated in Section 4.2.4 for the first fold;
   - `Reduce_step_to_me = Pi_CCS` is sound for CCS linearization under the recomputed transcript `chi_i = chi_step(Q_i, C_i)`: valid `pi_ccs[i]` implies that the temporary `B_i` instance is a valid `LCCCS_step(Q_i)` instance induced by a satisfying exact one-step `CCCS_step(Q_i)` claim with the same witness commitment `C_i` and scalar slot `1`;
   - `Fold_me = Pi_RLC` is sound for folding one running `LCCCS_step(Q_pref[i - 1])` instance with one temporary `LCCCS_step(Q_i)` instance into a high-norm running `LCCCS_step(Q_pref[i])` instance over the fixed post-fold class `M_hi(v*)`, under the checked compatibility law `ComposeCheck(Q_pref[i - 1], Q_i, Q_pref[i]) = 1`, while consuming the committed witness/opening pairs for the two source instances and producing the committed high-norm witness/opening pair for `H_i`;
   - `Normalize_me = Pi_DEC` is sound for decomposition from `M_hi(v*)` back into the bounded running message class `M_low(v*)`, preserves the folded running `LCCCS_step(Q_pref[i])` semantics, and outputs the bounded committed witness/opening pair for `A_i`;
   - `Verify_decide_step` is witness-sound for the existence of one full private unary accumulation transcript `T_acc[0,n]` from `A_0` to `A_n`;
4. the deterministic public recomputations in `VerifyBlockRecursive` faithfully implement the current consensus functions for verified-leaf commitment, receipt commitment, statement commitment, exact append-state transition, canonical sparse-set rebuild, public duplicate check, kernel roots, nullifier root, and DA root.

If `VerifyBlockRecursive(B, parent_state, verified_leaves, Pi_block)` accepts, then there exist raw states `S_0, ..., S_n` and one private unary accumulation transcript `T_acc[0,n]` such that:

1. `verified_leaves = (L_1, ..., L_n)` is the ordered verified-leaf stream attached to the block by the external tx-artifact verifier;
2. `S_0 = (0, lambda_0, tau_0, eta_0, T_0, z_384)`;
3. for every `1 <= i <= n`, the one-step statement `Q_i = (1, Sigma_state(S_{i-1}), Sigma_state(S_i))` has a valid witness `W_step[i]` under `BlockStepRelation_v*`;
4. `T_acc[0,n]` starts from the canonical empty-prefix accumulator `A_0 in LCCCS_step(Q_pref[0])`, ends at the terminal accumulator `A_n`, and for each round `i` soundly combines `A_{i - 1}` with the exact committed one-step claim `u_i = CCCS_step(Q_i)` into the next prefix accumulator for `Q_pref[i]`;
5. `i(S_i) = i` for every `0 <= i <= n`;
6. `lambda_i = AbsorbLeaf(lambda_{i-1}, L_i)` for every `i`;
7. `tau_i = P2(tau_{i-1} + iota(pack_C(R_i.statement_hash)))` for every `i`;
8. `eta_i = AbsorbReceipt(eta_{i-1}, R_i)` for every `i`;
9. `C_leaf(B) = proj_6(lambda_n)`, so the hidden recursive execution is bound to the exact ordered verified-leaf stream `L(B)`;
10. `tx_statements_commitment(B) = proj_6(tau_n)`;
11. `C_receipt(B) = proj_6(eta_n)`;
12. every anchor `anchor(Xi_i)` is present in the bounded history carried by `T_{i-1}`;
13. `T_n` is exactly the result of appending all non-zero commitments in the ordered verified tx views `V_1, ..., V_n` to `T_0`;
14. every non-zero nullifier appears at most once in the block, because the public duplicate check passes and each insertion into the internal sparse set must prove prior absence;
15. the public tuple components equal the current block semantics from Section 2.5.

### Theorem 6.2: constant wire size

If `RecursiveBackend_v2(v*)` provides a fixed serialized terminal accumulator/decider artifact size `|Artifact_step(B)| = L_art_step(v*)`, then:

`|Pi_block(B)| = L_art_step(v*) + 532`

for every admissible block size `n` representable in the live `u32` transaction-count field.

### Corollary 6.3: no padding cheat

This construction does not obtain constancy by padding every block to a consensus cap or by assuming a proof-system `N_max`.

Reason:

1. every unary accumulation round consumes exactly one real verified leaf `L_i`;
2. every accumulation round extends the prefix summary by exactly one leaf through the sound CCS-reduction law and `ComposeCheck(Q_pref[i - 1], Q_i, Q_pref[i]) = 1`;
3. the full verifier reconstructs `S_0`, `S_n`, and therefore `Q_pref[n] = (n, Sigma_state(S_0), Sigma_state(S_n))` from public data and deterministic replay;
4. `Verify_decide_step` checks the terminal accumulator `A_n` against that exact reconstructed terminal prefix summary, while `InitAccumulator_step` is fixed to the canonical base summary;
5. `C_leaf`, `C_stmt`, and `C_receipt` are derived from the same replayed terminal state bound to that exact terminal prefix summary.

So a proof for `n` transactions cannot be re-labeled as a proof for `N > n` transactions by hidden dummy leaves, padded empty segments, or a silent recursive-cap assumption. Extra leaves would change `n`, `C_leaf`, `C_stmt`, and `C_receipt`.

### Proposition 6.4: prover cost is linear

For fixed repo parameters `M_in = 2`, `M_out = 2`, `D = 32`, `H = 100`, and sparse-set depth `384`:

- one step instance has constant local work:
  - one verified-leaf transition over fixed-width `L_i`;
  - at most two commitment-tree appends;
  - one anchor-membership check against a window of size `100`;
  - at most two sparse-set insertions over depth `384`;
- one accumulation round has constant local work:
  - one constant-size CCS-reduction proof;
  - one constant-size random-linear-combination fold proof over one running `LCCCS` instance and one temporary linearized step instance;
  - one constant-size low-norm normalization proof;
- one finalization step has constant local work:
  - one constant-size accumulator-decider proof;
  - serialization of one constant-size terminal accumulator object and decider header.

There are exactly `n` unary accumulation rounds, so total proving work is still `Theta(n)`. The correct asymptotic story is:

- constant on-chain proof bytes;
- constant proof-visible tuple;
- linear prover work and private witness.

## 7. What The Repo Still Does Not Have

The checked-in repo still lacks `RecursiveBackend_v2(v*)`.

Concretely, it lacks:

1. a witness-sound exact step proof plus a Neo/HyperNova-style `Pi_CCS` layer that maps `BlockStepRelation_v*` into temporary linearized `LCCCS_step(Q_i)` instances;
2. a running `LCCCS` accumulator over the active pay-per-bit Ajtai commitment module, together with sound `Pi_RLC` folding and `Pi_DEC` normalization;
3. a constant-size decider proof `pi_dec[0,n]` that proves the hidden terminal accumulator `A_n` together with a valid private unary accumulation transcript;
4. the integration and serialization path that ships `(Header_dec_step(v*, Q_pref[n]), A_n, pi_dec[0,n])` together with `Y_rec(B)` as the constant-size block artifact and verifier input.

Until those exist, the repo still has verified-leaf aggregation, not a recursive block-proof backend.

## 8. Product Consequences

If this recursive path becomes real, the product changes are narrow and explicit:

1. `receipt_root` stops being the block-proof object on the constant-size path;
2. the per-transaction tx-artifact verification stage stays exactly where it is today;
3. the semantic tuple `Y_sem(B)` stays exactly the current one;
4. the recursive proof-visible tuple becomes `Y_rec(B) = (Y_sem(B), C_leaf(B), C_receipt(B), Sigma_tree(T_0), Sigma_tree(T_n))`;
5. the recursive block artifact becomes `(Header_dec_step(v*, Q_pref[n]), A_n, pi_dec[0,n])` rather than a second wrapper proof over a separate seal relation;
6. the Plonky3-specific auxiliaries `(alpha_perm, beta_perm)` and the linear nullifier vectors disappear from the on-chain block-proof payload;
7. the recursive core uses Poseidon2 verified-leaf/receipt/state commitments, Poseidon2 recursive Fiat-Shamir, and the exact sparse nullifier set from Section 2.9;
8. consensus still recomputes the ordered verified-leaf commitment, ordered receipt commitment, `tx_statements_commitment`, the exact append-state transition, the internal sparse-set root, kernel roots, `nullifier_root`, and `da_root` outside the proof and rejects mismatches.

Anything else is a different product.

## 9. Falsification Criteria

The design is false if any of the following happen in implementation:

1. `Artifact_step(B)` bytes vary with transaction count.
2. The public tuple varies in serialized length with transaction count.
3. The on-chain artifact serializes per-transaction objects, child proofs, nullifier vectors, sorted-nullifier vectors, or `receipt_root` records.
4. The implementation changes the semantics of `Y_sem(B)`.
5. The recursive arithmetic relies on in-relation BLAKE3 without an explicit arithmetization.
6. The recursive public tuple omits `C_leaf(B)` or `C_receipt(B)` and therefore fails to bind the exact ordered verified-leaf stream or the ordered verified receipt stream that the current product already checks before block-artifact verification.
7. The implementation claims the current checked-in `verify_leaf(..., expected_packed, ...)` / `fold_pair` API is already sufficient.
8. The implementation leaves the sparse nullifier set or the canonical public `SparseSetRoot` rebuild underspecified relative to Section 2.9.
9. The recursive public tuple omits `Sigma_tree(T_0)` / `Sigma_tree(T_n)` or otherwise leaves the exact append state underbound while claiming anchor-membership soundness.
10. The implementation never instantiates `BlockStepRelation_v*` as a concrete SuperNeo relation with fixed public statement arity `13`, fails to bind the decider profile and canonical initializer in `Header_dec_step`, or reintroduces an unstated second wrapper proof system instead of shipping the terminal accumulator-plus-decider artifact directly.
11. The implementation omits the canonical base-state constraint `S_0 = (0, lambda_0, tau_0, eta_0, T_0, z_384)`, the one-step leaf update `lambda_i = AbsorbLeaf(lambda_{i-1}, L_i)`, or the one-step counter constraint `i(S_i) = i(S_{i-1}) + 1`.
12. The implementation claims constancy only by padding on-chain artifacts to a maximum capacity or by introducing a hidden proof-system `N_max`.

Those are direct failures of the invariant.
