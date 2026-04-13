# Constant-Size Recursive Block Proof

This note states the recursive block-proof object as an actual proof construction, not as a placeholder backend. The construction here is:

- not Plonky3;
- not the checked-in `verify_leaf(..., expected_packed, ...)` / `fold_pair` lane;
- not a fake accumulator/decider whose soundness is delegated to unnamed future code.

The recursive object is a direct Smallwood proof-carrying recursion line over two alternating recursion profiles. The shipped on-chain artifact is one terminal recursive proof of fixed width plus one constant-size public tuple.

The visual blackboards live in [docs/assets/constant-recursive-block-proof-blackboards.svg](/Users/pldd/Projects/Reflexivity/Hegemon/docs/assets/constant-recursive-block-proof-blackboards.svg). The implementation plan lives in [.agent/CONSTANT_SIZE_RECURSIVE_BLOCK_PROOF_EXECPLAN.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/CONSTANT_SIZE_RECURSIVE_BLOCK_PROOF_EXECPLAN.md).

## 1. Hard Invariant

Let `B = (tx_1, ..., tx_n)` be any non-empty shielded block accepted by consensus under one fixed protocol line, and let `Pi_block(B)` be the proof artifact shipped on chain for that block.

The hard invariant is:

1. There exists one constant `C_block` such that `|ser_pi_block(B)| = C_block` for every admissible `n`.
2. The verifier-facing public tuple has constant arity and constant serialized length.
3. The serialized artifact contains no linear payloads:
   - no per-transaction proof bytes,
   - no per-transaction public inputs,
   - no `packed_public_values`,
   - no representative child proofs,
   - no nullifier vectors,
   - no sorted-nullifier vectors,
   - no `receipt_root` record lists.
4. Acceptance implies the real block truth surface:
   - every included transaction proof is valid,
   - the ordered transaction statement hashes absorb to the published `tx_statements_commitment`,
   - the append-only commitment-tree state evolves from the parent state to the child state by appending the block commitments in order,
   - every transaction anchor is a member of the bounded accepted-root history at the point where that transaction is processed,
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
   - constant-size,
   - recomputable by consensus from the parent state, block body, and the externally verified tx-artifact stream that current import already derives before checking the block artifact,
   - semantically inert auxiliaries rather than replacements for the tuple above.

This invariant says nothing about prover time. Prover work may grow linearly with `n`. Only the shipped artifact and its public tuple must stay constant-size.

## 2. Fixed Repo Semantics

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

### 2.3 Statement, verified-leaf, and receipt commitments

Let `enc: C -> F^6` be the canonical 48-byte-to-six-field map already used in the block commitment prover. Let `iota: F^6 -> F^12` inject into the first six coordinates and set the last six coordinates to zero. Let `P2: F^12 -> F^12` be one full Poseidon2 permutation under the live parameters.

Define the exact statement sponge:

- `tau_0 = (d_stmt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)`;
- `tau_i = P2(tau_{i-1} + iota(enc(H_stmt(P_i))))`;
- `C_stmt(B) = proj_6(tau_n)`.

Define the exact verified-leaf commitment over the current fixed-width verified-leaf payload:

- `L_i = (R_i, V_i, Xi_i)` where:
  - `R_i` is the canonical receipt,
  - `V_i` is the canonical tx public view,
  - `Xi_i` is the canonical serialized STARK public-input object;
- `pack_L(L_i) in F^114` is the canonical 114-limb leaf encoding:
  - `24` limbs for the receipt public statement,
  - `90` limbs for the tx/stark witness assignment from the live `TxLeafPublicRelation` seam;
- `lambda_0 = (d_leaf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)`;
- `lambda_i = AbsorbLeaf(lambda_{i-1}, L_i)` by 19 Poseidon2 rate-6 absorbs of `pack_L(L_i)`;
- `C_leaf(B) = proj_6(lambda_n)`.

Define the exact receipt commitment:

- `pack_R(R_i) = pack_C(h_i) || pack_C(p_i) || pack_C(d_i) || pack_C(rho_i) in F^24`;
- `eta_0 = (d_receipt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)`;
- `eta_i` is the four-absorb Poseidon2 update over `statement_hash`, `proof_digest`, `public_inputs_digest`, and `verifier_profile`;
- `C_receipt(B) = proj_6(eta_n)`.

The verified-leaf and receipt commitments are constant-size replacements for the current linear receipt-root surface and the previously underbound tx-leaf stream.

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

`T' = Append*(T, tx)`.

### 2.5 Internal sparse nullifier set

The public `nullifier_root(B)` stays unchanged. Inside recursion, uniqueness is enforced with an internal Poseidon sparse set keyed by the nullifier bits.

Define the sparse-set root `U_i` exactly as in the current note:

- depth `384`,
- absent leaf `z_0 = 0^48`,
- present leaf `o_0 = P2Hash_C(d_nf_present; 1)`,
- internal node hash `Node(l, r) = merkle_node_bytes(l, r)`,
- default subtree roots `z_h`,
- `NonMember(U, nf, W_nf)` and `InsertRoot(U, nf, W_nf)` from the path witness,
- `Insert*(U, tx)` by sequential insertion of the non-zero nullifiers of `tx`.

For outer deterministic replay, define:

`SparseSetRoot(X)`

to be the canonical root of the full sparse tree whose leaves are `o_0` for `nf in X` and `z_0` otherwise. Then, after a public duplicate check,

`U_pub(B) = SparseSetRoot(Set(NZ_nf(tx_1), ..., NZ_nf(tx_n)))`.

### 2.6 Semantic tuple and recursive proof-visible tuple

The current semantic block tuple is:

`Y_sem(B) = (n, C_stmt(B), root_prev(B), root_new(B), kernel_prev(B), kernel_new(B), nullifier_root(B), da_root(B))`

with serialized size:

- `4` bytes for `n`,
- `7 * 48 = 336` bytes for the seven 48-byte roots/commitments,
- total `|ser_y_sem(B)| = 340` bytes.

The recursive proof-visible tuple is:

`Y_rec(B) = (Y_sem(B), C_leaf(B), C_receipt(B), Sigma_tree(T_0), Sigma_tree(T_n))`

Define the canonical byte serializers:

- `ser_C48(c) = c` for `c in C = {0,1}^384`;
- `ser_F6(x_0, ..., x_5) = le_u64(x_0) || ... || le_u64(x_5)` for elements of `F^6`;
- `ser_y_sem(B) = u32_le(n) || ser_F6(C_stmt(B)) || ser_C48(root_prev(B)) || ser_C48(root_new(B)) || ser_C48(kernel_prev(B)) || ser_C48(kernel_new(B)) || ser_C48(nullifier_root(B)) || ser_C48(da_root(B))`;
- `ser_y_rec(B) = ser_y_sem(B) || ser_F6(C_leaf(B)) || ser_F6(C_receipt(B)) || ser_F6(Sigma_tree(T_0)) || ser_F6(Sigma_tree(T_n))`.

so:

- `|ser_y_rec(B)| = 340 + 48 + 48 + 48 + 48 = 532` bytes.

This is the honest split:

- `Y_sem(B)` preserves the current semantics exactly;
- `Y_rec(B)` adds only the constant-size bindings needed for recursive soundness.

### 2.7 Hash boundary

The corrected split is:

1. `BLAKE3-384` remains the hash for existing external semantics:
   - `H_stmt(P)`,
   - canonical receipt fields `proof_digest` and `public_inputs_digest`,
   - `nullifier_root(B)`,
   - `da_root(B)`,
   - legacy byte-oriented `digest_statement(...)` outside recursive arithmetic.
2. `Poseidon2` is the only hash used inside recursive arithmetic for:
   - `C_leaf(B)`,
   - `C_receipt(B)`,
   - `Sigma_tree(T)`,
   - `Sigma_state(S)`,
   - internal sparse nullifier-set updates,
   - recursive Fiat-Shamir and recursive proof authentication.
3. The recursive verifier does not arithmetize BLAKE3.

## 3. Internal Recursive State

After processing `i` verified leaves, define:

`S_i = (i, lambda_i, tau_i, eta_i, T_i, U_i)`

with:

- `i` the processed verified-leaf count,
- `lambda_i` the exact verified-leaf-stream sponge state,
- `tau_i` the exact statement sponge state,
- `eta_i` the exact receipt sponge state,
- `T_i` the exact append state,
- `U_i` the internal sparse-set root.

Base state:

- `S_0 = (0, lambda_0, tau_0, eta_0, T_0, z_384)`.

Define the exact internal digests:

`Sigma_tree(T) = P2Hash_F(d_tree; ell, pack_C(root), pack_C(f_0), ..., pack_C(f_{D-1}), m, pack_C(r_0), ..., pack_C(r_{H-1})) in F^6`

and

`Sigma_state(S) = P2Hash_F(d_state; i, lambda_i, tau_i, eta_i, Sigma_tree(T_i), pack_C(U_i)) in F^6`.

These are the fixed-size handles threaded through recursion.

## 4. Direct Recursive Smallwood Construction

### 4.1 Fixed protocol line and product boundary

Fix one protocol line:

- `v* = SMALLWOOD_CANDIDATE_VERSION_BINDING = (CIRCUIT_V2, CRYPTO_SUITE_BETA)`;
- `b* = tx_proof_backend_for_version(v*) = SmallwoodCandidate`;
- `a* = SmallwoodArithmetization::Bridge64V1`;
- `rho_leaf* = experimental_native_tx_leaf_verifier_profile_for_params(native_backend_params())`.

This is the live default line today in:

- [protocol/versioning/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/protocol/versioning/src/lib.rs#L174)
- [circuits/transaction/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs#L227)

The product boundary is explicit:

- ordered tx artifacts are still individually verified outside the recursive block proof;
- the recursive block proof consumes the ordered verified-leaf stream `L(B)`;
- on the recursive product lane, the recursive block proof is the one constant-size replacement for the current block-level pair `(commitment proof, receipt_root)`, not a replacement for the tx-artifact verifier.

### 4.2 Recursive Smallwood profiles

The recursive backend is the pair

`SWREC(v*) = (SmallwoodRecA_v1(v*), SmallwoodRecB_v1(v*))`.

The recursive relation family is the finite set

`K_rec(v*) = {BaseA, StepA, StepB}`.

Each admissible recursive proof line is one pair `(tau, k)` with:

- `(A, BaseA)`,
- `(A, StepA)`,
- `(B, StepB)`.

Each recursive profile is a recursion-friendly Smallwood proof system with:

- the same Goldilocks field;
- the same row-polynomial PIOP/PCS decomposition as the current Smallwood engine;
- one common recursive config `Cfg_rec(v*)`;
- a Poseidon2 transcript/XOF in place of the current BLAKE3 transcript;
- Poseidon2-based DECS authentication in place of the current byte-oriented tree;
- one canonical fixed-length serializer `ser_sw_rec`.

The two profiles differ only in:

- domain separators,
- verifier-key constants,
- which opposite profile they verify inside recursion.

Profile `A` verifies `B`. Profile `B` verifies `A`. This two-profile cycle is the explicit way the derivation avoids self-reference. There is no hidden fixed-point lemma and no proof-system `N_max`.

Define the exact common recursive config

`Cfg_rec(v*) = (row_count_rec, packing_factor_rec, constraint_degree_rec, linear_constraint_count_rec, witness_size_rec, constraint_count_rec, nb_polys_rec, degree_rec, width_rec, delta_rec, nb_lvcs_rows_rec, nb_lvcs_cols_rec, nb_lvcs_opened_combi_rec, open_schedule_spec_rec)`.

This is the full size-driving `SmallwoodConfig` tuple for the recursive line. It is not a semantic summary. It is the exact collection of dimensions and vectors that the recursive verifier uses in place of the current `SmallwoodConfig::new(...)` output when it runs the analogue of `validate_proof_shape(...)`.

Define:

- `ser_cfg_rec(Cfg_rec(v*))` as the unique length-tagged encoding of that tuple;
- `shape_digest_rec(v*) = digest_shape_rec(ser_cfg_rec(Cfg_rec(v*))) in Digest32`;
- `open_schedule_rec(v*) = open_schedule_spec_rec`, the exact ordered opening-point schedule and multiplicity vector carried inside `Cfg_rec(v*)`;
- `open_count_rec(v*) = |open_schedule_rec(v*)|`.

All three admissible recursive relations are compiled into that same exact config:

- `compiled_cfg(Base_A_v*) = Cfg_rec(v*)`;
- `compiled_cfg(Step_A_v*) = Cfg_rec(v*)`;
- `compiled_cfg(Step_B_v*) = Cfg_rec(v*)`.

For `Base_A_v*`, the witness coordinates used only by later step proofs are present in the common envelope but constrained to the canonical zero encoding. This is not an on-chain padding trick. It is the typing rule that makes the first `A` proof and every later `A` proof inhabit the same fixed-width serializer and the same verifier interface.

Write the recursive proof object:

`pi_rec^{tau,k} = (salt, nonce, h_piop, piop, pcs, opened_witness)`

for admissible `(tau, k)`.

Define the exact serializer:

`ser_sw_rec(pi_rec^{tau,k})`

as the unique concatenation of:

- `salt`,
- `nonce`,
- `h_piop`,
- the fixed `piop` coefficient blocks,
- the fixed `pcs` opening blocks,
- the fixed opened-row-scalar bundle.

Because every array length is fixed by `Cfg_rec(v*)`:

`|ser_sw_rec(pi_rec^{A,BaseA})| = |ser_sw_rec(pi_rec^{A,StepA})| = |ser_sw_rec(pi_rec^{B,StepB})| = L_rec(v*)`.

### 4.3 Recursive verifier object

For each admissible `(tau, k)`, define:

- `relation_id_{tau,k}(v*) in Digest32`;
- `vk_digest_{tau,k}(v*) in Digest32`;
- `shape_digest_rec(v*) in Digest32` from Section 4.2.

Then define the explicit recursive verifier descriptor

`R_{tau,k}(v*) = (relation_id_{tau,k}(v*), shape_digest_rec(v*), vk_digest_{tau,k}(v*))`.

The recursive verifier is

`VerifySw_{tau,k}(R_{tau,k}, P, pi)`.

It is the arithmetic transcription of the current `verify_candidate(...)` flow in [circuits/transaction/src/smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs#L250), with the following constructive replacements rather than a new proof family:

1. `bincode` parsing of `SmallwoodProof` is replaced by exact-consumption parsing under `ser_sw_rec`;
2. `hash_piop_transcript(...)` is replaced by a Poseidon2 field digest `HashPiop_rec(...)`;
3. `choose_opening_nonce(...)` and `xof_piop_opening_points(...)` are replaced by a Poseidon2 duplex/XOF `XOF_rec(...)`;
4. the byte-oriented DECS authentication tree is replaced by a Poseidon2 field tree over the same fixed opened-row schedule;
5. the current proof-shape checks in `validate_proof_shape(...)` remain, but are applied to the exact common config `Cfg_rec(v*)`;
6. the PCS and PIOP algebra stays the same row-polynomial algebra as the current Smallwood engine.

The recursive transcript/authentication surface is:

- `HashPiop_rec(X) = P2Hash_F(d_piop_rec; X)`;
- `pack32(Digest32)` is the canonical injective 32-byte to eight-field encoding `u32_0 || ... || u32_7` in little-endian 32-bit limbs;
- `pack_desc(R_{tau,k}) = pack32(relation_id_{tau,k}(v*)) || pack32(shape_digest_rec(v*)) || pack32(vk_digest_{tau,k}(v*)) in F^{24}`;
- `SeedXof_rec(R_{tau,k}, P, nonce, h_piop) = P2Hash_F(d_xof_rec; pack_desc(R_{tau,k}), bind_rec(P), nonce, h_piop)`;
- `XOF_rec(nonce, h_piop, R_{tau,k}, P)` is the Poseidon2 duplex stream obtained by repeatedly squeezing from `SeedXof_rec(...)` until the exact ordered schedule `open_schedule_rec(v*)` has been populated, i.e. exactly `open_count_rec(v*)` field challenges are produced and consumed in that fixed order;
- `Leaf_decs_rec(row) = P2Hash_F(d_decs_leaf_rec; row)`;
- `Node_decs_rec(l, r) = P2Hash_F(d_decs_node_rec; l, r)`;
- every DECS authentication path in the recursive proof is verified in that Poseidon2 tree instead of the current byte tree.

So the direct recursive Smallwood object is not “new cryptography around the proof.” It is the checked-in Smallwood PCS/PIOP algebra with one explicit field-native transcript/XOF layer and one explicit field-native authentication tree.

It performs:

1. exact-consumption parsing of `pi` under `ser_sw_rec`;
2. descriptor checks that `pi` is being verified under the explicit triple `(relation_id_{tau,k}, shape_digest_rec, vk_digest_{tau,k})`;
3. fixed-shape checks corresponding to the current `validate_proof_shape(...)`, but against the full `Cfg_rec(v*)` tuple rather than an implicit profile-local config;
4. derivation of opening points

   `eval_points = XOF_rec(nonce, h_piop, R_{tau,k}, P)`;

5. PCS transcript recomputation from:
   - the exact common recursive config `Cfg_rec(v*)`,
   - the explicit descriptor `R_{tau,k}`,
   - the public statement `P`,
   - `salt`,
   - `open_schedule_rec(v*)`,
   - `eval_points`,
   - the opened row scalars,
   - the PCS proof body;
6. PIOP transcript recomputation from:
   - the same exact common recursive config `Cfg_rec(v*)`,
   - the explicit descriptor `R_{tau,k}`,
   - the public statement `P`,
   - the PCS transcript,
   - `open_schedule_rec(v*)`,
   - `eval_points`,
   - the opened row scalars,
   - the PIOP proof body;
7. acceptance iff the recomputed transcript digest equals `h_piop` and all PCS/PIOP equalities hold.

Every step in `VerifySw_{tau,k}` is field arithmetic plus Poseidon2 transcript/authentication checks, so it is arithmetizable as one fixed relation. That is the cryptographic core missing from the fake digest-attestation versions.

### 4.4 Recursive prefix statement and base proof

The internal recursive statement is the constant-size prefix summary:

`P_i = (i, sigma_0, sigma_i, C_leaf_i, C_stmt_i, C_receipt_i, sigma_tree_0, sigma_tree_i)`

with:

- `sigma_0 = Sigma_state(S_0)`,
- `sigma_i = Sigma_state(S_i)`,
- `C_leaf_i = proj_6(lambda_i)`,
- `C_stmt_i = proj_6(tau_i)`,
- `C_receipt_i = proj_6(eta_i)`,
- `sigma_tree_0 = Sigma_tree(T_0)`,
- `sigma_tree_i = Sigma_tree(T_i)`.

Its exact public input vector is:

`public_inputs_rec(P_i) = i || sigma_0 || sigma_i || C_leaf_i || C_stmt_i || C_receipt_i || sigma_tree_0 || sigma_tree_i in F^43`.

Its exact byte encoding is:

`stmt_bytes_rec(P_i) = u32_le(i) || le_u64^6(sigma_0) || le_u64^6(sigma_i) || le_u64^6(C_leaf_i) || le_u64^6(C_stmt_i) || le_u64^6(C_receipt_i) || le_u64^6(sigma_tree_0) || le_u64^6(sigma_tree_i)`.

Write:

- `statement_digest_rec(P_i) = digest_statement(stmt_bytes_rec(P_i))`;
- `bind_rec(P_i) = public_inputs_rec(P_i)`.

The base relation is one fixed recursive Smallwood relation:

`Base_A_v*(P_0)`

It is the `A`-profile specialization with relation kind `BaseA`, public statement `P_0`, and witness

`W_base = (T_0, pi_prev_zero, P_prev_zero, L_zero, a_zero, M_zero)`,

where the latter five coordinates are the canonical zero encodings occupying the reserved recursive-envelope slots that later `Step_A_v*` proofs use live.

`Base_A_v*` accepts iff:

1. `S_0 = (0, lambda_0, tau_0, eta_0, T_0, z_384)`;
2. `P_0 = (0, Sigma_state(S_0), Sigma_state(S_0), proj_6(lambda_0), proj_6(tau_0), proj_6(eta_0), Sigma_tree(T_0), Sigma_tree(T_0))`.

The base proof is:

`pi_0^{A,BaseA} = ProveSw_{A,BaseA}(R_{A,BaseA}, Base_A_v*, P_0; W_base)`.

This proof is not shipped on chain. It is the private root of the recursive chain.

## 5. Exact Verified-Leaf Boundary

The recursive step does not consume an abstract "transaction." It consumes exactly the current verified tx-leaf object.

For one transaction index `i`, define:

`L_i = (R_i, V_i, Xi_i)`

as in Section 2.3.

Write:

`leaf_input_i = pack_L(L_i) in F^{114}`.

Its exact source is the current `TxLeafPublicRelation` seam:

- the 24-limb receipt public statement encoding from [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L852),
- the 90-limb tx/stark witness encoding from [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L400) and [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs#L1936).

The recursive construction is only allowed to consume that ordered verified stream, not an arbitrary hidden alternative.

## 6. One-Step Transition Relation

Use the exact one-step summary:

`Q_i = (1, sigma_{i-1}, sigma_i)`

with:

- `sigma_{i-1} = Sigma_state(S_{i-1})`,
- `sigma_i = Sigma_state(S_i)`.

Its exact relation encoding is:

- `artifact_version_step(v*) = native_backend_params().artifact_version(b"recursive-block-step-v1")`;
- `relation_id_step(v*) = RelationId::from_label("hegemon.smallwood.block-step.v1.c2.k2.bridge64")`;
- `stmt_bytes_step(Q_i) = u32_le(1) || le_u64^6(sigma_{i-1}) || le_u64^6(sigma_i)`;
- `public_inputs_step(Q_i) = 1 || sigma_{i-1} || sigma_i`, exactly `13` field elements;
- `statement_digest_step(Q_i) = digest_statement(stmt_bytes_step(Q_i))`.

Define the witness:

`W_step[i] = (S_{i-1}, S_i, L_i, a_i, M_i)`.

`BlockStepRelation_v*` accepts iff:

1. `Sigma_state(S_{i-1}) = sigma_{i-1}`;
2. `Sigma_state(S_i) = sigma_i`;
3. `i(S_i) = i(S_{i-1}) + 1`;
4. `R_i.verifier_profile = rho_leaf*`;
5. `V_i.version = v*`;
6. `lambda_i = AbsorbLeaf(lambda_{i-1}, L_i)`;
7. `tau_i = P2(tau_{i-1} + iota(pack_C(R_i.statement_hash)))`;
8. `eta_i = AbsorbReceipt(eta_{i-1}, R_i)`;
9. `anchor(Xi_i) = Xi_i.merkle_root` appears in `R_hist(T_{i-1})` at index `a_i`;
10. `T_i = Append*(T_{i-1}, V_i)` where the appended commitments are the non-zero commitments from `V_i.commitments`;
11. `U_i = Insert*(U_{i-1}, V_i)` using the path witnesses in `M_i`.

This closes the real local soundness holes:

- one step means exactly one tx;
- the counter advances by exactly one;
- the exact verified-leaf payload is absorbed;
- anchor admissibility and nullifier uniqueness are part of the proved transition.

## 7. Recursive Step Proofs

For `tau in {A, B}`, let `opp(tau)` be the opposite profile. For each step, let `k_prev(i, tau)` be the explicit previous-proof relation kind:

- if `tau = A`, then `k_prev(i, tau) = StepB`;
- if `tau = B` and `i = 1`, then `k_prev(i, tau) = BaseA`;
- if `tau = B` and `i > 1`, then `k_prev(i, tau) = StepA`.

The step relation `Step_tau_v*(P_i)` is one fixed recursive Smallwood relation with public statement `P_i` and witness

`W_rec[i]^tau = (k_prev(i, tau), P_{i-1}, pi_{i-1}^{opp(tau),k_prev(i, tau)}, S_{i-1}, S_i, L_i, a_i, M_i)`.

`Step_tau_v*` accepts iff:

1. `k_prev(i, tau) = StepB` if `tau = A`;
2. `k_prev(i, tau) = BaseA` iff `tau = B` and `i = 1`;
3. `k_prev(i, tau) = StepA` iff `tau = B` and `i > 1`;
4. `VerifySw_{opp(tau),k_prev(i,tau)}(R_{opp(tau),k_prev(i,tau)}, P_{i-1}, pi_{i-1}^{opp(tau),k_prev(i,tau)}) = 1`;
5. `i = 1` if `k_prev(i, tau) = BaseA`;
6. `P_{i-1}` matches the witness state `S_{i-1}` exactly:
   - previous count is `i - 1`,
   - previous start digest is `sigma_0`,
   - previous end digest is `Sigma_state(S_{i-1})`,
   - previous cumulative commitments are `proj_6(lambda_{i-1})`, `proj_6(tau_{i-1})`, `proj_6(eta_{i-1})`,
   - previous append-state digests are `sigma_tree_0` and `Sigma_tree(T_{i-1})`;
7. `BlockStepRelation_v*(S_{i-1}, S_i, L_i, a_i, M_i)` holds;
8. `P_i` matches the updated witness state `S_i` exactly:
   - current count is `i`,
   - start digest `sigma_0` is preserved from `P_{i-1}`,
   - end digest is `Sigma_state(S_i)`,
   - cumulative commitments are `proj_6(lambda_i)`, `proj_6(tau_i)`, `proj_6(eta_i)`,
   - append-state digests are the same `sigma_tree_0` and the new `Sigma_tree(T_i)`.

This is the constructive parent satisfiability law:

- verify the previous recursive proof,
- check one exact tx-leaf transition,
- emit the new prefix statement.

The recursive proof chain is:

- `pi_0^{A,BaseA} = ProveSw_{A,BaseA}(R_{A,BaseA}, Base_A_v*, P_0; W_base)`;
- for odd `i`, `pi_i^{B,StepB} = ProveSw_{B,StepB}(R_{B,StepB}, Step_B_v*, P_i; W_rec[i]^B)`;
- for even `i`, `pi_i^{A,StepA} = ProveSw_{A,StepA}(R_{A,StepA}, Step_A_v*, P_i; W_rec[i]^A)`.

Because `Base_A_v*`, `Step_A_v*`, and `Step_B_v*` all inhabit the same exact config `Cfg_rec(v*)`, every recursive proof in the chain has the same byte length `L_rec(v*)`, including the base proof consumed by the first `B`-step.

## 8. On-Chain Artifact And Full Verifier

Define:

- `tau(n) = A` if `n` is even and `tau(n) = B` if `n` is odd;
- `k_term(n) = StepA` if `n` is even and `k_term(n) = StepB` if `n` is odd;
- `P_n` the terminal prefix statement from Section 4.4;
- `pi_n^{tau(n),k_term(n)}` the terminal recursive proof from Section 7.

The recursive header is:

`Header_rec_step(v*, tau, k, P) = (artifact_version_rec(v*), tx_line_digest_v*, rec_profile_tag_tau, terminal_relation_kind_k, relation_id_base_A(v*), relation_id_step_A(v*), relation_id_step_B(v*), shape_digest_rec(v*), vk_digest_base_A(v*), vk_digest_step_A(v*), vk_digest_step_B(v*), proof_encoding_digest_rec(v*), proof_bytes_rec(v*), statement_digest_rec(P))`.

Its canonical serializer is:

`ser_header_rec_step(Header_rec_step(v*, tau, k, P))`

defined as the unique concatenation, in exactly that field order, of:

- `u32_le(artifact_version_rec(v*))`;
- `pack32(tx_line_digest_v*)`;
- `u32_le(tag_profile(tau))` with `tag_profile(A) = 1`, `tag_profile(B) = 2`;
- `u32_le(tag_kind(k))` with `tag_kind(BaseA) = 1`, `tag_kind(StepA) = 2`, `tag_kind(StepB) = 3`;
- `pack32(relation_id_base_A(v*))`;
- `pack32(relation_id_step_A(v*))`;
- `pack32(relation_id_step_B(v*))`;
- `pack32(shape_digest_rec(v*))`;
- `pack32(vk_digest_base_A(v*))`;
- `pack32(vk_digest_step_A(v*))`;
- `pack32(vk_digest_step_B(v*))`;
- `pack32(proof_encoding_digest_rec(v*))`;
- `u32_le(proof_bytes_rec(v*))`;
- `pack32(statement_digest_rec(P))`.

So the header width is one protocol constant:

`L_hdr_rec(v*) = |ser_header_rec_step(Header_rec_step(v*, tau, k, P))| = 336 bytes`.

The shipped recursive artifact is:

`Artifact_rec(B) = (Header_rec_step(v*, tau(n), k_term(n), P_n), pi_n^{tau(n),k_term(n)})`.

The full on-chain block proof is:

`Pi_block(B) = (Artifact_rec(B), Y_rec(B))`.

There is no accumulator object `A_n` and no separate decider proof `pi_dec[0,n]`. The terminal recursive proof `pi_n^{tau(n),k_term(n)}` is itself the constant-size certificate that the base proof and all `n` one-step transitions exist.

The exact-consumption rule is:

- `ser_artifact_rec(B) = ser_header_rec_step(Header_rec_step(v*, tau(n), k_term(n), P_n)) || ser_sw_rec(pi_n^{tau(n),k_term(n)})`;
- `ser_pi_block(B) = ser_artifact_rec(B) || ser_y_rec(B)`;
- `|ser_header_rec_step(Header_rec_step(v*, tau(n), k_term(n), P_n))| = L_hdr_rec(v*) = 336`;
- `|ser_sw_rec(pi_n)| = proof_bytes_rec(v*) = L_rec(v*)`;
- `|ser_y_rec(B)| = 532`;
- trailing bytes, alternate encodings, and hidden sidecars are invalid.

Define `VerifyBlockRecursive(B, parent_state, verified_leaves, Pi_block)` as:

1. parse `Pi_block` into `(Artifact_rec, Y_rec(B))` by exact-consumption canonical decoding under `ser_pi_block` and reject if any byte remains unconsumed;
2. parse `Artifact_rec` into `(Header_rec_step, pi_n)` by exact-consumption canonical decoding under `ser_artifact_rec` and reject if `|ser_header_rec_step(Header_rec_step)| != L_hdr_rec(v*)`, if `|ser_sw_rec(pi_n)| != proof_bytes_rec(v*)`, or if any byte remains unconsumed;
3. check that `verified_leaves = (L_1, ..., L_n)` is exactly the ordered output of the current tx-artifact verifier for block `B`;
4. check `len(verified_leaves) = n`;
5. replay the exact verified-leaf sponge over `verified_leaves` to obtain `lambda_n` and compare `proj_6(lambda_n)` against `C_leaf`;
6. replay the exact statement-hash sponge over the canonical ordered statement-hash list to obtain `tau_n` and compare `proj_6(tau_n)` against `C_stmt`;
7. replay the exact receipt sponge over the canonical ordered receipt stream to obtain `eta_n` and compare `proj_6(eta_n)` against `C_receipt`;
8. reconstruct the exact pre-block append state `T_0` from `parent_state` and compare `root_prev(B)` plus `Sigma_tree(T_0)` against `(root_prev, sigma_tree_prev)`;
9. recompute the exact post-block append state `T_n = Append*(T_0, B)` and compare `root_new(B)` plus `Sigma_tree(T_n)` against `(root_new, sigma_tree_new)`;
10. extract the ordered public non-zero nullifier list `N_pub(B)`, check `|sort_unique(N_pub(B))| = |N_pub(B)|`, and set `U_n = SparseSetRoot(Set(N_pub(B)))`;
11. recompute `kernel_prev(B)` and `kernel_new(B)` from the corresponding shielded roots and compare;
12. recompute `nullifier_root(B)` with the current sorted-unique BLAKE3 rule and compare;
13. recompute `da_root(B)` with the current DA-root rule and compare;
14. form `S_0 = (0, lambda_0, tau_0, eta_0, T_0, z_384)` and `S_n = (n, lambda_n, tau_n, eta_n, T_n, U_n)`;
15. derive

    `P_n = (n, Sigma_state(S_0), Sigma_state(S_n), proj_6(lambda_n), proj_6(tau_n), proj_6(eta_n), Sigma_tree(T_0), Sigma_tree(T_n))`;

16. check that `Header_rec_step` matches `(artifact_version_rec(v*), tx_line_digest_v*, rec_profile_tag_{tau(n)}, k_term(n), relation_id_base_A(v*), relation_id_step_A(v*), relation_id_step_B(v*), shape_digest_rec(v*), vk_digest_base_A(v*), vk_digest_step_A(v*), vk_digest_step_B(v*), proof_encoding_digest_rec(v*), proof_bytes_rec(v*), statement_digest_rec(P_n))`;
17. verify `VerifySw_{tau(n),k_term(n)}(R_{tau(n),k_term(n)}, P_n, pi_n) = 1`.

This is the honest verifier boundary. Tx-artifact validity stays exactly where the current product already checks it: outside the recursive block proof. The recursive proof certifies that the terminal prefix statement `P_n` is reachable from the canonical base state by exactly `n` successive one-leaf transitions.

For the fixed protocol line `v*`, the block-proof size is:

`|ser_pi_block(B)| = L_hdr_rec(v*) + L_rec(v*) + 532`.

Because the two recursion profiles share one proof width and one header width, this is one constant independent of `n`.

## 9. Theorems

### Theorem 9.1: soundness of the full verifier

Assume:

1. the current tx-artifact verifier is sound, `verified_leaves = (L_1, ..., L_n)` is exactly its ordered output for block `B`, and `len(verified_leaves) = n`;
2. the domain-separated commitments and digests used as recursive handles are binding on their valid encoded domains:
   - `pack_L` and `C_leaf = proj_6(lambda_n)`,
   - `pack_R` and `C_receipt = proj_6(eta_n)`,
   - the statement-hash compression `H_stmt` and `C_stmt = proj_6(tau_n)`,
   - `Sigma_tree`,
   - `Sigma_state`,
   - `statement_digest_step`,
   - `statement_digest_rec`,
   - `ser_C48`,
   - `ser_F6`,
   - `ser_y_sem`,
   - `ser_y_rec`,
   - `ser_artifact_rec`,
   - `ser_pi_block`,
   - `pack32`,
   - `pack_desc`,
   - `ser_cfg_rec`,
   - `open_schedule_rec`,
   - `open_count_rec`,
   - `relation_id_base_A`, `relation_id_step_A`, `relation_id_step_B`,
   - `shape_digest_rec`,
   - `vk_digest_base_A`, `vk_digest_step_A`, `vk_digest_step_B`,
   - `proof_encoding_digest_rec`,
   - `proof_bytes_rec`,
   - `tag_profile`,
   - `tag_kind`,
   - the canonical header serializer `ser_header_rec_step`,
   - the canonical serializer `ser_sw_rec`;
3. `SmallwoodRecA_v1(v*)` and `SmallwoodRecB_v1(v*)` are sound proof systems for the explicitly keyed descriptors `R_{A,BaseA}`, `R_{A,StepA}`, and `R_{B,StepB}`;
4. the deterministic public recomputations in `VerifyBlockRecursive` faithfully implement the current consensus functions for verified-leaf commitment, receipt commitment, statement commitment, exact append-state transition, canonical sparse-set rebuild, public duplicate check, kernel roots, nullifier root, and DA root.

If `VerifyBlockRecursive(B, parent_state, verified_leaves, Pi_block)` accepts, then there exist raw states `S_0, ..., S_n` such that:

1. `verified_leaves = (L_1, ..., L_n)` is the ordered verified-leaf stream attached to the block by the external tx-artifact verifier;
2. `S_0 = (0, lambda_0, tau_0, eta_0, T_0, z_384)`;
3. for every `1 <= i <= n`, `W_step[i] = (S_{i-1}, S_i, L_i, a_i, M_i)` satisfies `BlockStepRelation_v*`;
4. there exists a recursive proof chain

   `pi_0^{A,BaseA}, pi_1^{tau(1),k_term(1)}, ..., pi_n^{tau(n),k_term(n)}`

   such that:
   - `pi_0^{A,BaseA}` proves the canonical base statement `P_0`,
   - each `pi_i^{tau(i),k_term(i)}` proves the exact `Step_{tau(i)}_v*(P_i)` relation against the previous proof `pi_{i-1}^{tau(i-1),k_prev(i,tau(i))}`,
   - `pi_n^{tau(n),k_term(n)}` is the shipped on-chain proof;
5. `i(S_i) = i` for every `0 <= i <= n`;
6. `lambda_i = AbsorbLeaf(lambda_{i-1}, L_i)` for every `i`;
7. `tau_i = P2(tau_{i-1} + iota(pack_C(R_i.statement_hash)))` for every `i`;
8. `eta_i = AbsorbReceipt(eta_{i-1}, R_i)` for every `i`;
9. `C_leaf(B) = proj_6(lambda_n)`, so the recursive execution is bound to the exact ordered verified-leaf stream `L(B)`;
10. `tx_statements_commitment(B) = proj_6(tau_n)`;
11. `C_receipt(B) = proj_6(eta_n)`;
12. every anchor `anchor(Xi_i)` is present in the bounded history carried by `T_{i-1}`;
13. `T_n` is exactly the result of appending all non-zero commitments in the ordered verified tx views `V_1, ..., V_n` to `T_0`;
14. every non-zero nullifier appears at most once in the block;
15. the public tuple components equal the current block semantics from Section 2.6.

### Theorem 9.2: constant wire size

If `SmallwoodRecA_v1(v*)` and `SmallwoodRecB_v1(v*)` share one fixed serializer `ser_sw_rec` of width `L_rec(v*)`, `Header_rec_step` has one fixed serializer of width `L_hdr_rec(v*)`, and `Y_rec(B)` has one fixed serializer `ser_y_rec` of width `532`, then:

`|ser_pi_block(B)| = L_hdr_rec(v*) + L_rec(v*) + 532`

for every admissible block size `n` representable in the live `u32` transaction-count field.

### Corollary 9.3: no padding cheat

This construction does not obtain constancy by padding every block to a consensus cap or by assuming a proof-system `N_max`.

Reason:

1. every recursive step proof consumes exactly one real verified leaf `L_i`;
2. `Step_tau_v*` enforces `i(S_i) = i(S_{i-1}) + 1`;
3. the full verifier reconstructs `S_0`, `S_n`, and the exact terminal statement `P_n` from public data and deterministic replay;
4. the shipped proof `pi_n^{tau(n),k_term(n)}` is checked against that exact terminal statement `P_n`;
5. `C_leaf`, `C_stmt`, and `C_receipt` are derived from the same replayed terminal state bound to `P_n`.

So a proof for `n` transactions cannot be re-labeled as a proof for `N > n` transactions by hidden dummy leaves, padded empty segments, or a silent recursive-cap assumption. Extra leaves would change `n`, `C_leaf`, `C_stmt`, and `C_receipt`.

### Proposition 9.4: prover cost is linear

For fixed repo parameters `M_in = 2`, `M_out = 2`, `D = 32`, `H = 100`, and sparse-set depth `384`:

- one local step witness has constant work:
  - one verified-leaf transition over fixed-width `L_i`,
  - at most two commitment-tree appends,
  - one anchor-membership check against a window of size `100`,
  - at most two sparse-set insertions over depth `384`;
- one recursive proof round has constant recursive work:
  - one fixed-size recursive verifier check of the previous proof,
  - one fixed-size one-step transition proof,
  - one fixed-size proof serialization.

There are exactly `n` recursive proof rounds after the base proof, so total proving work is `Theta(n)`.

## 10. What The Repo Still Does Not Have

The checked-in repo still lacks the direct recursive Smallwood object above.

Concretely, it lacks:

1. the recursion-friendly Smallwood pair `SmallwoodRecA_v1(v*)`, `SmallwoodRecB_v1(v*)` with Poseidon2 transcript, Poseidon2 DECS authentication, and one fixed serializer `ser_sw_rec`;
2. the fixed relations `Base_A_v*`, `Step_A_v*`, and `Step_B_v*` as concrete `SmallwoodConstraintAdapter` implementations;
3. the arithmetized verifier gadgets `VerifySw_{tau,k}` for the admissible keyed descriptors `(A, BaseA)`, `(A, StepA)`, and `(B, StepB)` inside those step relations;
4. the integration and serialization path that ships `(Header_rec_step(v*, tau(n), k_term(n), P_n), pi_n^{tau(n),k_term(n)})` together with `Y_rec(B)` as the constant-size block artifact and verifier input.

Until those exist, the repo still has verified-leaf aggregation and digest-attestation scaffolding, not a recursive block-proof backend.

## 11. Product Consequences

If this recursive path becomes real, the product changes are narrow and explicit:

1. `receipt_root` stops being the block-proof object on the constant-size path;
2. the per-transaction tx-artifact verification stage stays exactly where it is today;
3. the semantic tuple `Y_sem(B)` stays exactly the current one;
4. the recursive proof-visible tuple becomes `Y_rec(B) = (Y_sem(B), C_leaf(B), C_receipt(B), Sigma_tree(T_0), Sigma_tree(T_n))`;
5. the recursive block artifact becomes `(Header_rec_step(v*, tau(n), k_term(n), P_n), pi_n^{tau(n),k_term(n)})`;
6. the Plonky3-specific auxiliaries `(alpha_perm, beta_perm)` and the linear nullifier vectors disappear from the on-chain block-proof payload;
7. the recursive core uses Poseidon2 verified-leaf/receipt/state commitments, Poseidon2 recursive Fiat-Shamir, and the exact sparse nullifier set from Section 2.5;
8. consensus still recomputes the ordered verified-leaf commitment, ordered receipt commitment, `tx_statements_commitment`, the exact append-state transition, the internal sparse-set root, kernel roots, `nullifier_root`, and `da_root` outside the proof and rejects mismatches.

Anything else is a different product.

## 12. Falsification Criteria

The design is false if any of the following happen in implementation:

1. `Artifact_rec(B)` bytes vary with transaction count.
2. The public tuple varies in serialized length with transaction count.
3. The on-chain artifact serializes per-transaction objects, child proofs, nullifier vectors, sorted-nullifier vectors, or `receipt_root` records.
4. The recursive proof admits multiple serializers, multiple byte widths, or trailing-byte acceptance under one fixed header/profile.
5. The implementation changes the semantics of `Y_sem(B)`.
6. The recursive arithmetic relies on in-relation BLAKE3 without an explicit arithmetization.
7. The recursive public tuple omits `C_leaf(B)` or `C_receipt(B)` and therefore fails to bind the exact ordered verified-leaf stream or the ordered verified receipt stream that the current product already checks before block-artifact verification.
8. The implementation claims the current checked-in `verify_leaf(..., expected_packed, ...)` / `fold_pair` API is already sufficient.
9. The implementation leaves the sparse nullifier set or the canonical public `SparseSetRoot` rebuild underspecified relative to Section 2.5.
10. The recursive public tuple omits `Sigma_tree(T_0)` / `Sigma_tree(T_n)` or otherwise leaves the exact append state underbound while claiming anchor-membership soundness.
11. The implementation does not instantiate `Base_A_v*`, `Step_A_v*`, and `Step_B_v*` as concrete recursive Smallwood relations with fixed public statement arity, fixed proof schema, fixed proof byte width, and exact-consumption parsing.
12. The implementation omits the canonical base-state constraint `S_0 = (0, lambda_0, tau_0, eta_0, T_0, z_384)`, the one-step leaf update `lambda_i = AbsorbLeaf(lambda_{i-1}, L_i)`, or the one-step counter constraint `i(S_i) = i(S_{i-1}) + 1`.
13. The implementation claims constancy only by padding on-chain artifacts to a maximum capacity or by introducing a hidden proof-system `N_max`.

Those are direct failures of the invariant.
