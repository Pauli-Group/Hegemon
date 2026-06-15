## 1. What a “shielded spend” proves (ZK statement)

We’ll design a *single* canonical shielded pool, with a fixed “join–split” circuit used for all transactions.

Say each transaction supports up to:

* `M` inputs (old notes),
* `N` outputs (new notes),

per proof. Use fixed `M, N` for the base circuit, recursion if you need more.

### 1.1 Data model

A **note** is conceptually:

* `value` - integer (e.g. 64-bit, or 128-bit if you're paranoid)
* `asset_id` - 64-bit label (u64) in the current circuit, encoded as a single field element inside the STARK. Commitments and nullifiers are serialized as 48-byte outputs with six 64-bit limbs for 384-bit capacity, and application-level types use 48-byte digests end-to-end. `0` = the native coin.
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

* An append‑only **Merkle tree of `cm`** (the note commitment tree)
* A **nullifier set**: any `nf` that has appeared as an input is “spent”

Each **transaction** includes:

* Public:

  * `nf[0..M-1]` – nullifiers for each consumed note
  * `cm'[0..N-1]` – commitments for each new note
  * `ct_hash[0..N-1]` – ciphertext hashes for each output note (domain-separated BLAKE3-384)
  * `balance_tag` – a compressed representation of value balance (see below)
  * optional `memo`s, optional miner tip, etc.
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
>      The executable Merkle path control flow is represented in Lean: generated vectors check sibling-depth admission, position-bit left/right orientation, root folding, and wrong-root rejection against the production `MerklePath` helper. Poseidon2 hash security and implementation equivalence remain separate cryptographic assumptions.
>      The verifier-facing public-input shape is also represented in Lean: generated vectors check fixed input/output widths, boolean flags, inactive zero padding, active nullifier/commitment nonzero rules, nonempty transaction admission, canonical balance-slot asset ordering, and stablecoin asset presence against `TransactionPublicInputsP3::validate`. The public/serialized input binding seam is represented in Lean as well: generated vectors check merkle-root, fee, signed value-balance, balance-slot asset, stablecoin policy, oracle, and attestation agreement against `transaction_public_inputs_p3_from_parts`. The statement-hash preimage grammar is represented in Lean too: generated vectors check the domain separator, digest padding, little-endian scalar encodings, raw stablecoin flag byte, and signed balance encodings against the shared helper used by transaction receipts and consensus tx-leaf binding; the same vector family now checks `tx-public-inputs-digest-v1` postcard preimage bytes against `transaction_public_inputs_digest_preimage_from_serialized`. The proof statement-binding transcript is represented in Lean as well: generated vectors check the `binding-hash-v3` message, chunk-domain-separated BLAKE2 preimages, stablecoin fields, balance-slot rows, and padding sentinel distinction against `StarkVerifier::compute_binding_hash`. Transaction proof-wrapper admission is represented in Lean as a separate decision table for exact consumption, canonical re-encode, backend support, proof/public-input presence, verifier-facing public-input validity, wrapper balance-slot agreement, and final verifier acceptance; `tx-proof-manifest` now routes nested wrappers through the same pre-verifier helper and uses the shared statement-hash helper instead of maintaining a duplicate grammar. The native tx-leaf artifact wire grammar is separately represented in Lean: generated vectors check bounded serialized STARK/public-tx counts, proof-length caps, commitment row/coeff caps, backend-byte defaulting, bad backend rejection, trailing-byte rejection, and truncation rejection against production `superneo-hegemon` decoding and canonical re-encoding. The native receipt-root artifact parser and structural schedule gate are represented in Lean as well: generated vectors check leaf/fold caps, non-empty expected leaf agreement, `fold_count = leaf_count - 1`, exact fold challenge count, exact parent-row dimensions, trailing-byte rejection, and truncation rejection against production `superneo-hegemon` decoding, canonical re-encoding, and the structural validator called before backend fold verification. The native backend reference-vector review policy is theorem-backed too: generated vectors check candidate-under-review posture, structural-candidate maturity, security-floor metadata, unique supported case names, expected-error metadata, and required valid/invalid tx-leaf and receipt-root case coverage before the independent Rust reference verifier checks artifact bytes. BLAKE2/BLAKE3 cryptographic security, native backend proof soundness, native receipt-root cryptographic fold soundness, and full proof-system soundness remain separate targets.
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

You can think of this as canonical shielded-note semantics with: no ECC, no Pedersen, no RedDSA — everything is hash‑ or lattice‑based.

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
* The size cost is O((M+N) log (M+N)) constraints, which is manageable at the target M,N.

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
or mints more than the scheduled subsidy `R(epoch)` (`499429223` base units initially, halving every `2102400` blocks under the
current 60-second target), the block is rejected
before the fork-choice comparison runs. This keeps the STARK circuit, MASP accounting, and the PoW header’s supply digest in
lockstep. The executable subsidy schedule is represented in Lean: named theorems pin the tokenomics constants, capped halving epoch,
zero-height subsidy, first/second halving boundaries, and post-cap extinction, and generated vectors check those facts against
`consensus::reward::block_subsidy`. The executable supply-accounting rule is also represented in Lean: generated vectors check
`CoinbaseData::net_native_delta`, `consensus::reward::update_supply_digest`, and the native node's checked no-coinbase/coinbase
supply helpers, including overflow rejection.
The accepted-chain supply invariant is represented separately in Lean: generated vectors check that every accepted claimed
`supply_digest` equals replaying the executable checked deltas from genesis, while counterfeit claimed supply, underflow, and
overflow are rejected by the production consensus transition helper used before PoW header acceptance.
The native block coinbase admission table is represented separately in Lean: generated vectors check that blocks have at most one coinbase action, no-coinbase blocks are accepted without summing fees, a present coinbase amount equals the checked subsidy plus checked shielded-transfer fee total, fee/reward overflows reject, and reward mismatches reject.
The native codec-admission boundary is represented separately in Lean: generated vectors check that bounded sync messages reject legacy bincode and trailing bytes, exact SCALE and bincode helpers reject unconsumed bytes plus parser-accepted bytes that do not round-trip to the canonical encoding, and decoded block actions reject header/action count mismatches or trailing action payloads before semantic validation. The packaged non-malleability theorem also proves the inverse acceptance direction for the modeled codec surfaces: an accepted sync decode consumed the full bounded wire message, an accepted exact decode consumed all bytes and matched its canonical re-encoding, and an accepted block-action decode matched the declared action count and exact action payloads. The live `hegemon_submitAction` projection boundary is represented separately too: generated vectors check strict known JSON fields, wallet-compatible empty kernel-envelope fields, rejection of non-empty unimplemented envelope fields, supported routes, scoped/bounded/valid nullifiers, bounded/base64-decoded `public_args`, and exact route-payload decoding before `PendingAction` construction. Route-specific semantic admission then runs before staging/publishing: bridge requests are converted to zero-delta pending actions and routed through `validate_action_state`, while shielded-transfer, coinbase, and candidate-artifact requests keep their route-local payload checks. The native action-hash admission boundary then checks every decoded block action's embedded `tx_hash` against the recomputed `pending_action_hash` and rejects duplicate action hashes before import or decode-only consumers observe the decoded actions. Persisted pending-action reload is represented by a separate Lean-conformance-checked admission table: malformed sled keys, sled-key/embedded-hash drift, recomputed `pending_action_hash` drift, and duplicate loaded hashes reject before reloaded local mempool entries can feed mining selection. These theorems cover the admission decision tables, not sled durability, serde/base64/SCALE implementation correctness, full raw-action-to-replay equivalence, or disk integrity.
The native decoded bridge action payload admission table is represented separately in Lean: generated vectors check bridge-family routing, no state-delta smuggling, supported bridge action IDs, outbound payload presence, inbound proof-receipt presence, inbound replay-key/message binding, Hegemon destination binding, inbound payload-hash binding, and rejection precedence before receipt verification or replay-set import. Live `hegemon_submitAction` bridge staging uses the same state-validation route: it constructs zero-delta bridge pending actions, runs `validate_action_state`/`validate_pending_action_against_mempool_state`/`validate_bridge_action_payload`, and rejects malformed bridge payloads before action hashing, sled insertion, durability flushing, or pending-map publication. The post-verifier inbound receipt-output admission table is represented separately too: generated vectors check source-chain, rules-hash, message-nonce, message-hash, tip/checkpoint arithmetic, confirmation overstatement, minimum-confirmation policy, and rejection precedence against the production helper called by `verify_inbound_bridge_receipt` after a receipt output is decoded. Startup reload of the consumed inbound replay set is represented by a separate Lean-conformance-checked admission table that rejects malformed persisted keys/markers and requires exact equality with replay-derived canonical block history before mining or serving state.
The native decoded shielded-transfer payload admission table is represented separately in Lean: generated vectors check proof presence and byte caps, anchor and commitment agreement, inline ciphertext byte caps, ciphertext hash/size metadata agreement, binding-hash agreement, decoded proof binding-hash agreement, fee agreement, and rejection precedence before anchor/nullifier state and tx-leaf proof verification. Accepted payloads now expose binding-hash, proof-binding-hash, and fee facts for downstream native tx-leaf theorem composition.
The native decoded block-action validation composition is represented separately in Lean: generated vectors check that action hash/count admission, route/scope admission, route-specific payload success, inbound bridge replay duplicate checks, shielded transfer ordering, and transfer state admission execute in fixed order before decoded actions are persisted or mutate state. A production binding and focused regression additionally require arrival-time-insensitive semantic duplicate rejection before transfer/replay state construction, so two actions with different `received_ms` values cannot bypass duplicate `tx_hash` admission. Announced-block import and canonical replay also compare decoded action roots to the block header before payload materialization. Announced-block import runs the block replay/accounting/commitment gate before deeper payload and artifact validation so forged body commitments reject under the Lean-modeled no-counterfeiting order instead of being masked by malformed action payloads.
The native action-plan application admission slice is represented separately in Lean: generated vectors check that planned commitment-start rows have the same length as decoded actions, match the current leaf cursor at each step, and advance under checked u64 arithmetic. Production preview, memory apply, materialized planning, and canonical-index rebuild now propagate this gate before appending commitments, deriving roots, or deriving canonical index rows. The companion native action wire-replay projection slice checks decoded `PendingAction` ciphertext hash/size rows and inbound bridge replay-key projection against materialized planned effects before preview, memory apply, materialized planning, or canonical-index rebuild derives replay rows; full raw SCALE field projection remains a separate implementation-equivalence target.
The transaction proof-wrapper admission slice is represented separately in Lean: generated vectors check exact/canonical wrapper admission, supported backend routing, proof/public-input presence, public-input validity, balance-slot agreement, and verifier acceptance ordering. Production `transaction-circuit` wrapper verification calls the admission predicate around decoded-field and verifier-result checks for both Plonky3 and the default SmallWood path, and `tx-proof-manifest` exact-decodes nested proofs before routing verifier rejection through the same table; proof-system soundness and bincode internals remain outside the claim.
The transaction spend-authorization boundary is represented separately in Lean: `Hegemon.Transaction.SpendAuthorization.authorizeInputSlots_lengths_match` proves successful slot authorization forces public input flags, public nullifiers, and private witnesses to have matching lengths, and `transactionSpendAuthorized_witnesses_align_with_public_inputs` lifts that fact through the transaction spend-authorization predicate. Indexed active/inactive slot facts can therefore no longer be applied to a mismatched public/witness vector shape in the formal model. This closes a no-theft implementation-equivalence precondition while keeping deployed STARK/AIR soundness, SmallWood soundness, witness extraction, concrete hash security/equivalence, wallet custody, and complete native-node refinement as explicit open work.
The transaction proof-statement binding slice is represented separately in Lean: generated vectors check the exact `binding-hash-v3` message bytes, chunk-domain-separated BLAKE2 preimages, stablecoin public fields, balance-slot row encoding, bad balance-slot count rejection, and padding-sentinel collision distinction against `protocol-shielded-pool` production helpers. Production `StarkVerifier::compute_binding_hash` is checked against those generated preimages, while `balance_tag`, `circuit_version`, and `crypto_suite` remain bound by the public-input, statement-hash, receipt, and tx-leaf gates. BLAKE2/BLAKE3 security, proof-system soundness, and complete Rust refinement remain outside the claim.
The canonical proof-system boundary slice is represented separately in Lean: `Hegemon.Transaction.ProofSystemBoundary` packages the canonical deployed verifier surface, deployed relation facts, accepted transaction relation, wrapper preconditions, public-input binding validity, statement preimage success/length, proof binding-message success, core root/fee/balance-slot/stablecoin statement binding, vector binding, input-vector binding, output-vector binding, value-balance binding, stablecoin payload binding, exposed spend/balance facts, native and per-asset authorized-delta projections, total input-slot statement/proof-binding facts, and output-slot statement/proof-binding facts into one named target for future AIR/refinement work. `deployed_soundness_canonical_surface_input_slot_boundary_facts` and `deployed_soundness_canonical_surface_output_slot_boundary_facts` now expose those input/output slot packages directly from the canonical surface plus the explicit deployed-verifier soundness assumption. It keeps `DeployedTxVerifierSoundnessAssumption` explicit; it does not prove deployed STARK/AIR, SmallWood, witness extraction, verifier implementation correctness, or hash security.
The serialized public-input digest preimage is checked by the same statement-hash vector family: Lean emits `tx-public-inputs-digest-v1` postcard bytes for representative normal and stablecoin verifier inputs, and Rust compares them against `transaction_public_inputs_digest_preimage_from_serialized` before hashing. This is byte-preimage conformance, not a general proof of postcard correctness.
The native candidate-artifact admission table is represented separately in Lean: generated vectors check no state-delta smuggling, decoded payload presence, shipped `recursive_block_v2` route/profile, tx/DA bounds, forbidden legacy proof payloads, absent receipt-root payloads, and recursive proof byte caps before deeper proof verification.
The native block-artifact binding admission table is represented separately in Lean: generated vectors check decoded tx-leaf/action nullifier, commitment, ciphertext-hash, input/output active-count, version, fee, balance-tag projection, receipt statement-hash, public-input digest, proof digest/backend-profile, and ciphertext payload-hash agreement, plus candidate artifact DA-root, tx statement-commitment, and verified recursive state-root agreement before a block can import or replay shielded transfer effects from a recursive artifact. Native block artifact verification now materializes sidecar ciphertext bytes through the same canonical materializer used by replay planning before constructing tx-leaf transactions.
The native DA/sidecar replay-binding slice is represented separately in Lean: `Hegemon.Native.DaSidecarReplayBinding` composes accepted candidate artifact admission, candidate DA-root binding, proven-batch DA binding, recursive semantic `daRoot` field sourcing, sidecar upload admission, action-stream acceptance, action wire-replay projection, projected replay startup equivalence, and raw-decoded projected replay startup equivalence into fact packages. Accepted raw projected DA/sidecar replay now exposes accepted replay over raw replay inputs, replayed supply equality, replayed leaf-cursor equality, commitment-plan preconditions, raw carried-state preconditions, and final nullifier/bridge replay-key uniqueness. This is still a composition over admitted predicates, not a full raw-byte refinement: raw `PendingAction` byte projection, DA availability, sidecar hot/cold retention, DA-root hash security/equivalence, recursive proof soundness, native tx-leaf proof soundness, storage durability, and complete native-node equivalence remain separate targets.
The native raw-ingress sidecar replay-recoverability slice is represented separately in Lean: `Hegemon.Native.RawIngressSidecarReplayRecoverability` composes accepted action-request projection, pending-action reload, staged ciphertext reload, staged proof reload, transfer-state sidecar materialization, the DA/sidecar replay-binding package, projected replay startup equivalence, raw-decoded projected replay startup equivalence, and raw-decoded ledger/tree replay publication. Accepted sidecar-route transfers therefore expose sidecar ciphertext availability, sidecar size presence, sidecar size agreement, DA-root binding facts, accepted ledger replay, replayed supply equality, leaf-cursor equality, canonical commitment-plan preconditions, commitment-root progression, carried-state preconditions, and final nullifier/bridge replay-key uniqueness before DA/replay facts are used. `accepted_raw_ingress_raw_projected_tree_replay_binds_sidecar_publication` packages `validateNativeLedgerTreeReplayChain` and `expectedCommitmentRootAfter` with the same sidecar publication facts, making the commitment-root cursor explicit at raw ingress, and `raw_ingress_publication_equivalent_to_raw_ledger_tree_replay` exposes those obligations as `RawIngressLedgerTreePublicationFacts` fields for production review. `Hegemon.Native.BridgeMintSafety.accepted_inbound_payload_authorized_amount_raw_ingress_sidecar_replay_safe` now composes that raw-ingress surface with accepted inbound bridge payload authorization, decoded amount equality, zero direct native mint delta, and one-shot replay import, so the bridge mint/replay package also carries sidecar materialization, DA-root binding, wire-replay preconditions, and wire action-count equality. `accepted_inbound_payload_authorized_amount_raw_ingress_tree_replay_safe` lifts the same bridge package through `RawIngressLedgerTreePublicationFacts`, so bridge mint/replay reasoning also carries accepted ledger/tree replay, commitment-root publication, replayed supply, replayed leaf cursor, canonical commitment-plan preconditions, raw tree carried-state preconditions, and final replay-set uniqueness. The companion `accepted_inbound_payload_authorized_amount_fresh_replay_survives_raw_projected_tail` proves that once the inbound replay key is freshly imported into the carried bridge replay state, accepted raw-projected replay preserves that key through the final consumed-replay set while retaining replayed supply, leaf-cursor, commitment-plan, nullifier-uniqueness, and replay-uniqueness facts. This still does not prove arbitrary-byte SCALE/JSON parser refinement, DA availability or hot/cold retention, BLAKE3/DA-root security/equivalence, recursive or tx-leaf proof soundness, sled durability, external bridge receipt soundness, or complete native-node equivalence.
The native sync block replay publication slice is represented in Lean as `Hegemon.Native.SyncBlockReplayPublication`. `accepted_sync_block_response_binds_raw_canonical_publication` composes accepted bounded sync wire decode, inbound response-count admission, exact block-action decode, explicit decoded-action-row to raw-replay-row equality, and raw canonical publication. Accepted synced raw block batches therefore expose exact sync/block decode facts, response-count bounds, accepted ledger/tree replay, commitment-root publication, replayed supply equality, replayed leaf-cursor equality, canonical commitment-plan preconditions, and final nullifier/bridge replay-key uniqueness. This narrows the sync-path implementation-equivalence gap without runtime work, but it still does not prove arbitrary sync/block parser internals, peer honesty, network liveness, proof soundness, storage durability, or complete native-node equivalence.
The raw-ingress pending-action publication slice is represented in Lean as `Hegemon.Native.RawIngressPendingActionPublicationRefinement`. `accepted_raw_ingress_pending_action_bytes_bind_publication` composes `RawIngressLedgerTreePublicationFacts` with `PendingActionBytePublicationFacts` over the same raw replay witness, so parser row-count agreement, sidecar availability and size agreement, DA-root binding, accepted ledger/tree replay, commitment-root publication, replayed supply, replayed leaf cursor, final nullifier uniqueness, and final bridge replay-key uniqueness are exposed together. `accepted_raw_ingress_pending_action_bytes_bind_tx_leaf_publication` adds the native tx-leaf/canonical statement artifact package on the same surface. This still does not prove arbitrary-byte parser internals, DA availability or retention, hash security, proof soundness, sled durability, or complete native-node equivalence.
The raw-ingress full-byte review slices are represented in Lean as `Hegemon.Native.RawIngressActionHashTxLeafPublication`, `Hegemon.Native.RawIngressDaSidecarCanonicalPublication`, and `Hegemon.Native.RawIngressFullBytePublicationSurface`. These packages project the nested raw-ingress theorem stack into top-level records: action-count/hash/uniqueness fields, statement preimage, binding-message, public-input binding, wrapper facts, value/stablecoin binding, tx-leaf preconditions, native artifact equality facts, proof metadata, proof-byte bounds, DA-root binding, raw/canonical replay, commitment-root publication, replayed supply, final replay-set uniqueness, exact parser facts, wire replay facts, bounded artifact shape, explicit parser-to-canonical projection assumptions, and full statement artifact facts. They add no runtime work and still do not prove arbitrary-byte parser internals, hash/security equivalence, DA availability, proof soundness, storage durability, or complete native-node equivalence.
The materialized sidecar DA-blob publication slice is represented in Lean as `Hegemon.Native.MaterializedSidecarDaBlobPublication`. `accepted_materialized_sidecar_da_blob_publication` consumes `RawIngressFullBytePublicationFacts` and exposes materialized sidecar rows, wire replay DA-row binding, candidate DA-root binding, proven-batch DA-root binding, recursive semantic DA-root sourcing, native tx-leaf ciphertext hash and payload-hash binding, statement ciphertext-vector binding, accepted ledger/tree replay, commitment-root publication, replayed supply, and final replay-set uniqueness together. It adds no runtime work and keeps materialized-row-to-`Transaction::new` equivalence, `Transaction::new`-to-consensus-DA-blob equivalence, DA-root hash/security equivalence, DA availability, proof-system soundness, storage durability, and complete native-node equivalence explicit.
The materialized consensus DA-blob refinement slice is represented in Lean as `Hegemon.Native.MaterializedConsensusDaBlobRefinement`. `accepted_materialized_transfer_payloads_feed_concrete_consensus_da_blob` consumes `MaterializedSidecarDaBlobPublicationFacts` instantiated with concrete `MaterializedRowsFeedTransactionNew` and proves the `transactions.map consensusDaPayload` to `Consensus.DaRoot.daBlob` relation internally, then packages ordered action/payload/transaction binding, consensus DA payload binding, exact `Consensus.DaRoot.daBlob` bytes, explicit u32 transaction/ciphertext length bounds, sidecar materialization facts, DA-root publication facts, tx-leaf ciphertext binding, accepted ledger/tree replay, replayed supply, commitment-root publication, and final replay-set uniqueness. The formal-core gate also runs `materialized_sidecar_transfer_payload_builds_consensus_da_blob`, which checks the production sidecar transfer path through sidecar materialization, consensus transaction construction, DA blob bytes, and DA root computation. This narrows row-to-`Transaction::new` and DA-blob construction equivalence without adding hot-path work; arbitrary-byte parser internals, DA availability/retention, DA-root hash/security, proof-system soundness, storage durability, and complete native-node equivalence remain explicit.
The materialized transfer no-theft publication slice is represented in Lean as `Hegemon.Native.MaterializedTransferNoTheftPublication`. `accepted_materialized_transfer_no_theft_publication` consumes `MaterializedSidecarDaBlobPublicationFacts` and composes accepted decoded transfer payload admission, native tx-leaf/action binding, canonical statement facts, active-input no-theft facts, and total input-slot authorization facts over the same materialized raw-ingress path. It adds no runtime work and keeps deployed verifier soundness, witness extraction, DA availability, hash/security equivalence, storage durability, and complete native-node equivalence explicit.
The canonical verifier boundary now has a split proof-system target. `Hegemon.Transaction.PublicInputBinding.signedMagnitudeMatches_true_eq` proves the public signed-magnitude relation determines the decoded integer. `Hegemon.Transaction.CanonicalVerifierBoundary.canonical_statement_spend_soundness_active_input_bound_to_statement` uses only the spend half of deployed soundness for active-input no-theft facts, while `canonical_statement_balance_soundness_public_authorized_asset_delta_value` uses only the balance/public-field half for authorized public asset deltas. `deployed_soundness_parts_imply_deployed_tx_verifier_soundness_assumption` preserves compatibility with downstream theorem calls. These theorems narrow the future AIR/Rust-refinement obligations; they do not discharge deployed proof-system soundness.

The tx-leaf artifact projection refinement slice is represented in Lean as `Hegemon.Native.TxLeafArtifactProjectionRefinement`. The theorem set proves that accepted native tx-leaf artifact bytes expose bounded serialized input/output/balance-slot counts, public nullifier/commitment/ciphertext-hash counts, proof length, commitment row/coeff counts, and backend explicit/default facts; that explicit parser-to-canonical projection assumptions imply accepted tx-leaf/action binding; and that pending-action byte publication plus raw-ingress pending-action tx-leaf publication can carry parsed artifact shape facts and full statement/artifact facts over the same tx-leaf witness. This narrows the implementation-equivalence target for native tx-leaf artifacts but still leaves the full production serialization-to-statement-vector proof, deployed proof-system soundness, hash security, DA availability, and complete native-node equivalence explicit.

The raw-ingress bridge pending-action publication slice is represented in Lean as `Hegemon.Native.RawIngressBridgePendingActionPublication`. `accepted_inbound_bridge_raw_ingress_pending_action_publication_safe` composes accepted inbound bridge payload authorization, authorized decoded amount equality, zero direct native mint delta, fresh replay import, duplicate replay rejection, raw pending-action byte publication, parser row-count agreement, commitment-root publication, replayed supply, final nullifier uniqueness, and final bridge replay-key uniqueness over the same raw ledger/tree replay witness. `accepted_inbound_bridge_raw_ingress_canonical_publication_safe` adds canonical publication, raw/canonical supply replay, commitment-root publication, and replay-set uniqueness on that same Hegemon-side surface without taking external receipt/PQ verifier soundness as a premise. `accepted_inbound_bridge_raw_ingress_canonical_publication_replay_safe` then adds accepted inbound receipt admission, native backend review preconditions, canonical publication facts, and explicit external receipt/PQ verifier soundness to the same package. This is the bridge counterpart to the transfer no-theft publication surface; it still does not prove external receipt soundness, a future PQ-clean receipt verifier, arbitrary-byte parser internals, hash security, DA availability, sled durability, or complete native-node equivalence.

The raw-ingress transfer no-theft publication slice is represented in Lean as `Hegemon.Native.RawIngressTransferNoTheftPublication`. `accepted_raw_ingress_transfer_payload_no_theft_authorization_publication` composes accepted raw-ingress pending-action tx-leaf publication with accepted transfer payload admission, singleton block-action validation, active-input no-theft facts, total input-slot authorization facts, replayed supply, final nullifier uniqueness, and native tx-leaf statement/proof artifact facts over the same raw replay witness. It keeps `DeployedTxVerifierSoundnessAssumption` explicit; it is an implementation-equivalence publication theorem, not a proof of deployed STARK/AIR, SmallWood, native tx-leaf proof, witness extraction, hash, wallet-custody, or full native-node soundness.

The native tx-leaf canonical-surface composition is represented separately in Lean: an accepted native tx-leaf/action binding gate plus a canonical deployed transaction statement surface now assumption-free expose statement preimage success/length, proof binding-message success, public-input binding validity, proof-wrapper preconditions/surface facts, and native receipt/public-input/proof/backend/ciphertext-payload equality gates. Under the explicit deployed verifier soundness assumption, the same boundary implies the accepted transaction relation, authorized asset-delta values, active input spend facts, total input-slot authorization facts, output commitment/ciphertext facts bound to the same statement and proof-binding vectors, and the packaged canonical proof-system boundary facts. The full statement/artifact package now also has a selected-output theorem, `native_tx_leaf_full_statement_artifact_output_slot_full_binding`, that keeps output-slot facts, statement/proof-binding output rows, wrapper/public/statement facts, native output equality gates, and native artifact digest/backend gates together for downstream ciphertext, observer, and AIR/refinement work. The packaged native artifact boundary directly exposes total input-slot statement/proof-binding facts for downstream implementation-equivalence proofs, and the proof-keyed transfer payload package composes accepted payload admission with the canonical native artifact boundary so active-input no-theft facts carry payload binding-hash agreement, decoded proof binding-hash agreement, wrapper/statement facts, and native proof/backend equality gates. `proof_keyed_transfer_payload_input_slot_authorization_full_binding` extends that proof-keyed package to every indexed input slot: active slots carry spend facts through the existing implication, while inactive slots carry the zero-nullifier fact, with payload binding-hash/proof-binding-hash/fee agreement, statement/proof nullifier-slot alignment, root/anchor binding, and native proof/backend/ciphertext-payload gates still attached. `Hegemon.Native.TransferNoTheftBoundary.validated_transfer_payload_active_input_no_theft_full_binding` and `validated_transfer_payload_input_slot_authorization_full_binding` then lift active no-theft and total input-slot full-binding through accepted decoded transfer payload admission and the modeled block-action validation path, including singleton transfer acceptance plus payload-before-order and order-before-state precedence before transfer state mutation. This closes a native artifact-to-statement/proof-facts implementation-equivalence gap, but it still does not prove deployed AIR/STARK/SmallWood soundness, hash security, tx-leaf parser completeness, or full native-node refinement.
PoW headers must also bind one registered miner identity: `validator_set_commitment` maps to the miner ML-DSA public key,
`signature_aggregate` carries exactly one ML-DSA-65 signature over the header signing hash, and PoW headers with BFT signature
bitmaps are rejected. This admission ordering is represented in Lean by `Hegemon.Consensus.MinerIdentity`; generated vectors
check the production `PowConsensus::verify_pow_miner_signature` helper's policy labels around the real ML-DSA parser and
verifier result.
The native node binds miner identity on its native block metadata rather than changing the bridge/light-client `PowHeaderV1`
wire surface. Local mining loads a dedicated ML-DSA seed from `miner-identity.seed` or `HEGEMON_MINER_IDENTITY_SEED[_PATH]`,
computes `BLAKE3-384(public_key)` as the miner commitment, and signs
`hegemon.native.miner-signature-v1 || PowHeaderV1::canonical_bytes || nonce || work_hash` before PoW metadata verification,
atomic block persistence, state publication, or broadcast. Announced native blocks verify the self-contained public key,
commitment, signature byte grammar, and signature result before PoW header admission and replay. `Hegemon.Native.MinerIdentity`
represents the admission decision table and generated vectors check the production helpers. Native miner membership is not
registered yet; the current release explicitly gates self-contained identity only, with registry/allowlist design tracked as a
residual risk.

The native `hegemon-node` process starts from a fresh native genesis, persists native block and shielded-state metadata in `sled`, mines PoW development blocks, syncs over the Hegemon PQ service, and keeps the wallet/app JSON-RPC method names stable. New native work must flow through `ConsensusBlock` validation, sled-backed native state, PQ sync, checked supply-digest advancement, and the same JSON-RPC compatibility surface. The release node does not link classical TLS client/server stacks: RPC is served as plaintext HTTP/WebSocket for loopback or a trusted operator control plane, and remote administrative access must be protected outside the process by a PQ-safe transport or host-level access policy. The release PQ-binary audit decision table is represented in Lean: generated vectors check that source, dependency, and linked-binary forbidden-primitive scan findings accept only when all three are clean and reject with fixed source-before-dependency-before-binary precedence. This proof does not prove scanner-pattern completeness; `scripts/security-audit.sh` remains the artifact scanner for actual source, `Cargo.lock`, and release-binary evidence. The dependency audit waiver decision table is also represented in Lean: generated vectors check required waiver fields, expiry, and exact advisory/package/version/kind matching before a cargo-audit finding can be waived. This proof does not prove advisory database completeness; `scripts/dependency-audit-gate.sh` remains the cargo-audit evidence gate. The native backend reference-vector review policy is represented in Lean: generated vectors check candidate-under-review posture, structural-candidate maturity, security-floor metadata, unique supported case names, expected-error metadata, and required tx-leaf/receipt-root case coverage before `native-backend-ref` verifies the actual artifact bytes. This proof does not prove native backend cryptographic soundness. Native RPC admission is represented separately in Lean: generated vectors check method-policy resolution, unsafe-method gating/list filtering, timestamp range caps, raw and decoded byte caps, and JSON-RPC batch caps against the production native RPC helpers and handler. Blueprint bindings and focused regressions additionally keep selected native RPC/storage materializers fail-closed for malformed block rows, timestamp rows, wallet archive rows, and start-mining thread parameters.

Shielded transfers accumulate one per-block tip bucket:
`BlockFeeBuckets { miner_fees }`. Each transfer’s public `fee` field is interpreted as an optional miner tip. `fee = 0`
is always valid on the product path. The shielded reward mint path (`mint_coinbase` external call name;
`mint_block_rewards` internal path) validates a `BlockRewardBundle` with one required miner note. Miner reward must equal
`subsidy + miner_fees`. There is no separate prover reward or artifact-claim payout lane on the product path, and there is
no deterministic fee-quote schedule. If a block omits reward minting, accumulated miner tips are treated as burned
and tracked on-chain; the missing subsidy is not added to `supply_digest` because no shielded coinbase note was created. Native local mining with `HEGEMON_MINER_ADDRESS` now synthesizes the miner coinbase before work-template root preview and ignores staged coinbase recipients so a local RPC submission cannot redirect the configured miner reward.

The legacy forced-inclusion bond queue is removed in the proof-native cut. Censorship resistance for the private lane is now handled by the unsigned shielded submission path itself plus block-import validation, rather than by reserving public balances behind a transparent account.

Within a block, shielded transfer actions must appear in nondecreasing order of `blake2_256(binding_hash || nullifiers...)`, with SCALE-encoded action/family payloads preserved for wallet compatibility.
Nodes enforce this during block import and local block production so miners do not have discretionary ordering inside the private lane. The executable transfer-key ordering predicate is represented in Lean and checked against the native helper; the hash derivation from action payloads remains a separate Rust/hash conformance boundary.

### zk bridge light-client method

The bridge path deliberately separates Hegemon consensus from zk proof transport. Full nodes still accept the greatest-work valid PoW chain. A zkVM prover only proves a light-client statement about that chain to another verifier:

```text
given a trusted Hegemon checkpoint,
verify a compact long-range PoW proof with deterministic target/work rules,
verify the fixed-width cumulative-work claimed by the message header and canonical tip,
verify MMR openings for the message header and deterministic FlyClient-style sampled headers,
verify an ordered BridgeMessageV1 is included under message_root,
emit BridgeCheckpointOutputV1.
```

The reusable verifier lives in `consensus-light-client` and exposes `PowHeaderV1`, `TrustedCheckpointV1`, `BridgeCheckpointOutputV1`, `HeaderMmrOpeningV1`, `HegemonLongRangeProofV1`, `verify_pow_header`, `verify_header_chain`, `verify_cumulative_work`, `verify_header_mmr_opening`, `verify_hegemon_long_range_proof`, and `verify_message_inclusion`. It is `no_std + alloc` compatible and has no node, sled, networking, async, or zkVM-vendor dependencies.

The native node computes bridge commitments during block production and import. Outbound bridge actions use the `protocol-kernel` bridge family and become ordered `BridgeMessageV1` records with nonce `source_height << 64 | per_block_index`; the block header binds their ordered `message_root` and `message_count`. Inbound bridge actions carry a versioned external proof receipt and are rejected unless the message is addressed to Hegemon, the payload hash matches, the `(source_chain_id, source_message_nonce)` replay key is neither pending nor consumed, and the action carries no shielded-state deltas.

`hegemon_exportBridgeWitness` exports the current canonical witness object for a committed outbound message: parent checkpoint, canonical `PowHeaderV1`, header-history hashes, compact `HegemonLongRangeProofV1` bytes when the message has at least one confirming source tip, bridge messages, selected message index, and the decoded `BridgeCheckpointOutputV1`. When called without a block hash, it scans backward from the current canonical tip for up to 4096 blocks and selects the latest canonical block containing a bridge message, so relayers do not need to race block production before the next empty block arrives. That latest-message backscan is now represented in Lean and checked against the production helper: missing height indexes and missing block records are skipped, canonical action-decode failures fail closed before older matches, the first eligible block in newest-to-oldest order is selected, and an empty/ineligible bounded scan rejects. Older messages require an explicit source block hash to avoid turning the RPC into an unbounded full-chain scan. Explicit block-hash parameters are now fail-closed: malformed hashes are rejected instead of being treated as "no hash supplied" and falling back to the latest-message scan. The native export gate itself is represented in Lean and checked against the production helper: a witness can be exported only for a known canonical block with a present canonical height index, decodable actions, an in-bounds bridge message index, an available parent header, and a best tip that is not before the message block; accepted exports compute `confirmations_checked` with explicit u32 capping. The long-range proof uses a real MMR root over historical header hashes plus deterministic FlyClient-style sample indices derived from the tip root, tip hash, and message header hash. The cheap long-range proof-shape admission table is represented in Lean and checked against the production `consensus-light-client` helper, covering verifier hash, message count, header/MMR length shape, checked trusted-checkpoint sample-start arithmetic, trusted/message/tip height ordering, selected message source, sample height/opening-index agreement, confirmation policy, tip-work policy, and claimed-output agreement. The deterministic FlyClient sample transcript and digest-prefix reduction are also represented in Lean and checked against the production sampler helpers. The `BridgeCheckpointOutputV1` canonical and journal byte grammar is represented in Lean too: generated vectors check the 35-byte output domain, 439-byte canonical preimage, 404-byte authenticated journal tuple, field order, scalar little-endian encoding, decode round-trip, and fixed-length rejection against the production output helpers. BLAKE3 transcript-hash security, output digest security, and probabilistic sampling soundness remain separate assumptions. It is probabilistic in the same sense as FlyClient: it avoids linear header replay, but it does not turn PoW into deterministic BFT finality.

The RISC Zero bridge method under `zk/risc0-bridge/methods` reads `HegemonLongRangeProofV1`, runs the same light-client statement inside the zkVM, and commits the fixed-width 404-byte `BridgeCheckpointOutputV1` wire tuple as the authenticated journal. The host prover under `zk/risc0-bridge/prover` emits `RiscZeroBridgeReceiptV1`, but the release native node does not link `risc0-zkvm`: the standard verifier dependency graph pulls Groth16/BN254 code into the binary even when Groth16 receipts are rejected at runtime. As a result, inbound RISC Zero bridge actions are rejected after syntactic envelope/journal decoding and message-binding prechecks, with no pending action staged. The RISC Zero crates remain offline measurement/prover artifacts only until the verifier path is replaced with a PQ-clean STARK/hash verifier surface. The prover defaults to RISC Zero succinct STARK receipts, while `HEGEMON_RISC0_RECEIPT_KIND=composite` is available for native-STARK smoke tests that trade receipt size for proving speed. On `hegemon-dev`, the optimized guest executes a 9951-byte live proof in 962524 RISC Zero cycles; cached release proving measured 8m37s for a 492158-byte composite envelope and 10m46s for a 224508-byte succinct envelope.

The CashVM bridge experiment under `zk/cashvm-bridge` verifies that the bridge statement can be adapted without making RISC Zero a hard protocol requirement. `CashVmBridgeOutputV1` is a BCH-facing, SHA-256-domain-separated 516-byte output derived from `BridgeCheckpointOutputV1` and `BridgeMessageV1`. It carries the Hegemon message root plus the confirmation and minimum-work policy actually checked, so the BCH-facing claim remains self-describing. `CashVmBridgeStateV1` encodes to exactly 128 bytes, matching the 2026 CashToken commitment target, and stores only digests/counters: verifier script hash, accepted checkpoint digest, replay root, minted supply, sequence, minimum PQ soundness bits, and flags. The Rust covenant model accepts a bridge spend only when the proof envelope binds the output statement digest, the verifier script hash matches, the claimed PQ soundness clears the state policy, the next state preserves the verifier/soundness policy, the source message payload hash is internally consistent, the CashVM SHA-256 message digest rebinds to the source message, the replay root advances by `(source_chain_id, message_nonce)`, the checkpoint digest advances to the proven Hegemon checkpoint, and minted supply increases by the proven amount. The standardness report currently prints one-transaction fit for the 9951-byte Hegemon long-range proof input and chunking requirements for the measured RISC Zero envelopes:

```text
HegemonLongRangeProofV1: bytes=9951 fits_standard_tx=true stack_elements_required=1 fragment_transactions_required=1
RISC Zero journal: bytes=404 fits_standard_tx=true stack_elements_required=1 fragment_transactions_required=1
CashVM bridge output: bytes=516 fits_standard_tx=true stack_elements_required=1 fragment_transactions_required=1
RISC Zero succinct envelope: bytes=224508 fits_standard_tx=false stack_elements_required=23 fragment_transactions_required=3
RISC Zero composite envelope: bytes=492158 fits_standard_tx=false stack_elements_required=50 fragment_transactions_required=6
```

This means the source-chain witness is not the blocker for BCH; the final proof object is. A BCH production bridge should use the same Hegemon light-client statement but a CashVM-native STARK/hash proof format or a multi-step proof-fragment covenant, not the existing RISC Zero receipt envelope.

### Aggregation mode and proof sidecar (product block path)

For the fresh-chain 0.10.0 product path, non-empty shielded blocks now always use native same-block recursive aggregation. Wallets submit native `tx_leaf` artifacts in each transfer extrinsic, and block authors must also attach a native constant-size `recursive_block` artifact so import verifies the block through `SelfContainedAggregation` instead of the removed `InlineRequired` product lane. On this lane the legacy `commitment_proof` payload is required to be empty and consensus derives the semantic tuple directly from the ordered verified `tx_leaf` stream plus parent state. The older native `receipt_root` object remains available as an explicit compatibility/research lane, not the shipped default.

* Block authors include `ShieldedPool::enable_aggregation_mode` early in every non-empty shielded block.
* A chain-level `ProofAvailabilityPolicy` still exposes the wire values `InlineRequired` and `SelfContained`, but the fresh-chain protocol manifest defaults to `SelfContained` and consensus rejects non-empty product blocks that attempt to rely on the legacy inline-required lane.
* Non-empty shielded blocks fail closed unless a valid same-block `submit_proven_batch` / `submit_candidate_artifact` payload carrying the native `recursive_block` artifact is present.
* Block template assembly now waits for a ready native bundle for non-empty shielded candidates instead of sealing a hybrid `proven_batch: None` block. Empty and non-shielded blocks can still be sealed immediately.
* Remote gossip does not get a cheap path into the ready pool: nodes quarantine network-originated shielded kernel transfers until the native `tx_leaf` artifact fully verifies against its public receipt and tx view. Local author-local RPC submissions keep the direct fast path.
* The unsigned transfer runtime path caps the outer native `tx_leaf` payload at the exact live artifact envelope and caps the embedded STARK proof separately at `512KiB`, so runtime admission and consensus/native verification stay aligned.
* Native sync admission is Lean-conformance-checked after bounded sync decode: served response ranges cap to local best height and `MAX_NATIVE_SYNC_RESPONSE_BLOCKS`, catch-up requests cap to the same response window, zero caps fail closed, and inbound responses with too many blocks are rejected before sorting or import.
* Native block-template action selection is Lean-conformance-checked before mining work is built: sidecar transfers without matching local staged ciphertext metadata are excluded before the transfer count selects a same-block recursive candidate artifact, and unselected candidate artifacts are dropped.
* Proof sidecars may still be staged off-chain via `da_submitProofs` keyed by `binding_hash`, but this is proposer/mempool coordination only and is not part of consensus validity. The DA staging RPC (`da_submitCiphertexts`, `da_submitProofs`) is unsafe-only and should be exposed only on a trusted local/proposer control plane with `--rpc-methods=unsafe`. Those staged sidecars are proposer-local caches, not durable consensus state; startup reload restores staged ciphertext metadata only from raw sidecar bytes whose hash matches the sled key, purges malformed/oversized/hash-mismatched/over-capacity ciphertext cache entries, restores staged proofs only from well-formed 64-byte binding-hash keys with nonempty in-budget proof bytes, purges malformed/empty/oversized/over-count/over-byte proof cache entries, and wallets/provers must be ready to restage when local cache availability is missing. The native RPC admission predicates are represented in Lean and checked with generated vectors against `rpc_method_policy`, unsafe-method dispatch/listing, timestamp range admission, bounded byte parsing, and JSON-RPC batch handling. The native pending-action and staged-proof byte-budget predicates are represented in Lean and checked with generated vectors against the production helpers, including exact-limit acceptance, over-limit rejection, staged-proof replacement semantics, and saturated totals. Native DA sidecar upload admission is represented separately in Lean and checked against production request-count, capacity, proof metadata, and decoded proof-byte helpers for `da_submitCiphertexts` and `da_submitProofs`; staged proof startup reload is covered by its own Lean kernel.
* Import verifies the ordered native `tx_leaf` artifacts plus the native `recursive_block` artifact and rejects any non-empty shielded block whose native bundle is missing, malformed, inconsistent with the canonical `tx_statements_commitment`, or tries to carry legacy commitment-proof bytes on the recursive lane.
* Proof verification is not an operator-selectable validity rule. `HEGEMON_PARALLEL_PROOF_VERIFICATION=0` is treated as a logged no-op during block production/import so development builds cannot accidentally accept a chain that full verification would reject.

---

### Experimental post-proof receipt folding spike

The repo now carries a bounded SuperNeo research spike under `circuits/superneo-*`. The method being tested is deliberately post-proof: instead of compiling the full transaction AIR into a second proof system, the experimental relation starts from a transaction-proof receipt. The receipt statement binds five 48-byte digests: a transaction-statement digest, a proof-bytes digest, a verifier-profile digest, a public-inputs digest, and a verification-trace digest.

The witness method is now split in four. The legacy synthetic receipt relation still exists for narrow crate-level tests. `TxLeafPublicRelation` is the active public bridge: it binds a canonical tx-validity receipt to a fixed-width public transaction view (nullifiers, commitments, ciphertext hashes, balance tag, version binding) plus serialized STARK public inputs. Builders derive that witness from real `TransactionProof` objects and re-verify those proofs before emitting native artifacts. The shipped native tx-leaf path now keeps a process-local setup cache keyed by `(parameter_fingerprint, spec_digest)` so the same `TxLeafPublicRelation` shape and lattice backend setup are reused across repeated tx builds/verifications instead of paying `backend.setup(...)` on every call; the cache is strictly parameter-bound and adjacent receipt-root leaf reuse is parameter-bound too, so alternate native parameter sets still fail closed rather than reusing stale verified leaves. The legacy wallet prover path is now explicit about the remaining local duplication too: `wallet::StarkProver` exposes `LocalProofSelfCheckPolicy`, preserves aggregate `proving_time` for compatibility, reports `proof_generation_time` and `local_self_check_time` separately, and when callers ask it to re-verify proof bytes locally it rebuilds the serialized verifier-facing public inputs from the witness instead of assuming that field can be omitted. The older bridge lane, `verified_tx_receipt`, now folds that same public tx-leaf relation directly from historical inline tx proofs so it remains benchmark-comparable to the native lane. Beside that, `NativeTxValidityRelation` is the real witness-driven path. It takes `TransactionWitness` directly, validates witness semantics plus Merkle membership, derives the canonical public-input object without going through a Plonky3 proof, and then feeds the native `TxLeaf` baselines that back both the shipped recursive lane and the explicit receipt-root compatibility lane. The raw `native_tx_validity` lane remains a lower-level diagnostic only, and `superneo-bench` now refuses to run any diagnostic lane unless the caller passes `--allow-diagnostic-relation`.

`circuits/superneo-backend-lattice` now implements a direct in-repo SuperNeo-style folding backend over Goldilocks behind one explicit parameter object, `NativeBackendParams`. The active family remains `goldilocks_128b_structural_commitment` with `security_bits = 128`, `ring_profile = GoldilocksFrog`, `matrix_rows = 11`, `matrix_cols = 54`, `challenge_bits = 63`, `fold_challenge_count = 5`, `max_fold_arity = 2`, `transcript_domain_label = "hegemon.superneo.fold.v3"`, `decomposition_bits = 8`, `opening_randomness_bits = 256`, `commitment_security_model = "bounded_kernel_module_sis"`, `commitment_estimator_model = "sis_lattice_euclidean_adps16"`, `max_commitment_message_ring_elems = 76`, and `max_claimed_receipt_root_leaves = 128`. Its manifest now exposes `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v8"`, `commitment_scheme_label = "bounded_message_random_matrix_commitment"`, `challenge_schedule_label = "quint_goldilocks_fs_challenge_profile_mix"`, and `maturity_label = "structural_candidate"`. The exact current protocol surface is frozen in [docs/crypto/native_backend_spec.md](docs/crypto/native_backend_spec.md), and benchmark JSON emits both the active `spec_digest` and the code-derived claim so archived measurements can be tied to one exact protocol contract. The fold transcript is still the five-challenge Goldilocks line, but the live ring law is no longer the fully splitting `X^8 + 1` quotient; the active profile now mixes folds through the `GoldilocksFrog` quotient `Z_q[X]/(X^54 + X^27 + 1)` while the commitment side remains tied to the exact bounded-kernel Module-SIS reduction note for the implemented bounded live message class plus one explicit coefficient-space Euclidean SIS estimate of the active instance. Setup rejects parameter sets whose advertised security target exceeds the configured challenge schedule, estimator-backed binding floor, or composition bound, and the parameter fingerprint plus `spec_digest` cover the manifest together with `fold_challenge_count`, `max_fold_arity`, transcript-domain settings, `commitment_security_model`, `commitment_estimator_model`, `max_commitment_message_ring_elems`, and `max_claimed_receipt_root_leaves` so future drift there cannot silently change backend behavior. The native backend release posture is separately theorem-backed at the policy layer: generated Lean vectors pin the default candidate gate and the deliberately stricter accepted-review gate, while the packaged review claim remains `candidate_under_review` / `structural_candidate` until external acceptance evidence is checked in. The tx proof backend is now version-owned separately from the folding backend: the protocol manifest commits the active tx proof family (`SmallwoodCandidate` today), the legacy Plonky3 family remains explicitly versioned for historical decoding and comparison work, native `tx_leaf` artifacts carry a trailing tx-proof-backend selector byte, and the receipt-root verifier dispatches through that selector while keeping the folding relation and receipt-root semantics fixed.

The active default `SMALLWOOD_CANDIDATE_VERSION_BINDING` is now mapped to `SmallwoodCandidate`. That path contains a real SmallWood PCS/ARK transcript generated by the in-repo Rust SmallWood engine behind a Hegemon-local Goldilocks BLAKE3 XOF/hash adapter. The Rust engine supports sparse linear constraints so packed copy/equality relations are expressible without the old C bridge. The current integrated candidate is no longer the old scalar fallback. It proves a `64`-lane packed semantic relation over the native witness surface: Poseidon2 subtrace transitions, note commitments, Merkle authentication, nullifiers, spend-auth binding, selector routing, and balance equations are enforced against the packed witness, and the repo carries a fast witness-check path that accepts the honest packed semantic witness and rejects one-word mutations for regression/debug and explicit preflight without forcing that duplicate pass on every production wallet send.

The important architectural distinction is now explicit. The failed flat `934 x 64` chunked direct layout is no longer a live proving target on this PCS. The current row-polynomial PCS/opening path proves local row neighborhoods, not arbitrary cross-row matrix slices, so both live arithmetizations, `Bridge64V1` and `DirectPacked64V1`, now use the same row-aligned `1447`-row local-gate geometry (`raw_witness_len = 295`, `poseidon_permutation_count = 143`, `poseidon_state_row_count = 4576`, `expanded_witness_len = 92608`, `lppc_packing_factor = 64`). The frozen `64`-lane target statement (`raw_witness_len = 3991`, `poseidon_permutation_count = 145`, `expanded_witness_len = 59749`, `lppc_row_count = 934`) remains a structural research target, not the current proving object. There is now one measured intermediate branch, `DirectPacked64CompactBindingsV1`, that keeps the same `64`-lane packing and Poseidon grouping but removes the duplicated output ciphertext-hash rows and stablecoin binding rows that the nonlinear relation already consumes from public values. That branch reduces the live direct geometry to `raw_witness_len = 264`, `lppc_row_count = 1416`, `expanded_witness_len = 90624`.

`DirectPacked64V1` is no longer witness-carrying. It proves and verifies through the same normal proof envelope and row-scalar PCS/opening line as `Bridge64V1`, with only the arithmetization tag distinguishing the two modes. The earlier raw-witness payload, sampled matrix-opening bundle, and replay-heavy direct checker are gone. The direct semantics kernel now stays local to authenticated row cells plus statement public values, and the direct lane is regression-locked to stay at or below the compact bridge baseline. That is the hard-stop condition in code: no raw-witness payload, no matrix-opening payload, and no fake direct success. The latest row-aligned relation also closes the public-field binding gap from the earlier redteam pass: active ciphertext hashes and stablecoin policy version / policy hash / oracle / attestation commitments now live in dedicated local secret rows that are linearly bound to the public statement.

Under the current exact no-grinding `128-bit` profile for the shipped default (`rho = 2`, `nb_opened_evals = 3`, `beta = 2`, `decs_nb_evals = 32768`, `decs_nb_opened_evals = 23`, `decs_eta = 3`, zero grinding bits), the shipped structural upper bound now projects in-repo to `90830` bytes, and the checked exact sampled release proofs on the current benchmark witness land in the `87086 .. 87214` byte band. That is about `4.1x` smaller than the legacy `354081`-byte Plonky3 proof, about `13.6% .. 13.7%` smaller than the old `100956`-byte bridge baseline, about `11.3% .. 11.6%` smaller than the former `98532`-byte shipped default, and still below the current `524288`-byte native `tx_leaf` cap. The checked profile sweep in `docs/crypto/tx_proof_smallwood_profile_sweep.json` now covers the live bridge, the older compact-binding branch, the former `DirectPacked64CompactBindingsSkipInitialMdsV1` line, and the shipped `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` line. It shows that Bridge/direct still prefer the realistic `32768 / 24 / 3` DECS point, while the shipped inline-Merkle default has one smaller realistic passing point at `32768 / 23 / 3`. The verifier now fail-closes on exact inner proof shapes, enforces distinct DECS opening indices, binds the full PCS commitment transcript into the PIOP transcript, hashes full opened combis for the DECS challenge, rejects bridge/direct opening-mode mismatches explicitly, rejects mismatched wrapper-vs-serialized public inputs before replay, rejects non-canonical or trailing SmallWood candidate wrappers before arithmetization/profile routing, and keeps recursive witness reconstruction on the same compact inner-proof serializer the live tx prover emits instead of the retired nested-`bincode` proof object. Proof-specific verifier-profile digests now bind the actual SmallWood arithmetization tag instead of assuming bridge mode, and the version-only helper is now pinned to the canonical shipped `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` profile so default proving and version-only receipt-profile derivation stay aligned. This keeps the later SmallWood release cryptography swap local to one backend-specific byte format while leaving the folding layer unchanged, and it is no longer a witness-carrying mock or a geometry-proxy binding story. `Bridge64V1` remains a measured baseline at `100956` bytes. `DirectPacked64CompactBindingsV1` still proves and verifies under the same release profile and measures `99828` release bytes, recorded in `docs/crypto/tx_proof_smallwood_compact_bindings_size_report.json`. `DirectPacked64CompactBindingsSkipInitialMdsV1` remains the previous shipped line at `98532` bytes. The shipped default is now `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` with a `90830`-byte structural upper bound and checked exact sampled proofs in the `87086 .. 87214` byte band, recorded in `docs/crypto/tx_proof_smallwood_current_size_report.json`. The repo now also carries a semantic LPPC seam in `circuits/transaction/src/smallwood_lppc_frontend.rs`: it materializes the exact `NativeTxValidityRelation` witness order from `TransactionWitness`, binds the same native statement/public-input digests the shipped tx proof uses, fixes the v1 semantic LPPC window at `4096` elements, and runs those shapes through the current SmallWood structural projection and soundness path. The checked structural frontier in `docs/crypto/tx_proof_smallwood_semantic_lppc_frontier_report.json` is `1024x4=52874`, `512x8=36346`, and `256x16=31154`, all still clearing the no-grinding `128-bit` structural floor. The repo now also has an exact current-engine opening-layer spike over that same witness window in `docs/crypto/tx_proof_smallwood_semantic_lppc_identity_spike_report.json`, and sampled exact prove/verify roundtrips now land materially below the structural projection on the current tree. The full auxiliary-Poseidon fallback is still dead on economics: `docs/crypto/tx_proof_smallwood_semantic_lppc_auxiliary_poseidon_spike_report.json` shows that carrying the full current Poseidon subtrace as auxiliary witness balloons the object to `472008 .. 493536` bytes, and the exact `512x8` spike now matches that projection after fixing the auxiliary replay bug in the engine. The more interesting backend floor is now `docs/crypto/tx_proof_smallwood_semantic_helper_aux_report.json`: if the semantic LPPC witness window keeps the grouped Poseidon rows in-domain and moves only the lane-visible helper surface into auxiliary witness, the winning `64x` point lands at `92402` projected bytes. That floor used to beat the shipped line; it no longer beats the current shipped line. By contrast, `docs/crypto/tx_proof_smallwood_semantic_helper_floor_report.json` still shows `99794` bytes once those helper rows return as explicit opened rows. That narrows the remaining problem further. The current opening layer is already compatible with the semantic LPPC witness window, but the shipped bridge statement just proved a stricter backend point: any future semantic-adapter branch now has to beat the `90830`-byte structural upper bound and the current `87086 .. 87214` checked exact band, not merely clear the older `98532` default.

* pack witness values with pay-per-bit widths in `superneo-ring`,
* expand the packed witness to low-bit digits,
* embed those digits into small ring elements over Goldilocks,
* commit to the resulting ring vector with a deterministic Ajtai-style public matrix over that ring,
* derive the native commitment deterministically from the public tx view plus serialized STARK public inputs instead of shipping any witness or commitment-opening bytes,
* bind each leaf to its statement digest and witness-commitment digest in a compact native leaf proof,
* fold commitments with transcript-derived linear challenges and explicit parent rows so malformed fold rows or mixed parent/child commitments fail algebraic verification rather than falling back to a digest-only placeholder.

For the live experimental `ReceiptRoot` path, import consumes standalone native `TxLeaf` artifacts instead of decoding inline tx proof bytes on that lane. The verifier now reconstructs the expected packed witness from the on-chain tx public view plus the serialized STARK public inputs, verifies the embedded STARK proof bytes directly, rejects mismatched `spec_digest` values and oversized artifacts before deep decode, verifies the deterministic commitment under the manifest-owned parameter set, derives the ordered `TxStatementBinding`s from those verified leaves, and only then accepts the folded receipt root. The older bridge path that still starts from inline tx proofs is benchmarked as `verified_tx_receipt`, but it now exists only as a comparison lane. The native artifact path no longer pays for hidden witness transport or a public commitment-opening object; it pays only for public tx data, STARK proof bytes, the derived commitment rows, and the native leaf proof. The active live security floor therefore comes from transcript soundness minus the explicit receipt-root composition loss, capped by the exact coefficient-space Euclidean SIS estimate computed for the active bounded-kernel Module-SIS instance; it does not count an opening-hiding term because the shipped artifact path does not use a live public opening/seed flow. The exact reduction note now lives in [docs/crypto/native_backend_commitment_reduction.md](docs/crypto/native_backend_commitment_reduction.md). Import hardening adds exact size rejection for native tx-leaf and receipt-root artifacts, a Lean-backed receipt-root structural gate for exact non-empty leaf/fold schedule and fold row dimensions before cryptographic fold checks, plus a reusable verified-native-leaf store keyed by native artifact hash, and the product verifier now defaults to the `verified_records` root-verification path so it consumes those already-verified native leaf records instead of replaying the full leaf verifier a second time. Replay-heavy root verification remains available as a diagnostic cross-check mode. On the SmallWood candidate backend specifically, the release verifier now fail-closes on exact PCS payload shapes, requires distinct DECS opening indices, binds the full PCS commitment transcript into the PIOP transcript, and derives both commitment-time and verifier-time polynomial openings from the explicit LVCS interpolation domain rather than the earlier broken “rotate and treat as consecutive” shortcut. The redteam regressions also now cover forged self-consistent PCS payloads, wrapper-level PCS splicing, `partial_evals` tampering, and malformed `all_evals` payloads without panic. `HEGEMON_REQUIRE_NATIVE=1` still fail-closes authoring/import by rejecting non-canonical selectors, `InlineTx` fallback outcomes, and non-canonical receipt-root payloads. Historical backend-hardening plans now live under [.agent/archive/proof-history](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/archive/proof-history), while the exact current spec and claim model remain in [docs/crypto/native_backend_spec.md](docs/crypto/native_backend_spec.md), [docs/crypto/native_backend_commitment_reduction.md](docs/crypto/native_backend_commitment_reduction.md), and [docs/crypto/native_backend_security_analysis.md](docs/crypto/native_backend_security_analysis.md).

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

Given that ML‑KEM decapsulation is not *that* expensive and users don’t have thousands of addresses typically, trial decryption is acceptable in v1. The scanning cost is of the same order of magnitude as a contemporary shielded-wallet scan/decryption pass.

**Full viewing key** `vk_full`:

* Contains everything in `vk_incoming`, plus:

  * enough info to recompute nullifiers (`nk` or a view‑equivalent),
  * so it can see which of “its” notes have been spent.

Hegemon chooses the watch‑only path: full viewing keys include the spend-derived nullifier PRF output (`prf_nf`) so wallets can compute
nullifiers for spentness tracking without embedding `sk_spend`.

### 4.5 Implementation details

*Key derivations and addresses.* `wallet/src/keys.rs` implements `RootSecret::derive()` using the domain-separated label `wallet-hkdf` and SHA-256 to expand `(label || sk_root)` into the 32-byte subkeys for spend/view/enc/diversifier. `AddressKeyMaterial` then uses `addr-seed` plus the diversifier index to deterministically derive the ML-KEM key pair; `pk_recipient` is derived from the view key and diversifier while `pk_auth` is derived from the spend key via the Poseidon2 key schedule used by the circuit. `wallet/src/address.rs` serializes `(version, crypto_suite, index, pk_recipient, pk_auth, pk_enc)` as a Bech32m string (HRP `shca`) so senders can round-trip addresses through QR codes or the CLI.

*Note encryption.* `wallet/src/notes.rs` consumes the recipient’s Bech32 data, runs ML-KEM encapsulation with a random seed, and stretches the shared secret into two ChaCha20-Poly1305 keys via `expand_to_length("wallet-aead", shared_secret || label || crypto_suite, 44)`. The first 32 bytes drive the AEAD key and the final 12 bytes form the nonce so both note payload and memo use disjoint key/nonce pairs. Ciphertexts record the version, crypto suite, diversifier index, and ML-KEM ciphertext so incoming viewing keys can reconstruct the exact `AddressKeyMaterial` needed for decryption. The AEAD AAD binds `(version, crypto_suite, diversifier_index)` so header tampering fails authentication. Runtime admission hard-cuts to current header version `v3`; any other version is rejected. The crypto-format and chain-format note ciphertext parsers exact-consume their byte streams and are Lean-vector-gated for truncation, trailing bytes, memo overrun, zero fixed-container padding, canonical compact KEM length encoding, and fixed ML-KEM ciphertext length.

*Viewing keys and nullifiers.* `wallet/src/viewing.rs` defines `IncomingViewingKey` (scan + decrypt), `OutgoingViewingKey` (derive `pk_recipient` for audit), and `FullViewingKey` (incoming + spend-authority metadata). Full viewing keys now store the spend-derived nullifier PRF output (not the spend secret), so wallets can compute chain nullifiers while the transaction witness still proves knowledge of `sk_spend` in-circuit. `RecoveredNote::to_input_witness` converts decrypted notes into `transaction_circuit::note::InputNoteWitness` values by reusing the same `NoteData` and taking the best-effort `rho_seed = rho` placeholder until the circuit’s derivation is finalized.

*CLI, daemon, and fixtures.* `wallet/src/bin/wallet.rs` now ships three families of commands:

  * Offline helpers (`generate`, `address`, `tx-craft`, `scan`) that mirror the deterministic witness tooling described in DESIGN.md. `tx-craft` emits redacted witness JSON (no serialized `sk_spend`) so exported artifacts are safe to share.
* Wallet management over native node RPC (`wallet init`, `wallet node-sync`, `wallet node-daemon`, `wallet node-send`, `wallet status`, `wallet export-viewing-key`). `wallet init` writes an encrypted store (Argon2 + ChaCha20-Poly1305) containing the root secret or an imported viewing key. `wallet node-sync` and one-shot send/status flows can use HTTP or WebSocket RPC to fetch commitments/ciphertexts/nullifiers and maintain a local Merkle tree/nullifier set, while subscription-backed `wallet node-daemon` still requires WebSocket. `wallet node-send` crafts witnesses, proves them locally, and submits a shielded transfer before tracking pending nullifiers.
  * Ciphertext sync is robust to DA/sidecar quirks: ciphertext indices can have gaps (retention) and may include non-canonical ciphertexts during forks. The wallet maps decrypted notes back to commitment positions via the commitment list and skips any decrypted note whose commitment cannot be found locally.
* Native RPC wallet management (`node-sync`, `node-daemon`, `node-send`, `node-batch-send` gated behind the `batch-proofs` feature) that uses native JSON-RPC for live wallets. One-shot commands accept HTTP or WebSocket endpoints; daemon/subscription mode remains WebSocket-only. `wallet node-send` records outgoing disclosure records inside the encrypted store so on-demand payment proofs can be generated later. In v0.9 strict mode, `walletd` defaults to self-contained submission (`HEGEMON_WALLET_DA_SIDECAR=0`) so proof/ciphertext bytes propagate with the transaction across miners; sidecar staging remains opt-in for controlled topologies.
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
* Release-coordination documentation (`governance/VERSIONING.md`) specifies how to draft a proposal, publish the activation window, and ship the canonical schedule hash inside an adopted release line, while the operational runbook (`runbooks/emergency_version_swap.md`) walks operators through emergency swaps: announce the swap, enable the upgrade circuit, watch `version_counts` to ensure old notes migrate, then retire the deprecated binding at the scheduled height.

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
* Signature: ML-DSA-65xx (Dilithium-level) or category-3 equivalent with approximately 2–3 KB signatures and 1–2 KB public keys. Native PoW seals and node-authenticated envelopes reuse this scheme, hashing PQ public keys into 32-byte ids so address encoding stays stable while signatures grow.

We do not need signatures inside the shielded circuit, only for block authentication and possibly transaction-level authentication.

#### 1.5 Network identity seeds

PQ network identities are derived from a 32-byte secret seed that must be generated from OS entropy and persisted on disk with restrictive permissions (mode 0600). The node loads this seed from `HEGEMON_PQ_IDENTITY_SEED` (hex) when provided, otherwise it reads `HEGEMON_PQ_IDENTITY_SEED_PATH` or defaults to `<base-path>/pq-identity.seed`. The seed is never derived from public peer IDs; peer IDs are computed from the public keys that result from this secret seed. This keeps PQ transport identity keys unpredictable while keeping peer identity stable across restarts.
Every session must still rekey: both the modern PQ transport and the legacy `PeerIdentity` handshake use OS-random KEM encapsulation seeds plus fresh transcript nonces per connection, so repeated connections between the same persisted identities do not reuse the first AEAD key/nonce pair.

#### 1.6 Peer discovery (PQ address exchange)

The Hegemon node’s PQ network stack is **not** libp2p, so we do not get Kademlia/mDNS discovery “for free”.

Instead, once a PQ connection is established, peers run a small “address exchange” protocol over the PQ framed message channel:

* Protocol id: `/hegemon/discovery/pq/1`
* Messages (`HNW1` version marker plus bounded postcard encoding):

  * `Hello { listen_port }` – the receiver combines the *observed peer IP* with `listen_port` to form a dialable `IP:port` even if the connection’s TCP source port was ephemeral.
  * `GetAddrs { limit }` and `Addrs { addrs }` – bounded address lists used to share additional dial targets beyond seeds.
  * `GetPeerGraph { limit }` and `PeerGraph { peers }` – bounded lists of currently connected peers used to build a multi-hop peer graph for dashboards.

Nodes persist learned addresses under the native `--base-path` (cache file: `<base-path>/pq-peers.bin`) and opportunistically dial a small batch of learned addresses when peer count is low. `HEGEMON_SEEDS` remains the bootstrap mechanism; operators should use `HEGEMON_SEEDS="hegemon.pauli.group:30333"` unless the approved seed list has deliberately rotated, and miners on the same network must share the same seed list to avoid partitions. Mining hosts must keep NTP or chrony enabled because future-skewed PoW timestamps are rejected.

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
* Parser admission exact-consumes both the fixed container and KEM tail: memo overruns, nonzero padding, noncanonical compact lengths, truncated payloads, and trailing bytes reject before wallet scan or transaction construction can treat bytes as canonical.

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

This does not change the total number of required consolidation transactions in the worst case (with 2→1 merges it is still `note_count - MAX_INPUTS`), but it reduces wall-clock time by letting miners include multiple independent merges in the same block when space permits. The batch-size budget must stay below the native node’s configured block action capacity. Operators can tune consolidation throughput with `HEGEMON_WALLET_CONSOLIDATION_MAX_TXS_PER_BATCH` and `HEGEMON_WALLET_CONSOLIDATION_MAX_BATCH_BYTES`; sidecar/proof-sidecar behavior is controlled by `HEGEMON_WALLET_CONSOLIDATION_DA_SIDECAR` and `HEGEMON_WALLET_CONSOLIDATION_PROOF_SIDECAR`.

#### 5.1 Public inputs

The circuit's public inputs (fed into its transcript) are:

* `root_before` - Merkle root anchor encoded as six field elements.
* For each input `i`: `input_active[i] ∈ {0,1}` and `nf_in[i]` is a 6-limb nullifier, with inactive inputs using all-zero limbs.
* For each output `j`: `output_active[j] ∈ {0,1}` and `cm_out[j]` is a 6-limb commitment, with inactive outputs using all-zero limbs.
* For each output `j`: `ct_hash[j]` as a 6-limb ciphertext hash (padded with zeros for inactive outputs).
* `fee_native ∈ F_p` and `value_balance` split into a sign bit plus a 61-bit magnitude.
  In production, `value_balance` is required to be zero because there is no transparent pool.
* `balance_slot_asset_ids[0..3]`, where slot `0` is the native asset, active non-native asset ids are strictly increasing, and padding uses `u64::MAX` only as a suffix.
* Stablecoin public payload fields: `stablecoin_enabled`, `stablecoin_asset_id`, `stablecoin_policy_hash`, `stablecoin_oracle_commitment`, `stablecoin_attestation_commitment`, `stablecoin_issuance_delta` encoded as sign plus magnitude, and `stablecoin_policy_version`.

The AIR now binds `ct_hash[j]` at the final-row gate (the hash value itself is still computed outside the circuit from ciphertext bytes).

The transaction envelope still carries the full `balance_slots` vector and a `balance_tag`, which are validated outside the STARK for now.
`root_after` and any `txid` binding are handled at the block circuit layer (or a future transaction-circuit revision).

As an additional integrity check outside the STARK, the runtime and wallet compute a 64-byte binding hash over the public inputs:

```
message = anchor
       || len_u32(nullifiers) || nullifiers
       || len_u32(commitments) || commitments
       || len_u32(ciphertext_hashes) || ciphertext_hashes
       || fee || value_balance || balance_slot_asset_ids
       || stablecoin_enabled || stablecoin_asset_id
       || stablecoin_policy_hash || stablecoin_oracle_commitment
       || stablecoin_attestation_commitment || stablecoin_issuance_delta
       || stablecoin_policy_version
binding_hash = Blake2_256("binding-hash-v3" || 0 || message)
             || Blake2_256("binding-hash-v3" || 1 || message)
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

The repository now wires this design into executable modules. The `state/merkle` crate implements an append-only `CommitmentTree` that precomputes default subtrees, stores per-level node vectors, and exposes efficient `append`, `extend`, and `authentication_path` helpers. It uses the same Poseidon-style hashing domain as the transaction circuit, ensuring leaf commitments and tree updates are consistent with the ZK statement. `TransactionProof::verify` rejects missing STARK proof bytes/public inputs in production builds. On top of that, the block-artifact path lives in `circuits/block-recursion`. One caveat is now explicit in the codebase instead of hidden in stale constants: the legacy `RecursiveBlockV1` width of `699,404` bytes is only validated through the first `StepA` terminal. The current diagnostic report measures `BaseA = 41,371`, first `StepB = 162,763`, first `StepA = 561,075`, and steady-state `StepB = 1,868,811`, so `v1` is not a general constant-size recursive lane on the current backend. The lane remains available only as a legacy compatibility/debug path, and it still requires empty legacy `commitment_proof` bytes so no linear public-input payload can be smuggled through the old field, but the repo no longer treats its `699,404`-byte container as a universal steady-state cap. The `circuits/block` crate and its `CommitmentBlockProof` remain available only for the explicit native `ReceiptRoot` compatibility lane. The fresh-chain product path no longer accepts `InlineRequired` verification for non-empty shielded blocks, and strict authoring now requires a ready `submit_proven_batch` / `submit_candidate_artifact` payload for shielded candidates instead of falling back to `proven_batch: None`. Recursive epoch proofs remain removed; the live product block-artifact path is still `RecursiveBlock`, while `ReceiptRoot` remains an alternate native lane. The tree-reduced `RecursiveBlockV2` lane now owns the bounded-domain invariant instead of inheriting the old `v1` proof cap, and its verifier exact-consumes the canonical compact proof prefix from the padded proof field before relation reconstruction. It uses `TREE_RECURSIVE_CHUNK_SIZE_V2 = 1000`, supports at most `1000` txs per recursive artifact version, and currently serializes to a fixed `522,159`-byte outer artifact under that bounded domain. In other words, the shipped `v2` point is now “one bounded chunk proof carried in the `v2` artifact envelope” rather than “a shallow merge tree,” because that geometry is both smaller and faster on the current backend while preserving the same public verification contract. Consensus/runtime admission now accepts `RecursiveBlockV2` payloads by that derived cap, and it is the shipped recursive block lane because it is the only recursive lane in the repo with a currently validated constant-size bound across its supported domain.

Aggregation payloads are now part of the shipped 0.10.0 shielded block path. `consensus::types::Block` carries canonical ordered `tx_validity_claims` plus an optional neutral `block_artifact` envelope; backend-specific `tx_validity_artifacts` no longer travel inside the generic block model and are instead passed only through explicit verifier/build helper inputs at the backend boundary. On the fresh-chain product path any non-empty shielded block must carry the native `recursive_block` artifact and verify under `SelfContainedAggregation`. The old `InlineTx` label survives only as historical vocabulary in archived benchmarks and compatibility-oriented test vectors, not as a live product consensus mode, and `ReceiptRoot` is now the explicit alternate native lane rather than the shipped default.

Block-proof payload compatibility is hard-cut to schema `2` + proof format id `5` in active import logic. Nodes reject malformed or legacy payload versions fail-closed. Import treats the optional block artifact as a neutral `(proof_kind, verifier_profile, bytes)` object even when the on-chain payload still carries the legacy `proof_mode` selector for compatibility. On the shipped `RecursiveBlock` lane, import verifies the ordered native `TxLeaf` artifacts, derives the exact semantic tuple `(tx_statements_commitment, state roots, kernel roots, nullifier_root, da_root)` from the verified leaf stream plus parent state and block body, and then verifies the constant-size recursive artifact against that tuple while rejecting any non-empty legacy `commitment_proof` bytes. The explicit `ReceiptRoot` lane remains in-tree as a compatibility/native comparison surface: when selected, import verifies the ordered native `TxLeaf` artifacts, reconstructs the packed public witness from the on-chain tx object plus the serialized public inputs carried in each artifact, verifies the embedded STARK proof bytes, deterministically derives the canonical tx-validity receipts and `TxStatementBinding`s from those verified leaves, checks that the resulting statement-hash list commits to the block’s expected `tx_statements_commitment`, and only then accepts the folded receipt-root artifact. The old recursive `MergeRoot`, manifest-style `FlatBatches`, warm-store accumulation wrapper, and residual ARC/WHIR lane were removed from consensus, node authoring/import, tests, and operator selection after they failed the product bar.

The native node persists every imported block by hash and stores cumulative work in block metadata. Side branches with known parents are validated against replayed parent state; if a side branch wins, the node replays the winning chain from genesis and rebuilds canonical sled indexes for heights, commitments, nullifiers, ciphertexts, and pending actions. Pending root preview first plans the in-memory action stream through the checked stream helper, so duplicate nullifiers, replay-key reuse, and commitment index overflow reject before template or commitment roots are derived. Canonical index rebuild first plans the whole replayed action stream through the same helper used by import, so duplicate nullifiers, replay-key reuse, ciphertext/commitment count mismatches, and commitment index overflow reject before rebuilt indexes are written. Reorganization and startup canonical-index repair now compute the full canonical index rebuild plan before installing replacement canonical height, commitment, nullifier, replay, or ciphertext indexes; a missing sidecar ciphertext or other semantic rebuild failure leaves the previous canonical indexes intact. Winning reorgs and startup canonical-index repairs install their rebuilt canonical rows through sled transactions. Startup canonical block-index reload now flows through a Lean-conformance-checked admission table: it fails closed unless the stored best block exists by hash, best metadata matches that hash-addressed record, the parent chain reconstructs from the computed native genesis, canonical block heights/chain id/rules hash/work hash and every height index are exact, and the genesis marker is valid or absent. Missing legacy genesis markers are repaired only after the chain and height index validate; sled transaction implementation correctness, operating-system fsync semantics, disk firmware behavior, and crash-consistency below sled remain outside the Lean proof. Startup commitment/nullifier reload also flows through a Lean-conformance-checked admission table: nullifier keys and markers must be exact, persisted commitment entries must be contiguous canonical indexes, the commitment tree must rebuild, and the loaded commitment/nullifier roots must match the committed best header roots. Shielded coinbase is also a native action: a block may append one coinbase note commitment, and when present its amount must equal subsidy plus included transfer fees before the supply digest is accepted. Local mining with `HEGEMON_MINER_ADDRESS` builds that note before previewing roots or hashing the header preimage, while validators recompute the public note commitment from amount, compact recipient fields, and public seed before payload admission accepts.

Node and consensus routing are collapsed onto one explicit `ArtifactRoute = (ProvenBatchMode, ProofArtifactKind)`. That route is the real product selector above the backend seam. The shipped route is `(RecursiveBlock, RecursiveBlockV2)`. The explicit alternate native route is `(ReceiptRoot, ReceiptRoot)`. Keeping that pair explicit matters because the payload still carries the older `proof_mode` field for compatibility, while authoring caches, RPC announcements, and selector logic need exact route identity to avoid wrong-lane reuse. In other words, mode and artifact kind are no longer treated as independently meaningful choices in product code; they travel together as one route and the rest of the system keys on that route plus the verifier-profile digest. The proof-layer split above that edge is explicit too: `consensus/src/backend_interface.rs` is the single facade that re-exports backend proof helpers for the rest of `consensus` and `node`, while `consensus/src/proof_interface.rs` owns the stable backend-neutral contracts.

The hostile proof-surface review tightened the same shipped path against malformed-byte and stale-assumption attacks. Outer `TransactionProof` wrappers and SmallWood candidate wrappers exact-consume and require canonical serialization before backend/profile routing; shipped proof carriers (`tx-proof-manifest`, disclosure, batch, block-commitment, and tx-leaf artifacts) now do the same on their trust boundaries; recursive witness reconstruction canonicalizes the compact inner SmallWood proof bytes instead of assuming the retired nested-`bincode` object; recursive prove/verify helpers derive the no-grinding profile from the arithmetization tag; the local recursive verifier accepts the compact DECS auth-path encoding used by the live tx backend; and the outer fixed-width recursive artifact verifier now decodes a canonical compact proof prefix from the padded proof field and requires zero padding after the consumed prefix.

Canonical transaction-validity receipts are still derived from a tx statement hash, proof digest, serialized public-input digest, and verifier-profile digest, and the experimental receipt-root adapter re-checks that exact receipt object during import. Generic consensus/node code now reaches that backend only through neutral receipt-root helper APIs, not by importing `superneo-*` crates directly. Native authoring uses local reusable-artifact discovery helpers (`prover_listArtifactAnnouncements`, `prover_getCandidateArtifact`). Aggregation candidate selection still drops proof-sidecar transfers whose ciphertext bytes are not available in the local pending sidecar store, preventing endless reproving loops on nodes that did not receive the sidecar payloads directly.

The benchmark harness still distinguishes the canonical native leaf baseline from historical comparison surfaces: `raw_shipping` is the frozen transport baseline, `raw_active` is the legacy inline-proof comparison lane, `merge_root_active` remains only as historical benchmark context, `verified_tx_receipt` is the older bridge experiment built from real inline tx proofs plus a folded receipt-root artifact using the same `TxLeafPublicRelation`, `native_tx_validity` is the lower-level witness diagnostic lane, and `native_tx_leaf_receipt_root` is the decision-grade native leaf baseline. Those numbers are current implementation measurements for the experimental topology and native relation, not final claims about paper-faithful Neo/SuperNeo security.

Batch STARK verification still caches `setup_preprocessed()` verifier keys by proof shape (`degree_bits`, inferred FRI blowup) so preprocessed trace commitments are built once and reused across block imports; node startup prewarms the configured shape set via `HEGEMON_BATCH_VERIFY_PREWARM_TXS` (defaults to the current `HEGEMON_BATCH_SLOT_TXS` power-of-two profile). Prove-ahead block preparation still caches prepared bundles keyed by the neutral prepared-artifact selector plus `(tx_statements_commitment, tx_count, shape profile)` via `HEGEMON_PROVE_AHEAD_CACHE_CAPACITY`, so parent transitions only pay the parent-bound commitment step when the candidate set is unchanged. Receipt-root authoring now adds a second reuse layer below that coarse bundle cache on the explicit alternate native lane: the native builder splits ordered `tx_leaf` artifacts into deterministic `8`-leaf mini-roots, caches verified leaf material plus cached chunk folds by native artifact identity via `HEGEMON_RECEIPT_ROOT_CACHE_CAPACITY`, and service-side worker planning can run the aggregation build on a dedicated Rayon pool sized by `HEGEMON_RECEIPT_ROOT_WORKERS`. Fresh builds still perform about `N - 1` folds overall, but exact repeats skip the whole bundle, and one-leaf or near-repeat candidates can reuse most of the lower tree. Coordinator scheduling now gates readiness on the current parent/generation only: stale-parent prepared bundles are retained only in a bounded recent-parent window for cache amortization, they no longer suppress new-parent scheduling, and remote artifact-protocol announcements/responses are not trusted as authoring inputs. Operator-facing mode selection is now simple: the fresh-chain product default is `HEGEMON_BLOCK_PROOF_MODE=recursive_block`, the explicit alternate native lane is `HEGEMON_BLOCK_PROOF_MODE=receipt_root`, and the node’s unconfigured product path expects same-block native recursive bundles rather than legacy inline block verification.

The commitment proof binds `tx_statements_commitment` (derived from the ordered list of canonical transaction statement hashes) and proves nullifier uniqueness in-circuit (a permutation check between the transaction-ordered nullifier list and its sorted copy, plus adjacent-inequality constraints). The proof also exposes starting/ending state roots, nullifier root, and DA root as public inputs, but consensus recomputes those values from the block’s transactions and the parent state and rejects any mismatch; this keeps the circuit within a small row budget while preserving full soundness. The native candidate artifact carries the computed `da_root` plus `chunk_count` explicitly so importers can fetch DA chunks before reconstructing ciphertexts and archive audits can select valid chunk indices.

Data availability uses a dedicated encoder in `state/da`. The block’s ciphertext blob is serialized as a length-prefixed stream of ciphertexts (ordered by transaction order, then ciphertext order) and erasure-encoded into `k` data shards of size `da_params.chunk_size` plus `p = ceil(k/2)` parity shards. The Merkle root `da_root` commits to all `n = k + p` shards using BLAKE3 with domain tags `da-leaf` and `da-node`. Consensus recomputes `da_root` from the transaction list and rejects any mismatch before verifying proofs. Sampling is per-node randomized: each validator chooses `da_params.sample_count` shard indices, fetches the chunk and Merkle path over P2P, and rejects the block if any sampled proof fails.

Two on-chain policies gate these checks: `DaAvailabilityPolicy` selects between `FullFetch` (reconstruct and verify `da_root`) and `Sampling` (verify randomized chunks against the commitment payload’s `da_root`/`chunk_count` without full reconstruction), and `CiphertextPolicy` toggles whether inline ciphertext bytes are accepted or sidecar-only submissions are enforced. The node consults the runtime API for the active policy on import, so the network can start with full storage and migrate to sampling + sidecar enforcement as the prover/DA markets mature.

Operationally, the node persists DA encodings and ciphertext bytes for a bounded “hot” retention window and prunes old entries by block number. Ciphertexts use `HEGEMON_CIPHERTEXT_DA_RETENTION_BLOCKS` (falling back to legacy `HEGEMON_DA_RETENTION_BLOCKS`). Proof sidecars are no longer consensus-critical in Phase C; retention for proposer staging is operational, not validity-critical.

For throughput benchmarking, the local artifact-worker cache lifecycle matters as much as raw prover count. `scripts/throughput_scaling_matrix.sh` now keeps worker prewarm disabled only during funded snapshot creation, because snapshots never build the optional `ReceiptRoot` artifact. Real strict throughput points default to worker prewarm enabled and, unless the operator overrides `HEGEMON_SCALE_AGG_PREWARM_MAX_TXS`, they prewarm the exact target `tx_count` shape before send. The matrix also defaults to `HEGEMON_AGG_PREWARM_INCLUDE_MERGE=0`, which now only means “do not synthesize extra historical aggregation shapes during startup”; the removed merge-root lane is gone from product routing. This prevents the matrix from charging thread-local cache/common-data setup to the first live native batch while keeping startup materially lower than the old full-prewarm path. Operators can still force broader warmup explicitly by setting `HEGEMON_SCALE_AGG_PREWARM_INCLUDE_MERGE=1`, but that now affects only historical benchmark surfaces rather than any shipped proof mode.

`verify_block` expects miners to supply the current tree state. On the shipped `RecursiveBlock` lane it recomputes the canonical transaction statement hash list, derives the semantic tuple directly from the verified leaf stream plus parent state and block body, rejects any non-empty legacy `commitment_proof` bytes, verifies the recursive artifact against that tuple, and then updates the tree to the expected ending root. On the explicit `ReceiptRoot` lane it still verifies the parent-bound commitment proof plus the folded receipt-root artifact. Verifier-side statement-anchor admission is Lean-gated separately before recursive semantic derivation and artifact verification: `Hegemon.Consensus.StatementAnchorAdmission.accepts_iff_statement_anchor_preconditions` proves that every transaction has one statement binding and that every binding anchor is known in the parent commitment-tree root-history window, while generated vectors check the production `validate_statement_anchor_history` helper including retained-history acceptance, binding-count rejection, unknown-root rejection, and rejection of anchors created only by earlier same-block appends. The final commitment-tree transition control flow is Lean-gated separately: `Hegemon.Consensus.TreeTransition.tree_transition_accepts_iff_preconditions` proves that acceptance requires proof starting-root agreement, successful nonzero-commitment application, and proof ending-root agreement, while generated vectors check the production `verify_and_apply_tree_transition_without_anchors` helper including zero commitment filtering, tree-full failure, accepted applied-root return, and rejection precedence. Solo miners follow a simple operational loop: sync the tree, wait for the ready native bundle when a shielded candidate exists, run the block verifier on any candidate they plan to extend, update their local `VersionSchedule`, and only then start hashing on top of the verified root. Mining pauses while the node is catching up to peers so local hashing never races against historical imports. Public authoring nodes do the same before broadcasting templates or blocks, so every verifier sees the same state transition without needing an external prover host in the live path. Operators must configure the same `HEGEMON_SEEDS` list across miners to avoid forked peer partitions, and must keep NTP/chrony time sync enabled because PoW headers with timestamps beyond the future-skew bound are rejected. This provides the current concrete path from transaction proofs to a mandatory block-level proof artifact that consensus checks before accepting any non-empty shielded block. The operational growth path for this authoring model is tracked in [docs/SCALABILITY_PATH.md](docs/SCALABILITY_PATH.md): start with one public authoring node running the native recursive-block product path, raise proof-ready transaction throughput, then add federated authors before attempting any public prover market.

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

The `crypto/` crate provides safe Rust bindings for the PQ primitives referenced throughout the design. All APIs use fixed-length byte arrays so serialization matches the NIST ML-DSA, SLH-DSA, and ML-KEM parameter sizes. ML-KEM and ML-DSA use final RustCrypto implementations; SLH-DSA remains on the newest RustCrypto release candidate and is explicitly tracked in the dependency waiver policy until a final FIPS 205 crate is available.

Module layout:

* `crypto::ml_dsa` – exposes `MlDsaSecretKey`, `MlDsaPublicKey`, and `MlDsaSignature` with `SigningKey`/`VerifyKey` trait implementations over ML-DSA-65. Public keys are 1952 bytes, expanded compatibility secret keys are 4032 bytes, and signatures are 3309 bytes.
* `crypto::slh_dsa` – mirrors the ML-DSA interface but with SLH-DSA key lengths (32 B public, 64 B secret, 17088 B signatures).
* `crypto::ml_kem` – wraps ML-KEM-1024 with `MlKemKeyPair`, `MlKemPublicKey`, and `MlKemCiphertext`. Public keys and ciphertexts are 1568 bytes, expanded compatibility secret keys are 3168 bytes, and shared secrets are 32 bytes. The deterministic seed-taking API exists for KATs and reproducible wrappers; protocol callers must feed it secret OS randomness and bind transcripts only through HKDF/info or AEAD AAD. The PQ Noise session HKDF labels/input ordering, role-to-key mapping, nonce layout, counter overflow behavior, InitHello/RespHello/Finish signing preimage grammar, and assumption-explicit handshake-to-channel composition are represented in Lean and checked by generated vectors plus theorem gates against the production `pq-noise` helpers. The legacy network secure-channel KDF preimage labels, role-to-key mapping, nonce layout, and counter overflow behavior are represented in Lean and checked by generated vectors against the production `network` helpers.
* `crypto::hashes` – contains `sha256`, `sha3_256`, `blake3_256`, `blake3_384`, a Poseidon-style permutation over the Goldilocks prime (width 3, 63 full rounds, NUMS constants), and helpers `commit_note`, `derive_prf_key`, and `derive_nullifier` (defaulting to 48-byte BLAKE3-384 with SHA3-384 fallbacks via `commit_note_with`) that apply the design’s domain tags (`"c"`, `"nk"`, `"nf"`). PQ address hashes remain BLAKE3-256 by default while commitments/nullifiers normalize on 48-byte digests.
* Native identity records store optional PQ session keys as protocol metadata. New registrations supply PQ bundles through release/governance tooling when that surface is reintroduced.
* Historical attestation and settlement storage treated verifier parameters as mutable state; the proof-native cut treats these as protocol-release parameters instead. The active default tx proof backend is now `SmallwoodCandidate`, and the version-owned manifest surface in `protocol/versioning` no longer advertises a Plonky3 FRI profile for that default binding. The old fixed-`log_blowup = 4`, `num_queries = 32`, `query_pow_bits = 0` Plonky3 profile remains checked in under `docs/crypto/tx_proof_profile_sweep.json` and `docs/crypto/tx_proof_soundness_analysis.md` as legacy comparison material. The active SmallWood profile note lives in `docs/crypto/tx_proof_smallwood_no_grinding_soundness.md`. With 384-bit digests, PQ collision resistance reaches ~128 bits.

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
   - `cargo test -p consensus`, `cargo test -p network`, `cargo test -p protocol-kernel`, `cargo test -p protocol-shielded-pool`, and `cargo test -p hegemon-node --lib` for the live protocol/node/network path.
   - `cargo test -p transaction-circuit`, `cargo test -p block-circuit`, and `cargo test -p disclosure-circuit` for the circuits that still back the shipped wallet/disclosure flow.
   - `cargo test -p wallet` plus `cargo test --test security_pipeline -- --nocapture` for the wallet/store/send pipeline.
   The expensive `circuits/batch` proving tests are intentionally `#[ignore]` because that auxiliary batch lane is not part of the live InlineTx authoring path; default CI keeps only cheap structural sanity coverage for that crate.
3. **Manual security harnesses** – run these only when touching the relevant surface:
   - `cargo test -p consensus --test fuzz -- --ignored` (consensus duplicate-nullifier property coverage).
   - `PROPTEST_CASES=64 cargo test -p transaction-circuit --test security_fuzz` (transaction witness invariants).
   - `PROPTEST_CASES=64 cargo test -p network --test adversarial` (handshake tampering).
   - `PROPTEST_CASES=64 cargo test -p wallet --test address_fuzz` (address encode/decode mutations).
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
| `formal-core` | Runs `bash scripts/check_formal_core.sh`, which builds the pinned Lean proof kernel, checks generated Lean-to-Rust bridge, bridge checkpoint-output canonical/journal bytes, bridge long-range proof-shape, bridge header-MMR opening-shape, bridge header-MMR parent/root transcript, bridge FlyClient sampling transcript/index, shielded-nullifier, consensus fork-choice, consensus PoW-admission, consensus header-preimage, consensus PoW miner-identity, native miner-identity, consensus version-policy, consensus proof-policy, consensus native tx-leaf admission, consensus receipt-root admission, consensus recursive-block admission, consensus recursive public replay, consensus recursive semantic inputs, consensus statement-anchor admission, consensus DA-root byte binding, consensus proven-batch binding, consensus aggregation V5 header admission, supply-accounting, consensus supply-chain invariant, native action-ordering, native action request projection admission, native action hash/count admission, native pending-action reload and startup/reorg semantic re-admission, native staged ciphertext reload admission, native staged proof reload admission, native canonical-state reload admission, native bridge-replay reload admission, native action-root transcript binding, native announced-block admission, native block-index reload admission, native mined-work admission, native storage-durability admission, native atomic commit manifest admission, native work-template admission, native recursive-artifact context admission, native action scope admission, native bridge action payload admission, native bridge witness backscan, native bridge witness export admission, native block-action validation, native RISC Zero release-verifier fail-closed admission, native backend review policy, native transfer action payload admission, native transfer state admission, native coinbase accounting admission, native coinbase action payload admission, native mineable action admission, native resource-budget admission, native sidecar upload admission, native sync admission and canonical row body materialization, network secure-channel key schedule, PQ Noise key schedule/signing transcript, native candidate artifact admission, native candidate artifact coupling admission, native block artifact binding admission, native block commitment admission, native block replay refinement, native tx-leaf artifact, native receipt-root, wallet note-ciphertext wire/decrypt/plaintext binding, privacy observer/native observer surface, transaction-balance, transaction note-commitment input, transaction nullifier input, transaction Merkle-path, transaction public-input shape, transaction public-input binding, transaction proof-wrapper admission, transaction proof-statement binding, and transaction statement-hash conformance vectors, and checks the formal model inventory, claims ledger, blueprint DAG, declared non-test Rust implementation bindings and call-order constraints for the critical supply/replay/import path, independent bridge reference vectors, transaction proof-manifest nested-wrapper regression, native backend review-policy coverage, native backend release-posture coverage, and native backend reference vectors. |
| `core-tests` | Runs `./scripts/check-core.sh test` for the fast shipping-path Rust suite. |
| `release-build` | Runs `./scripts/check-core.sh build` so the release native node builds cleanly. |

Operator-scenario harnesses such as `./scripts/test-node.sh two-node-restart` remain available for manual debugging, with `two-node-restart` included in the native acceptance gate.
Benchmark, simulator, and profiling harnesses such as `circuits-bench`, `wallet-bench`, `go test ./...` in `consensus/bench`, and `netbench` are also manual, not part of default CI.

All jobs operate on Ubuntu runners with Rust stable and the native build dependencies installed via `apt`. Adding new languages or toolchains to the blocking gate requires updating this table, the workflow, and `docs/CONTRIBUTING.md`.

## 7. Node, wallet, and UI operations

Follow [runbooks/miner_wallet_quickstart.md](runbooks/miner_wallet_quickstart.md) whenever you need a reproducible demo:

1. Launch the native `hegemon-node` binary with `HEGEMON_MINE=1` and `--dev` for development block times. The node exposes JSON-RPC on port 9944 and P2P on port 30333 by default. Run `make node` to build. Use `HEGEMON_SEEDS="hegemon.pauli.group:30333"` when joining the shared public fresh testnet, keep every miner on the same approved seed list to avoid forks, and keep NTP/chrony enabled because future-skewed PoW timestamps are rejected.
2. Connect the desktop app or native JSON-RPC tooling to the node RPC endpoint to view live telemetry. When using the desktop app, prefer a persistent base path (avoid `--tmp`), and set `--listen-addr 0.0.0.0:30333` only when you intend to accept IPv4 peer traffic. Expose RPC externally only on trusted networks.
   The desktop app is organized into Overview, Node, Wallet, Send, Disclosure, and Console workspaces. Its global status bar always shows the active node, wallet store, and genesis hash so operators can detect mismatches before sending or mining.
   Use `hegemon_peerGraph` to retrieve connected peer details plus reported peers (address, direction, best height/hash); `system_peers` remains empty on the PQ transport.
3. For multi-node setups, start additional nodes with the same `HEGEMON_SEEDS` list (for local testing, `HEGEMON_SEEDS=127.0.0.1:30333` for the first node endpoint).

### Security assurance workflow

- Follow `docs/SECURITY_REVIEWS.md` whenever commissioning cryptanalysis or third-party audits. Every finding recorded there must reference the code path touched plus the mitigation PR.
- `bash scripts/check_formal_core.sh` is the mandatory formal-core gate for release branches. It runs `bash scripts/check_lean_formal.sh`, generates Lean bridge, bridge checkpoint-output canonical/journal bytes, bridge long-range proof-shape, bridge header-MMR opening-shape, bridge header-MMR parent/root transcript, bridge FlyClient sampling transcript/index, shielded-nullifier, consensus fork-choice, consensus PoW-admission, consensus header-preimage, consensus PoW miner-identity, native miner-identity, consensus version-policy, consensus proof-policy, consensus native tx-leaf admission, consensus receipt-root admission, consensus recursive-block admission, consensus recursive public replay, consensus recursive semantic inputs, consensus statement-anchor admission, consensus DA-root byte binding, consensus proven-batch binding, consensus aggregation V5 header admission, supply-accounting, consensus supply-chain invariant, native action-ordering, native action request projection admission, native action hash/count admission, native pending-action reload and startup/reorg semantic re-admission, native staged ciphertext reload admission, native staged proof reload admission, native canonical-state reload admission, native bridge-replay reload admission, native action-root transcript binding, native announced-block admission, native block-index reload admission, native mined-work admission, native storage-durability admission, native atomic commit manifest admission, native work-template admission, native recursive-artifact context admission, native action scope admission, native bridge action payload admission, native bridge witness backscan, native bridge witness export admission, native block-action validation, native RISC Zero release-verifier fail-closed admission, native backend review policy, native transfer action payload admission, native transfer state admission, native coinbase accounting, native coinbase action payload admission, native mineable action admission, native resource-budget admission, native sidecar upload admission, native sync admission and canonical row body materialization, native candidate artifact admission, native candidate artifact coupling admission, native block artifact binding admission, native block commitment admission, native block replay refinement, native tx-leaf artifact, native receipt-root, wallet note-ciphertext wire/decrypt/plaintext binding, privacy observer/native observer surface, transaction-balance, transaction note-commitment input, transaction nullifier input, transaction Merkle-path, transaction public-input shape, transaction public-input binding, transaction proof-wrapper admission, transaction proof-statement binding, and transaction statement-hash vectors and verifies them against production Rust helpers or policy helpers, validates `config/formal-security-claims.json`, validates the blueprint DAG in `config/formal-security-blueprint.json`, checks declared non-test Rust implementation bindings and declared call-order constraints, checks the formal inventory, verifies independent bridge message/replay vectors, checks native backend review-policy coverage for the checked-in vector bundle, reruns the native backend reference vectors, and checks that the native backend review package remains in the explicit candidate-under-review release posture. The current binding set covers 200 implementation bindings across bridge witness backscan/export admission, resource-budget and sidecar-upload admission, native header-MMR history loading, old canonical chain loading, bridge long-range proof-shape acceptance, generic PoW admission/miner-identity/supply-claim binding, native self-contained miner-identity admission/signing, consensus PoW retarget schedule wiring, consensus version-policy import gating, consensus proof-policy, transaction note-commitment input binding, transaction nullifier input binding, transaction statement-hash receipt derivation, transaction proof-wrapper admission, transaction proof-statement binding, native tx-leaf admission, proven-batch binding, receipt-root admission, recursive-block admission, consensus recursive semantic-input propagation, consensus statement-anchor admission, consensus block-tree transition, native tx-leaf/receipt-root wire parser wiring, native codec admission, native action-request projection admission, native sync canonical row body/action-root materialization, native bridge-message extraction, native action hash/root/commitment gates, recursive-artifact context admission, candidate-artifact admission, pending-action key/hash reload plus startup/reorg semantic re-admission/quarantine and semantic duplicate rejection, live submit action-request projection/revalidation and bridge state-validation publication ordering, staged-sidecar reload and cleanup, native action-state/stream effect planning, native action-plan application admission, native wire-replay projection admission, native supply advancement, coinbase accounting, coinbase payload admission, action-scope admission, block-action ordering, bridge/transfer payload admission, transfer state admission, work-template admission, RPC unsafe-method/timestamp/block-row/wallet-archive/mining-thread/sync/mineable-action admission with dead-filter and non-preserving-map rejection, decoded block-action validation and semantic duplicate guarding, block-artifact coupling/binding and replay artifact verification, announced-block pre-PoW/body-replay ordering, announced-block metadata projection propagation, native fork-choice publication ordering, active P2P secure-channel key-schedule/frame protection, outbound sync encode-before-send binding, block replay refinement, nonwinning announced side-branch block-record persistence, mined-work/PoW mutation and atomic mined-block commit ordering, native storage-durability barrier propagation, native atomic commit manifest admission, consensus version-policy import ordering, canonical-index rebuild planning, atomic canonical reorg commit ordering, startup block-index/canonical-state/bridge-replay open-path propagation and state-publication ordering, startup canonical-index repair commit wiring, RISC Zero inbound verifier propagation, and inbound bridge receipt-output admission propagation, plus 142 caller-order constraints covering 371 callee-precedence edges, 158 result obligations, and 128 dominance constraints covering 339 dominance edges. The claims ledger now contains 115 theorem-backed claims with 1509 named Lean theorem declarations, 105 production-eligible claims, and 43 explicit residual risks; the blueprint contains 115 nodes, 480 dependency edges, and 446 falsification cases. Every `lean_theorem` claim must list explicit fully qualified `lean_theorems`, and the formal-core checker resolves each symbol against a non-comment declaration in a non-generator Lean evidence file so generated vectors, prose, or theorem-looking text inside Lean comments cannot back an exported theorem claim. The Lean proof gate also queries `#print axioms` for every claimed theorem and requires every axiom dependency to be either an explicitly allowed Lean kernel axiom or a capped temporary family in `config/lean-axiom-waivers.json`; no temporary local or synthetic axiom dependencies are permitted in theorem-backed claims. The blueprint DAG is a JSON review map for that ledger: it makes dependencies, target review, implementation bindings, cheap falsification cases, Lean theorem evidence, axiom policy, and scope boundaries machine-checkable. A declared implementation binding means the checker parses the referenced Rust source and requires the named callee plus every listed caller to exist outside `cfg`-gated non-production code, requires every matching caller body to contain an actual call expression for that callee, rejects required caller bodies that locally shadow the callee through a `let`, `for`, nested `fn`, `use`, or closure-parameter binding before call scanning, and rejects arbitrary receiver/path calls for bare bound callees except same-impl `self.callee(...)` or `Self::callee(...)` when that method exists outside tests. Caller selectors may be bare Rust function names or method-qualified `TypeName::method_name` selectors, with qualified selectors matching methods inside inherent impls and trait impls for the named type; bare selectors match every same-named non-test function or method and every match must satisfy the binding. Ordered successor selectors may be bare identifiers or conservative path/member selectors such as `RwLock::new` or `self.persist_block`, with qualified selectors requiring the exact receiver/type path immediately before the call. Bindings can require propagated fallible results with `result_obligation = "must_propagate_result"` using `?` on the direct helper result, including turbofish calls, or an allowed simple `.map(...)`/`.map_err(...)`/`.context(...)`/`.with_context(...)` chain, an explicit `return helper(...).map_err(...);`, or an outer function-body tail return; error-swallowing combinators do not satisfy propagation. Explicit fail-closed handling with `result_obligation = "must_check_result_fail_closed"` recognizes only branches that hit a top-level terminal return, including direct or assignment-bound `match` Err arms and immediately bound `if let Err` checks; direct loop-skip `if let Err(_) = helper(...) { ... continue; }` checks or direct `match helper(...) { Err(_) => ... continue, ... }` arms can require `result_obligation = "must_check_result_loop_skip_fail_closed"`; iterator filters can require `result_obligation = "must_filter_ok_result"` so direct `.is_ok()` is the returned predicate and the filtered iterator feeds a terminal consumer whose result is returned, explicitly returned, or bound to a non-underscore local that is used later in the surrounding block, and arbitrary `.map(...)` chains are not treated as preserving the filtered set; tuple wrappers can require `result_obligation = "must_return_tuple_result_component"` so the second result component is tail-returned; native mining-template supply fallback can require `result_obligation = "must_reset_work_template_on_err"` so rejected pending-action supply advancement resets to an empty parent-root template before header construction; boolean predicates can additionally require `result_obligation = "must_guard_false_fail_closed"` for `if !helper(...) { return ... }` guards that top-level terminal-return before successor work; native replay expected-supply reconstruction can require `must_match_some_or_return_supply_delta_invalid`; generic PoW checked supply claims can require `must_match_some_and_compare_supply_claim`. Every call site for the bound helper in the required caller must satisfy the declared obligation. When a binding declares call-order constraints, the checker requires the Lean-conformance helper call to occur before every declared successor call in the non-test caller body; constraints marked `must_dominate_successors` additionally require the helper call to sit in an earlier statement in the same Rust block or an earlier ancestor-block statement than every successor call, so sibling-branch call references do not satisfy mutation/persistence ordering gates. The current blueprint uses 158 result obligations, 128 dominance constraints covering 339 dominance edges, and 142 call-order constraints covering 371 order edges.
- Current formal-core metadata now includes the concrete materialized consensus DA-blob refinement, mined-block commit-publication surface, and split verifier-soundness boundary: the claims ledger contains 115 theorem-backed claims with 1509 named Lean theorem declarations, 105 production-eligible claims, and 43 explicit residual risks; the blueprint contains 115 nodes, 480 dependency edges, 446 falsification cases, and the same 200 implementation bindings / 142 order constraints / 158 result obligations / 128 dominance constraints.
- `formal/lean` is the pinned Lean 4 project for machine-checked Hegemon kernels. The detailed bullets below name the proved predicates and generated conformance vectors; passing `formal-core` is release-gate evidence for those narrow executable rules, not a proof of hash security, proof-system soundness, privacy, network finality, or complete native-node equivalence.
- The consensus PoW admission kernel proves checked u64 next-height arithmetic, compact-target rejection, strict timestamp policy, hash-threshold rejection, and fixed-width Work48 cumulative-work behavior with `Hegemon.Consensus.checkedNextU64_rejects_max`, `Hegemon.Consensus.checkedNextU64_accepts_predecessor`, `Hegemon.Consensus.powAdmission_rejects_height_overflow`, and the companion compact-target, timestamp, work-addition, and valid-admission theorems, including `Hegemon.Consensus.compactTarget_rejects_shifted_zero_target` for nonzero-mantissa compact bits that decode to target zero. The same Lean module now pins the executable retarget target-adjustment clamp with `Hegemon.Consensus.retargetConstants_match_consensus`, `Hegemon.Consensus.adjustedTimespan_clamps_fast_blocks`, `Hegemon.Consensus.adjustedTimespan_clamps_slow_blocks`, and the companion `retargetTarget_*` theorems; compact retarget re-encoding with `Hegemon.Consensus.targetToCompact_easy_roundtrip`, `Hegemon.Consensus.targetToCompact_roundtrip_easy_target`, `Hegemon.Consensus.retargetBits_expected_timespan_keeps_bits`, and `Hegemon.Consensus.retargetBits_rejects_invalid_previous_bits`; and retarget-boundary scheduling/history with `Hegemon.Consensus.retargetAnchorSteps_boundary_requires_window`, `Hegemon.Consensus.expectedPowBitsSchedule_missing_history_rejects`, `Hegemon.Consensus.expectedPowBitsSchedule_expected_timespan_keeps_bits`, and the companion scheduler theorems. `gen_pow_vectors` emits examples that Rust `evaluate_pow_admission`, `consensus::reward::adjusted_timespan`, `consensus::reward::retarget_target`, `target_to_compact`, `pow_retarget_anchor_steps`, `evaluate_pow_bits_schedule`, and the light-client Work48 helpers must match; focused regressions reject u64 height overflow at both generic consensus admission and `consensus-light-client::verify_pow_header`, and reject generic consensus cumulative work that would exceed the 48-byte work domain. This does not prove SHA-256 implementation equivalence, timestamp honesty, retarget economics, network orphan policy, long-range finality, or complete light-client soundness.
- The consensus proof-policy kernel proves the product-path block proof-payload shape with `Hegemon.Consensus.empty_clean_accepts`, `Hegemon.Consensus.nonempty_requires_tx_artifacts`, `Hegemon.Consensus.nonempty_rejects_inline_required`, `Hegemon.Consensus.nonempty_requires_proven_batch`, `Hegemon.Consensus.recursive_rejects_commitment_proof_bytes`, `Hegemon.Consensus.recursive_requires_block_artifact`, and companion theorem rows. `gen_proof_policy_vectors` emits examples that Rust `evaluate_block_proof_policy` must match, and the blueprint now requires `ParallelProofVerifier::verify_block_with_backend` to fail closed on that helper before transaction-artifact claim derivation, commitment proof payload verification, proven-batch binding, block-artifact verification, recursive-block artifact verification, or tree transition. Skipped edge: `HashVerifier::verify_block_with_backend` does not call this helper and is not the self-contained product verifier, so binding it would be false metadata.
- The native tx-leaf admission kernel proves the cheap consensus envelope/profile/size/hash/cache table before native backend verification with `Hegemon.Consensus.NativeTxLeafAdmission.accepts_iff_admission_preconditions`, `Hegemon.Consensus.NativeTxLeafAdmission.valid_uncached_requires_backend_verification`, `Hegemon.Consensus.NativeTxLeafAdmission.valid_cache_hit_accepts`, and companion rejection theorems, including cache receipt and public transaction-view mismatch rejection. `gen_native_tx_leaf_admission_vectors` emits examples that Rust `evaluate_native_tx_leaf_admission` must match, and the focused cache replay regression ensures a cached native tx-leaf record cannot be reused for a different transaction view. The blueprint requires result propagation and dominance in `verify_native_tx_leaf_artifact_record` before backend verification, statement binding, or decode, and also requires `NativeTxLeafVerifier::verify_tx_artifact` to tail-propagate `verify_native_tx_leaf_artifact_record(...).map(...)` at the product entry point. Skipped edge: `NativeTxLeafVerifier::verify_block_artifact` is not an implemented method on this verifier.
- The receipt-root admission kernel proves the cheap consensus payload/envelope/size/count/statement/metadata tables around native receipt-root verification with `Hegemon.Consensus.ReceiptRootAdmission.payload_accepts_iff_preconditions`, `Hegemon.Consensus.ReceiptRootAdmission.artifact_accepts_iff_preconditions`, `Hegemon.Consensus.ReceiptRootAdmission.statement_accepts_iff_preconditions`, and `Hegemon.Consensus.ReceiptRootAdmission.verified_metadata_accepts_iff_preconditions`, plus companion rejection theorems. `gen_receipt_root_admission_vectors` emits examples that the production receipt-root admission helpers in `consensus/src/proof.rs` must match. The blueprint binds payload admission in `ParallelProofVerifier::verify_block_with_backend` before `verify_block_artifact`, and binds artifact, statement, and metadata admission in `ReceiptRootVerifier::verify_block_artifact` with propagated results and dominance before native tx-leaf record verification and backend receipt-root verification.
- The native sidecar upload admission kernel proves DA staging request-count caps, staged sidecar capacity with replacement semantics, proof binding-hash metadata admission, decoded proof byte caps, and decoded proof binding-hash equality with the upload key with `Hegemon.Native.SidecarUploadAdmission` theorems, including `Hegemon.Native.SidecarUploadAdmission.proof_binding_hash_mismatch_rejects`. `gen_sidecar_upload_admission_vectors` emits examples, including `proof_binding_hash_mismatch`, that Rust sidecar upload helpers used by `da_submitCiphertexts` and `da_submitProofs` must match. This does not prove RPC authentication, unsafe RPC exposure safety, base64/hex parser correctness, ciphertext hash security or implementation equivalence, sled durability, DA sidecar availability, native tx-leaf proof soundness, or complete native-node equivalence.
- The pre-heavy-work resource-bound surface is a Lean composition over accepted `ResourceBudgetAdmission`, `RpcAdmission`, `SidecarUploadAdmission`, `MineableActionAdmission`, `ActionRequestProjectionAdmission`, `TransferActionPayloadAdmission`, `CandidateArtifactAdmission`, and tx-leaf artifact parser inputs. `Hegemon.Native.PreHeavyWorkResourceBoundSurface.accepted_preheavy_resource_bound_surface_exposes_bounds` packages pending-action and staged-proof byte caps, timestamp row caps, hex/base64 byte caps, JSON-RPC batch caps, sidecar request/capacity/proof preconditions, and mineable-action preconditions into one review surface before expensive proof or block-template work. `action_request_projection_accepts_implies_preheavy_bounds` derives strict submit-action JSON, empty kernel-envelope, supported route, nullifier, public-args, and exact route-payload predicates from accepted action-request projection before heavy work. `accepted_preheavy_public_input_parser_admission_bounds_verification_paths` adds those action-request facts, transfer proof/ciphertext caps, recursive candidate tx/proof caps, and tx-leaf byte-shape facts before heavy verification, with parser correctness and benchmark caps carried as explicit assumptions. It adds no runtime path and inherits production conformance from the underlying gates; it does not prove JSON parser correctness, RPC authentication, unsafe-method exposure safety, DA availability, sled durability, proof-system soundness, or complete native-node equivalence.
- The native staged-ciphertext reload kernel proves the startup per-entry admission/drop table with `Hegemon.Native.StagedCiphertextReload.accepts_iff_staged_ciphertext_reload_preconditions` and companion rejection-precedence theorems. `gen_staged_ciphertext_reload_vectors` emits examples that Rust `evaluate_native_staged_ciphertext_reload` must match before `load_staged_sizes_with_limits` restores proposer-local sidecar size metadata. This does not prove sled atomicity, filesystem durability, I/O error behavior, BLAKE3 ciphertext-hash security or implementation equivalence, DA sidecar availability, native tx-leaf proof soundness, or complete native-node equivalence.
- The native staged-proof reload kernel proves the startup per-entry admission/drop table with `Hegemon.Native.StagedProofReload.accepts_iff_staged_proof_reload_preconditions` and companion rejection-precedence theorems. `gen_staged_proof_reload_vectors` emits examples that Rust `evaluate_native_staged_proof_reload` must match before `load_staged_proofs_with_limits` restores proposer-local proof sidecars. This does not prove sled atomicity, filesystem durability, I/O error behavior, binding-hash security or implementation equivalence, proof byte parsing, DA sidecar availability, native tx-leaf proof soundness, or complete native-node equivalence.
- The native sync admission kernel proves response-range, missing-request, zero-cap, saturating-edge, and inbound response-count behavior with `Hegemon.Native.SyncAdmission` theorems. `gen_sync_admission_vectors` emits examples that Rust sync helpers used by response serving, catch-up requests, and inbound response rejection must match. Production bindings additionally require non-genesis canonical rows served over sync to decode native action bodies and verify the decoded action root before response publication. `Hegemon.Native.SyncBlockReplayPublication.accepted_sync_block_response_binds_raw_canonical_publication` composes accepted sync decode/count admission with exact block-action decode and raw canonical publication so synced raw block batches carry replayed supply, leaf-cursor, commitment-root, nullifier, and bridge replay-key facts. This does not prove SCALE codec correctness, arbitrary sync/block parser internals, PQ Noise transport security, full PoW/header validity beyond the metadata projection helper, fork-choice convergence, peer honesty, network liveness, storage durability, or complete native-node equivalence.
- The native mineable-action admission kernel proves the block-template selection gate with `Hegemon.Native.MineableActionAdmission.accepts_iff_mineable_preconditions`, covering selected candidate artifacts, unselected candidate rejection, sidecar staged ciphertext metadata presence, staged size agreement, and rejection precedence. `gen_mineable_action_admission_vectors` emits examples that Rust candidate selection helpers used by `prepare_work` and mined-block import replay must match, and the blueprint now requires `select_mineable_actions` to use `evaluate_native_mineable_action_admission(...).is_ok()` as the direct iterator `filter` predicate before inclusion. This does not prove ciphertext hash security or implementation equivalence, sled/BTreeMap consistency, DA durability, recursive proof soundness, tx-leaf proof soundness, candidate selection fairness, or complete native-node equivalence.
- The native mined-work admission kernel proves the local mined-block freshness gate with `Hegemon.Native.MinedWorkAdmission.accepts_iff_mined_work_preconditions`, covering current-best parent-hash agreement, checked next-height arithmetic, u64 height overflow rejection, and rejection precedence. `Hegemon.Native.MinedBlockCommitPublication.accepted_mined_block_commit_publication_facts` now composes accepted mined-work freshness, native block-commitment admission, and atomic mined-block commit-manifest admission into one local publication surface exposing parent/height preconditions, header/body/supply commitment preconditions, mined-block manifest kind, and atomic manifest preconditions. `gen_mined_work_admission_vectors` emits examples that Rust `evaluate_native_mined_work_admission` must match before pending-action replay, body commitment admission, supply accounting, and PoW metadata verification. The blueprint also binds `verify_native_pow_meta` inside `import_mined_block` and requires it to occur before `commit_mined_block_atomically`, `publish_mined_state`, and `broadcast_block_announce`; `commit_mined_block_atomically` must occur before state publication and broadcast. `mined_invalid_pow_does_not_mutate_pending_state` keeps invalid local seals from partially mutating pending, commitment, or supply state, and `mined_action_block_commit_reloads_canonical_sled_state` checks that a mined action block reloads the best header, height index, commitment state, archived ciphertext, and empty pending-action tree from sled after reopening. Mined import now builds the next in-memory state on a clone, commits the block record, height index, best pointer, canonical state/replay/ciphertext indexes, and pending-action removals in one sled transaction, and only then publishes that state to the running node. Nonwinning announced side-branch block-record reload is covered separately by the block replay-refinement implementation-binding gate. This does not prove work-template construction, action validity, body replay, supply accounting, PoW hash-threshold validity beyond the production verifier call, sled transaction implementation correctness, filesystem/fsync durability, fork-choice liveness, or complete native-node equivalence.
- The native storage-durability admission kernel proves the explicit database durability barrier with `Hegemon.Native.StorageDurabilityAdmission.accepts_iff_storage_durability_preconditions`, covering transaction/write acceptance, explicit flush acceptance, flush-failure rejection, and transaction-rejection-before-flush-failure precedence. `gen_storage_durability_admission_vectors` emits mined-block, canonical-reorg, canonical-index-repair, noncanonical-record, pending-action, ciphertext-sidecar, proof-sidecar, genesis-bootstrap, genesis-marker-repair, startup-staged-ciphertext-repair, startup-staged-proof-repair, startup-pending-action-repair, transaction-rejected, and flush-failed examples that Rust `evaluate_native_storage_durability_admission` must match. The blueprint binds initialized-node paths through `flush_native_durability_barrier` and startup paths through `flush_native_db_durability_barrier`, requiring mined import, canonical reorg, canonical-index repair, nonwinning side-branch persistence, pending-action staging, sidecar staging, startup staged-sidecar repair, startup pending-action quarantine cleanup, and genesis bootstrap/repair to propagate the barrier before publication, success, or open completion. This proves the explicit barrier and wiring; it does not prove sled transaction implementation correctness, operating-system fsync semantics, disk firmware behavior, crash-consistency below sled, fork-choice liveness, or complete native-node equivalence.
- The native atomic-commit manifest admission kernel proves the declared row-family manifest gate with `Hegemon.Native.AtomicCommitManifestAdmission.accepts_iff_atomic_commit_manifest_preconditions`, covering mined-block, canonical-reorg, canonical-index-repair, and noncanonical block-record commit kinds. `gen_atomic_commit_manifest_admission_vectors` emits valid manifests plus mined plan-length, block-record, height-index, best-pointer, canonical-index-clear, pending-tree-clear, pending action, commitment, nullifier, bridge replay, ciphertext index/archive, and staged-ciphertext removal mismatch examples that Rust `evaluate_native_atomic_commit_manifest_admission` must match. The blueprint requires that gate to propagate before noncanonical block-record persistence and before sled transaction execution in the mined/reorg/repair commit helpers. This proves the manifest decision table and wiring; it does not prove sled transaction implementation correctness, operating-system fsync semantics, row byte serialization beyond existing codec gates, fork-choice liveness, or complete native-node equivalence.
- The native work-template admission kernel proves the mining-template emission gate with `Hegemon.Native.WorkTemplateAdmission.accepts_iff_work_template_preconditions`, covering checked next-height arithmetic, u64 height overflow rejection, checked Work48 cumulative-work advancement, and rejection precedence. `gen_work_template_admission_vectors` emits examples that Rust `evaluate_native_work_template_admission` must match before `prepare_work` constructs a header preimage, and the blueprint binds auto-coinbase assembly before root preview, supply advancement, bridge-message extraction, or header hashing. This does not prove pending-action preview correctness, action validity, header hash security, PoW seal search/liveness, body replay, supply accounting, storage durability, fork-choice liveness, or complete native-node equivalence.
- The native recursive-artifact context admission kernel proves the proof-verifier context height gate with `Hegemon.Native.RecursiveArtifactContextAdmission.accepts_iff_recursive_artifact_context_preconditions`, covering checked next-height arithmetic before native recursive artifact verification constructs the consensus block header passed to the backend verifier. `gen_recursive_artifact_context_admission_vectors` emits examples that Rust `evaluate_native_recursive_artifact_context_admission` must match. This does not prove tx-leaf proof soundness, recursive proof cryptographic soundness, DA-root binding, statement-commitment hash security, body replay, storage durability, fork-choice liveness, or complete native-node equivalence.
- The native action-root transcript kernel proves the block `action_root` preimage grammar with `Hegemon.Native.ActionRootTranscript.action_root_domain_hex`, `Hegemon.Native.ActionRootTranscript.action_root_count_is_little_endian`, `Hegemon.Native.ActionRootTranscript.action_root_order_binds_hashes`, and companion length/byte theorems. `gen_action_root_transcript_vectors` emits examples that the Rust `action_root_transcript_preimage` helper used before BLAKE3 hashing must match. This does not prove BLAKE3 action-root collision resistance, pending-action-hash derivation, SCALE encoding implementation equivalence, full action payload validation, or complete native-node equivalence.
- The native action-state effect kernel proves the single-action mutation precondition table with `Hegemon.Native.ActionStateEffect.accepts_iff_state_effect_preconditions`, covering canonical ciphertext/commitment count agreement, checked u64 commitment leaf-count advancement, zero/duplicate nullifier rejection, inbound bridge replay duplicate rejection, and rejection precedence. `gen_action_state_effect_vectors` emits examples that Rust `evaluate_native_action_state_effect` must match.
- The native action-stream effect kernel proves representative ordered-list replay facts with `Hegemon.Native.ActionStreamEffect.accepts_iff_stream_preconditions`, `valid_two_action_stream_accepts`, `cross_action_duplicate_nullifier_rejects`, `within_action_duplicate_nullifier_rejects`, `cross_action_bridge_replay_duplicate_rejects`, and companion prior-state, overflow, and precedence theorems. `gen_action_stream_effect_vectors` emits examples that Rust `evaluate_native_action_stream_effect` must match, and the native memory replay, pending-action planning, and canonical-index rebuild paths now call that stream helper before deriving commitment/message roots or mutating commitment, nullifier, bridge-replay, action, or ciphertext-index state. Winning reorg canonical-index rebuilds and canonical block records are committed through one sled transaction before `publish_reorganized_state`; startup canonical-index repair now commits the rebuilt canonical commitment/nullifier/bridge replay/ciphertext index/archive rows through one sled transaction before open returns. Nonwinning announced side-branch block-record reload is covered separately by the block replay-refinement implementation-binding gate. This does not prove sled transaction implementation correctness, filesystem/fsync durability, commitment-tree hash security, SCALE decoding implementation equivalence, full action payload validation, tx-leaf proof soundness, or complete native-node equivalence.
- The native announced-block admission kernel proves pre-PoW native header admission with `Hegemon.Native.AnnouncedBlockAdmission.accepts_iff_announced_block_preconditions`, covering checked next-height arithmetic, u64 height overflow rejection, parent-hash agreement, strict timestamp advancement, future-skew bounds, hash/work-hash equality, and rejection precedence. `gen_announced_block_admission_vectors` emits examples that Rust `evaluate_native_announced_block_admission` must match before PoW metadata verification and body commitment replay. Blueprint bindings require that helper's fallible result to propagate in `validate_announced_block` before `verify_native_pow_meta`, and require `validate_announced_block` to propagate in `import_announced_block` before parent replay, action decoding, commitment replay, payload/artifact validation, side-branch persistence, or winning reorg. This does not prove PoW hash-threshold validity, light-client header verification, wall-clock correctness, fork-choice liveness, action payload validation, or complete native-node equivalence.
- The native block-index reload kernel proves startup canonical index admission with `Hegemon.Native.BlockIndexReload.accepts_iff_block_index_reload_preconditions`, covering chain reconstruction success, nonempty chain, computed-genesis equality, best metadata equality, canonical block metadata checks, exact height-index checks, missing-height rejection, genesis-marker validity, missing-marker repair, and rejection precedence. `gen_block_index_reload_vectors` emits examples that Rust `evaluate_native_block_index_reload` must match before `NativeNode::open` trusts persisted canonical block indexes, and the blueprint requires `validate_loaded_block_indexes` to propagate in `NativeNode::open` before subsequent startup reload helpers and before `RwLock::new` publishes in-memory state. This does not prove sled atomicity, filesystem durability, bincode implementation correctness, hash collision resistance, full historical block replay, or complete native-node equivalence.
- The native canonical-state reload kernel proves startup commitment/nullifier admission with `Hegemon.Native.CanonicalStateReload.accepts_iff_canonical_state_reload_preconditions`, covering well-formed nullifier keys/markers, well-formed commitment keys/values, contiguous commitment indexes, commitment-tree rebuild success, commitment root equality with the best header, nullifier root equality with the best header, and rejection precedence. `gen_canonical_state_reload_vectors` emits examples that Rust `evaluate_native_canonical_state_reload` must match before `NativeNode::open` trusts persisted canonical shielded state, and the blueprint requires `validate_loaded_canonical_state` to propagate in `NativeNode::open` before bridge-replay and staged-sidecar reloads. This does not prove sled atomicity, filesystem durability, commitment-tree hash security, nullifier-root hash security, full historical block replay, or complete native-node equivalence.
- The native bridge-replay reload kernel proves startup inbound bridge replay admission with `Hegemon.Native.BridgeReplayReload.accepts_iff_bridge_replay_reload_preconditions`, covering well-formed replay keys/markers, unique replay-derived canonical history, missing/extra loaded consumed replay-key rejection, and rejection precedence. `gen_bridge_replay_reload_vectors` emits examples that Rust `evaluate_native_bridge_replay_reload` must match before `NativeNode::open` trusts persisted inbound bridge replay state, and the blueprint requires `validate_loaded_bridge_replay_state` to propagate in `NativeNode::open` before staged-sidecar reloads. This does not prove sled atomicity, filesystem durability, BLAKE3 replay-key derivation, SCALE action decoding correctness, bridge receipt soundness, full historical block replay, or complete native-node equivalence.
- The native transfer-state admission kernel proves the post-payload transfer state table with `Hegemon.Native.TransferStateAdmission.accepts_iff_state_preconditions`, covering known anchors, zero/spent/duplicate/pending nullifier rejection, nonzero commitments, sidecar ciphertext availability, staged ciphertext size presence, staged size agreement, and rejection precedence. `gen_transfer_state_admission_vectors` emits examples that Rust `evaluate_native_transfer_state_admission` must match. This does not prove commitment-tree hash security, BTreeSet/BTreeMap implementation correctness, ciphertext hash security or implementation equivalence, DA durability, tx-leaf proof soundness, recursive proof soundness, or complete native-node equivalence.
- The native block-action validation kernel proves the composed decoded-action import table with `Hegemon.Native.BlockActionValidation.accepts_iff_block_action_validation_preconditions`, covering action hash/count admission, route/scope admission, payload-before-replay/state precedence, inbound bridge replay duplicate rejection, transfer ordering, transfer order-before-state precedence, and transfer state rejection. `gen_block_action_validation_vectors` emits examples that Rust production helpers used by `validate_block_actions_locked` must match. This does not prove SCALE decoding implementation equivalence, pending-action hash security, transfer-key hash derivation, bridge payload-hash security, tx-leaf proof soundness, recursive proof soundness, storage durability, or complete native-node equivalence.
- The recursive-block admission kernel proves the cheap consensus envelope/profile/decode/header/count/statement/public-replay table before heavy recursive proof verification with `Hegemon.Consensus.RecursiveBlockAdmission.artifact_accepts_iff_preconditions`; companion accept/reject and precedence theorems pin representative rows. It also proves `Hegemon.Consensus.RecursiveBlockAdmission.direct_v1_requires_semantic_replay` and `Hegemon.Consensus.RecursiveBlockAdmission.direct_v2_requires_semantic_replay`, so the generic recursive-block registry verifier fails closed unless the product path supplies verified-record semantic replay inputs. `gen_recursive_block_admission_vectors` emits examples that Rust `evaluate_recursive_block_artifact_admission` and the direct `RecursiveBlockVerifier` rejection must match. The blueprint requires the artifact-admission helper to dominate `verify_block_recursive_v1` and `verify_block_recursive_v2`, and requires `ParallelProofVerifier::verify_block_with_backend` to propagate `verify_recursive_block_artifact_against_verified_records` before tree transition. Skipped edge: `RecursiveBlockVerifier::verify_block_artifact` is a direct fail-closed registry stub with no backend successor to order against.
- The recursive public replay kernel proves v1/v2 tx-index admission and semantic-field propagation with `Hegemon.Consensus.RecursivePublicReplay.accepts_iff_contiguous`, `Hegemon.Consensus.RecursivePublicReplay.valid_v1_public_fields_match_semantic`, `Hegemon.Consensus.RecursivePublicReplay.valid_v2_public_fields_match_semantic`, `Hegemon.Consensus.RecursivePublicReplay.v1_public_byte_length`, and `Hegemon.Consensus.RecursivePublicReplay.v2_public_byte_length`; companion rejection theorems pin gap, duplicate, and decreasing-order cases. `gen_recursive_public_replay_vectors` emits examples that Rust `public_replay_v1` and `public_replay_v2` must match.
- The recursive semantic-input kernel proves nonempty/nullifier/DA admission, rejection precedence, and source binding for expected statement commitment, parent/applied commitment-tree roots, kernel roots, nullifier root, DA root, header message root, and recursive tree-state commitments with `Hegemon.Consensus.RecursiveSemanticInputs.semantic_accepts_iff_preconditions`, `Hegemon.Consensus.RecursiveSemanticInputs.valid_semantic_fields_match_sources`, and companion rejection theorems. `gen_recursive_semantic_input_vectors` emits examples that Rust `recursive_block_semantic_inputs_from_block` must match.
- The DA-root byte-binding kernel proves transaction ciphertext blob serialization, DA-param rejection, data/parity/total shard-count arithmetic, `da-leaf`/`da-node` preimage domains, child-order binding, and even/odd Merkle step orientation with `Hegemon.Consensus.DaRoot.sample_blob_hex`, `Hegemon.Consensus.DaRoot.node_preimage_order_binds_children`, `Hegemon.Consensus.DaRoot.shard_count_max_accepts`, and companion rejection/orientation theorems. `gen_da_root_vectors` emits examples that Rust `consensus::build_da_blob` and `state-da` shard/preimage helpers must match.
- The proven-batch binding kernel proves the complete executable acceptance predicate for route compatibility, tx-count binding, statement-commitment binding, DA-root binding, nonzero DA chunks, block-artifact envelope kind/profile agreement, and recursive-block receipt-root exclusion with `Hegemon.Consensus.ProvenBatchBinding.accepts_iff_binding_preconditions`; companion accept/reject theorems pin representative rows. `gen_proven_batch_binding_vectors` emits examples that Rust `evaluate_proven_batch_binding` must match, and the blueprint now requires `ParallelProofVerifier::verify_block_with_backend` to propagate `validate_proven_batch_binding` before block-artifact verification, recursive-block artifact verification, or tree transition.
- The supply-accounting kernel proves checked supply-digest increase/decrease, underflow/overflow rejection, no-coinbase native no-op behavior, and checked native coinbase advance with `Hegemon.Consensus.increaseSupplyDigest_ok`, `Hegemon.Consensus.increaseSupplyDigest_rejects_overflow`, `Hegemon.Consensus.decreaseSupplyDigest_ok`, `Hegemon.Consensus.decreaseSupplyDigest_rejects_underflow`, `Hegemon.Consensus.nativeSupplyDelta_without_coinbase`, `Hegemon.Consensus.advanceNativeSupplyDigest_checked`, and `Hegemon.Consensus.advanceNativeSupplyDigest_rejects_supply_overflow`. `gen_supply_vectors` emits examples that Rust `CoinbaseData::net_native_delta`, `consensus::reward::update_supply_digest`, and native checked supply helpers must match. The blueprint now requires mined-block import to propagate checked supply advancement before replay, validation, PoW verification, commit, publication, or broadcast, requires mining-template construction to reset to an empty parent-root template before root/message/header construction if pending-action supply advancement rejects, and requires native replay expected-supply reconstruction to return `SupplyDeltaInvalid` before block commitment admission if checked reconstruction fails.
- The consensus supply-chain invariant kernel proves accepted claimed supply steps replay to the same final value as the executable checked-delta sequence with `Hegemon.Consensus.SupplyInvariant.validated_chain_matches_expected_deltas`, plus concrete counterfeit, underflow, and overflow rejection theorems. `gen_supply_invariant_vectors` emits examples that Rust `consensus::reward::validate_supply_transition`, `expected_supply_after_transition`, and the PoW header `supply_digest` check must match. The generic PoW path calls the checked transition through `expected_pow_supply_after_transition`, and the blueprint requires fail-closed `None` handling plus an immediate comparison against `block.header.supply_digest` before PoW admission, proof verification, or node insertion. This does not prove transaction proof soundness, privacy, hash implementation equivalence, monetary policy economics beyond the checked transition helper, or complete native-node equivalence.
- The native candidate-artifact coupling admission kernel proves the block-level rule that zero shielded transfers require zero decoded candidate artifacts and non-empty shielded blocks require exactly one tx-count-matching candidate artifact with `Hegemon.Native.CandidateArtifactCouplingAdmission.accepts_iff_coupling_preconditions` and companion rejection/precedence theorems. `gen_candidate_artifact_coupling_admission_vectors` emits examples that Rust `evaluate_native_candidate_artifact_coupling_admission` must match before recursive artifact verification.
- The native block-artifact binding admission kernel proves deterministic equality gates after coupling and decoding: tx-leaf/action nullifier, commitment, ciphertext-hash, input/output active-count, version, fee, stablecoin public payload, balance-tag projection, receipt statement-hash, public-input digest, proof digest/backend-profile, and ciphertext payload-hash agreement, plus candidate DA-root, tx statement-commitment, and verified recursive state-root agreement with `Hegemon.Native.BlockArtifactBindingAdmission.tx_leaf_action_accepts_iff_preconditions` and `Hegemon.Native.BlockArtifactBindingAdmission.candidate_artifact_binding_accepts_iff_preconditions`. `Hegemon.Native.TxLeafCanonicalSurface` composes the accepted tx-leaf/action binding gate with the canonical deployed transaction verifier surface, assumption-free exposing statement preimage success/length, proof binding-message success, public-input binding validity, proof-wrapper preconditions/surface facts, and native receipt/public-input/proof/backend/ciphertext-payload equality gates. The stronger `native_tx_leaf_binding_and_canonical_surface_full_statement_artifact_facts` theorem now packages that assumption-free surface with public-shape validity, core root/fee/value-balance/balance-slot/stablecoin binding, full nullifier/commitment/ciphertext vector binding, input/output vector binding, value-balance binding, stablecoin payload binding, tx-leaf/action preconditions, and the complete tx-leaf equality facts before any deployed-verifier soundness assumption is used. `native_tx_leaf_full_statement_artifact_output_slot_full_binding` then packages selected output rows with output-slot facts, statement/proof-binding output rows, wrapper/public/statement facts, native output equality gates, and native artifact digest/backend gates. With the explicit deployed-verifier soundness assumption, the boundary derives the accepted transaction relation and authorized asset-delta values while exposing field-level native tx-leaf binding facts. It now also packages the native equality gate, canonical statement/proof facts, canonical deployed-verifier facts, native/per-asset authorized-delta projections, total input-slot statement/proof-binding facts, active input no-theft facts, selected output-slot full-binding facts, proof-keyed transfer payload full-binding facts, wrapper surface facts, root/fee/balance-slot/stablecoin identity bindings, spend/balance exposure, authorized asset delta, and receipt/public-input/proof/backend equality gates into implementation-equivalence theorems, while `Hegemon.Transaction.ProofSystemBoundary.canonical_boundary_facts_output_slot_bound_to_statement`, `deployed_soundness_canonical_surface_input_slot_boundary_facts`, and `deployed_soundness_canonical_surface_output_slot_boundary_facts` expose output-slot and direct input/output boundary packages from the canonical boundary. `Hegemon.Native.TxLeafCanonicalSurface.proof_keyed_transfer_payload_active_input_no_theft_full_binding` keeps the active spend facts, payload binding-hash/proof-binding-hash/fee agreement, public-input binding, root/anchor binding, statement/proof nullifier-slot alignment, native fee/proof/backend/ciphertext-payload equality gates, and field-level tx-leaf binding facts together for future verifier/AIR refinement. `Hegemon.Native.TxLeafCanonicalSurface.proof_keyed_transfer_payload_input_slot_authorization_full_binding` extends that package from active no-theft to total input-slot authorization, so inactive padding slots keep zero-nullifier evidence under the same payload, wrapper, root, statement/proof, and native tx-leaf gates. `Hegemon.Privacy.NativeObserverSurface` then composes native output-slot binding with the valid observer-chain surface, proving that statement-bound output commitments/ciphertext hashes reach observer ciphertext summary format/count facts, active native output slots force nonempty observer ciphertext bytes/summaries, active native output slots have in-bounds public active-output ranks for those observer lists, active ranks select public observer wire rows parsed to the same chain-format summaries, selected active rows expose direct public-shape, canonical-statement, and proof-binding commitment/ciphertext-hash vector indices, byte-bounded selected observer rows have the fixed production chain ciphertext wire length, selected active output ciphertext boundary facts carry projected DA bytes plus the native ciphertext-hash, ciphertext-payload-hash, and output-count equality gates, `native_tx_leaf_active_output_ciphertext_boundary_binds_projected_da_hash` binds those projected DA bytes to the public ciphertext-hash row through an explicit hash-match predicate, and same-chain-wire worlds preserve allowed leakage under the same explicit verifier assumption. The current observer theorem does not prove public ciphertext-hash equality/security for selected wire bytes without that explicit predicate. `gen_block_artifact_binding_admission_vectors` emits examples, including `stablecoin_payload_mismatch`, that Rust `evaluate_native_tx_leaf_action_binding_admission` and `evaluate_native_candidate_artifact_binding_admission` must match before native block artifact effects are accepted. Mined import, announced import, and canonical replay all call the artifact verifier before commit/persistence/reorg publication or replay memory application; `reorg_replay_rechecks_historical_side_branch_artifacts_before_publish` covers a durable side-branch replay rejection.
- The native block replay-refinement kernel proves the composed executable order of ordered action-stream effects, checked native supply advancement, and block commitment admission with `Hegemon.Native.BlockReplayRefinement.accepts_iff_block_replay_preconditions`, `Hegemon.Native.BlockReplayRefinement.accepted_has_action_stream_effect`, `Hegemon.Native.BlockReplayRefinement.accepted_claims_expected_supply`, `Hegemon.Native.BlockReplayRefinement.accepted_implies_commitment_preconditions`, `Hegemon.Native.BlockReplayRefinement.traced_result_matches_untraced`, `Hegemon.Native.BlockReplayRefinement.accepted_trace_is_canonical`, and companion counterfeit/rejection-precedence theorems. `Hegemon.Native.BlockReplayInputProjection.projectedLedgerStateAfter_eq_validate_projected_replay` proves the direct production-style projected ledger-state executor equal to accepted projected replay, and `rawProjectedLedgerStateAfter_eq_validate_raw_replay` proves the raw decoded projected executor equal to accepted replay over raw replay inputs; `accepted_projected_ledger_state_after_startup_equivalence` then lifts the direct executor to replayed supply equality, replayed leaf-cursor equality, canonical commitment-start plans, carried-state preconditions, final nullifier uniqueness, and final bridge replay-key uniqueness. `accepted_raw_projected_ledger_state_after_startup_equivalence` adds a decoded-native-block surface over the same executor: decoded carried supply, leaf cursor, spent-nullifier state, consumed bridge replay state, actions, and commitment flags project into the model and inherit the same startup equivalence, with valid and stale raw-decoded examples. `accepted_raw_projected_ledger_tree_state_after_startup_equivalence` adds the decoded native ledger/tree replay surface: raw decoded replay fields and decoded tree-transition inputs project into accepted ledger/tree replay, proving commitment-root progression, accepted ledger replay, replayed supply, leaf-cursor equality, canonical commitment-plan preconditions, carried-state preconditions, final nullifier uniqueness, and final bridge replay-key uniqueness, with valid raw and stale-root examples. `Hegemon.Native.CanonicalPublicationRefinement.accepted_canonical_publication_refines_ledger_tree_replay` and `accepted_raw_canonical_publication_refines_ledger_tree_replay` compose those replay facts with accepted block-index reload, canonical-state reload, canonical reorg-chain admission, atomic commit-manifest admission, and storage durability admission, so the modeled publication boundary carries the same supply, leaf-cursor, commitment-root, nullifier, and bridge replay uniqueness facts. `Hegemon.Native.PendingActionBytePublicationRefinement.accepted_pending_action_bytes_bind_raw_canonical_publication` adds the accepted byte-admission layer: exact pending-action decode, exact block-action decode, pending reload key/hash checks, action-hash admission, action wire-replay projection, and raw canonical publication facts are carried together before the package exposes replayed supply, leaf-cursor, commitment-root, nullifier, and bridge replay uniqueness. `accepted_pending_action_bytes_bind_tx_leaf_publication` then composes that same package with accepted native tx-leaf/canonical statement artifact facts, so byte admission, replay/publication, and statement/proof artifact binding are available as one Lean surface. `gen_block_replay_refinement_vectors` emits examples that the production replay-refinement helper must match while calling the production native action-stream, supply, and block-commitment helpers, including valid two-action replay plus cross-action duplicate nullifier and inbound replay-key rejection cases. Those vectors now include `expected_trace`, so Rust checks the production helper's traced stage sequence, not just the final summary or rejection label. Native mined-block import, announced-block import, and explicit-chain canonical branch replay call that helper before a replayed block is accepted; the helper now materializes inline/sidecar ciphertext bytes before constructing action-stream counts, and sidecar materialization checks presence, size cap, declared size, and ciphertext-hash binding. Block artifact verification and canonical-index rebuild now consume those same materialized ciphertext bytes before tx-leaf artifact construction or canonical row derivation, so they cannot use a weaker sidecar fetch path. The blueprint implementation-binding gate rejects the claim if any non-test caller stops referencing the helper or if replay/memory planning stops using `materialize_native_action_payloads` and `plan_materialized_action_effects`. The same blueprint gate enforces declared order constraints requiring the helper to precede payload/artifact validation, the atomic mined-block sled commit, state publication, and broadcast in mined import; deeper payload/artifact validation plus nonwinning side-branch block-record persistence and winning explicit-chain reorganization in announced import; and memory mutation in canonical replay. Canonical reorg state itself is committed through `commit_reorg_state_atomically` before `publish_reorganized_state`, and `reorg_action_block_commit_reloads_canonical_sled_state` checks best/header/block-record/index/state/archive/pending reload after reopening. Startup canonical-index repair is separately bound to `commit_canonical_index_repair_atomically` and covered by `startup_canonical_index_repair_rebuilds_archive_atomically`. Nonwinning announced side-branch persistence is bound to `persist_noncanonical_block_record`, and `nonwinning_announced_side_branch_record_reloads_without_canonicalizing` checks hash-addressed reload without canonical height replacement. Canonical replay now also re-runs `verify_native_block_artifacts_locked` before memory application, and `reorg_replay_rechecks_historical_side_branch_artifacts_before_publish` checks that a durable side branch with invalid historical artifacts cannot publish a reorg. The formal-core wrapper also runs `announced_block_replay_commitment_mismatch_precedes_payload_validation` and `materialized_sidecar_ciphertext` regressions. This does not prove parser-internal arbitrary raw SCALE/bincode decoding, full raw-action replay equivalence, Merkle tree content/hash implementation equivalence, tx/recursive proof soundness, sled transaction implementation correctness, filesystem durability below the accepted durability predicate, or complete native-node equivalence.
- `Hegemon.Native.PendingActionByteParserRefinement.accepted_pending_action_byte_parser_refines_wire_replay_rows` now splits the parser/wire row-count part out of that byte-admission layer: accepted block-action decode binds declared transaction count to actual action payload count, accepted wire replay binds projected action rows to accepted decoded action count, and the publication theorem derives projected-row agreement from those facts plus the production declared-count binding instead of taking row agreement as an assumption. Parser-internal arbitrary raw SCALE/bincode correctness remains a separate target.
- The native bridge action payload admission kernel proves decoded bridge-family routing, clean state-delta scope, supported bridge action IDs, outbound payload presence, inbound proof-receipt presence, inbound replay-key/message binding, Hegemon destination binding, inbound payload-hash binding, and rejection precedence with `Hegemon.Native.BridgeActionPayloadAdmission.accepts_iff_payload_preconditions` and companion theorems. `gen_bridge_action_payload_admission_vectors` emits examples that Rust `evaluate_native_bridge_action_payload_admission` must match before bridge receipt verification.
- The native RISC Zero release-verifier kernel proves the fail-closed release decision table after bridge action prechecks with `Hegemon.Native.Risc0ReleaseVerifier.accepts_iff_release_preconditions`, `Hegemon.Native.Risc0ReleaseVerifier.release_build_never_accepts`, `Hegemon.Native.Risc0ReleaseVerifier.release_disabled_rejects`, and companion image-id/journal rejection-precedence theorems. `gen_risc0_release_verifier_vectors` emits examples that Rust `evaluate_native_risc0_release_verifier` must match, the inbound bridge regression still verifies that replay-key, destination, and payload-hash tampering reject before the disabled verifier path, and the blueprint now requires `verify_inbound_bridge_receipt` to propagate `verify_risc0_bridge_receipt`. The evaluator's explicit `expect_err` rejection sentinels are not yet expressible as result obligations in the current binding grammar. This does not enable RISC Zero receipt acceptance; it proves the current PQ-only release node fails closed until a PQ-clean verifier replaces it.
- The consensus header-preimage kernel proves the signing preimage domain and fixed-field byte layout, signing-preimage independence from signature/BFT bitmap/PoW seal payloads, BFT bitmap tag/length encoding, PoW seal tag/nonce/pow_bits encoding, and absent-auth tags with `Hegemon.Consensus.Header.signingPreimage_independent_of_auth_payloads` and the companion length/tag theorems. `gen_header_vectors` emits exact byte preimages that Rust `BlockHeader::signing_preimage_v1` and `BlockHeader::full_header_preimage_v1` must match. This does not prove SHA-256 collision resistance, SHA-256 implementation equivalence, ML-DSA unforgeability, semantic correctness of header field values, retarget economics, or network finality.
- The consensus miner-identity kernel proves no-BFT-bitmap, registered-miner, ML-DSA-65 signature length, signature parser, and signature verifier admission ordering with `Hegemon.Consensus.powMinerIdentity_accepts_valid` and the companion rejection theorems. `gen_miner_identity_vectors` emits examples that Rust `PowConsensus` checks against the production helper around the real ML-DSA parser and verifier result. This does not prove ML-DSA unforgeability, ML-DSA implementation equivalence, key-registration governance, or miner key custody. Header signing preimage byte grammar is covered separately by the consensus header-preimage kernel.
- The native miner-identity kernel proves self-contained native block metadata admission with `Hegemon.Native.MinerIdentity.accepts_iff_native_miner_identity_preconditions`, covering the genesis exemption, ML-DSA-65 public-key length/parser success, BLAKE3-384 miner-commitment agreement, ML-DSA-65 signature length/parser success, signature verifier success, and rejection precedence. `gen_native_miner_identity_vectors` emits examples that Rust `evaluate_native_miner_identity_admission` checks before native PoW metadata admission, and the blueprint binds local mining so `sign_native_block_meta` precedes final PoW verification, atomic persistence, state publication, and broadcast. This does not prove ML-DSA unforgeability, ML-DSA implementation equivalence, key custody, native miner registry membership, or complete native-node equivalence.
- The wallet note-ciphertext wire/decrypt/plaintext kernel proves representative crypto-format and chain-format parser facts with `Hegemon.Wallet.NoteCiphertextWire.crypto_valid_accepts`, `Hegemon.Wallet.NoteCiphertextWire.crypto_truncated_after_kem_rejects`, `Hegemon.Wallet.NoteCiphertextWire.crypto_trailing_byte_rejects`, `Hegemon.Wallet.NoteCiphertextWire.chain_valid_accepts`, and companion chain rejection theorems for memo overrun, nonzero fixed-container padding, noncanonical compact KEM length, and trailing bytes. `Hegemon.Wallet.NoteCiphertextWire.bounded_parse_compact_mlkem_consumes_two`, `Hegemon.Wallet.NoteCiphertextWire.parsed_chain_ciphertext_has_fixed_wire_length_of_bounded`, and `Hegemon.Wallet.NoteCiphertextWire.parsed_chain_ciphertext_has_projected_da_bytes_of_bounded` prove that byte-bounded accepted chain wires consume exactly the fixed chain container, the canonical compact ML-KEM length bytes, and the ML-KEM ciphertext bytes, and project to the fixed DA ciphertext-hash preimage bytes after deleting the compact length field; the bounded hypothesis is required because the Lean `Byte` model is `Nat`. `Hegemon.Wallet.NoteCiphertextDecrypt.decrypt_admission_rejects_version_mismatch`, `decrypt_admission_rejects_crypto_suite_mismatch`, `decrypt_admission_rejects_diversifier_mismatch`, `wrong_recipient_or_malleated_ciphertext_fails_under_crypto_assumptions`, and `decrypt_success_implies_metadata_matches` prove the modeled decrypt admission order and success boundary over an explicit crypto-authentication predicate. `Hegemon.Wallet.NotePlaintextCommitment.decrypt_success_plaintext_to_commitment_boundary` and `active_output_slot_commitment_matches_exported_plaintext` prove that decrypted plaintext plus recipient material exports the note data committed by the same abstract note-commitment relation used by spend authorization and active public output slots. `Hegemon.Privacy.NativeObserverSurface.native_tx_leaf_active_output_ciphertext_boundary_has_projected_da_bytes` lifts the projected DA preimage boundary to the selected active native tx-leaf observer row while carrying the existing statement/proof-binding ciphertext-hash indices and native equality gates. `Hegemon.Privacy.Observer.same_public_metadata_leakage_of_public_summaries_and_placement` separates public metadata leakage from raw ciphertext wire bytes, and `same_batch_timing_leakage_of_valid_public_inputs_and_placement` makes batching/timing leakage explicit as active-output count, ciphertext count, parsed-summary count, block height, and action index. `Hegemon.Privacy.CiphertextPrivacy` adds the same-shape ciphertext privacy-game boundary over valid observer-chain worlds: public inputs, parsed summaries, placement, public metadata leakage, and explicit batch/timing leakage preserve public shape/count/format facts, while `wireIndistinguishable` is the one explicit ML-KEM/AEAD/KDF/RNG premise for different same-shape wire bytes. `Hegemon.Privacy.CiphertextPrivacy.ciphertext_privacy_game_boundary_facts` packages those deterministic facts with first-class proof-system zero-knowledge, wallet metadata hygiene, timing/batching policy, and network metadata policy assumptions, and proves the observer, public metadata, and batch/timing projections ignore private witnesses and prover randomness once public wire data is fixed. `ciphertext_privacy_game_secret_resampling_boundary_facts` further proves public metadata and explicit batch/timing leakage are stable under independent left/right private-witness and prover-randomness resampling. `Hegemon.Privacy.NativeObserverSurface.native_tx_leaf_ciphertext_privacy_game_active_output_slot_selects_same_public_summary` composes the game with active native tx-leaf output-slot binding, proving both worlds select the same public active-output rank and parsed summary, carry the same statement/proof-bound commitment and ciphertext-hash metadata plus native ciphertext equality gates, preserve batch/timing leakage, and retain `wireIndistinguishable` as the explicit raw-wire crypto obligation. `Hegemon.Privacy.NativeObserverSurface.native_tx_leaf_ciphertext_privacy_game_decrypts_selected_output_to_statement_commitment` further composes the selected row with wallet decrypt success and plaintext commitment export, proving recipient-decrypted selected output rows reconstruct the exact plaintext-derived commitment indexed in public shape, statement preimage, and proof-binding vectors while preserving public metadata, batch/timing leakage, and the explicit raw-wire crypto obligation. `gen_note_ciphertext_wire_vectors` emits examples with expected wire lengths and expected DA projection bytes that Rust checks against `synthetic_crypto::note_encryption::NoteCiphertext::from_bytes`, `wallet::NoteCiphertext::from_chain_bytes`, `wallet::NoteCiphertext::to_da_bytes`, and production `ciphertext_hash_bytes`, including the fixed valid chain and DA preimage lengths. Focused Rust regressions additionally check wrong recipient/root key, metadata mismatch, KEM/note/memo payload malleation rejection, full-view decrypt-to-witness commitment equality, recipient-decrypted wallet bundle/native tx-leaf commitment and ciphertext-hash consistency, and same-plaintext same-recipient re-encryption freshness. This does not prove ML-KEM security or implementation equivalence, AEAD confidentiality or unforgeability, Poseidon2/BLAKE3 hash security, nullifier correctness, BLAKE3 ciphertext-hash security/equality, full DA-root inclusion or DA availability, wallet key security, simulator zero knowledge, timing or batching privacy, or complete wallet/native equivalence.
- `Hegemon.Privacy.NativeObserverSurface.native_tx_leaf_ciphertext_privacy_game_selected_output_wire_da_commitment_boundary` composes selected same-shape privacy-game output rows with the byte-bounded chain-wire and projected-DA boundary for both worlds, carrying fixed wire length, fixed DA preimage length, public/statement/proof-binding ciphertext rows, native ciphertext-hash/payload-hash/output-count gates, and explicit ML-KEM, AEAD, KDF, RNG, and raw-wire indistinguishability assumptions. `native_tx_leaf_active_output_ciphertext_boundary_binds_projected_da_hash` is the single-world companion that binds projected DA bytes to the public ciphertext-hash row through an explicit hash-match predicate before any privacy-game comparison. `native_tx_leaf_ciphertext_privacy_game_decrypts_selected_output_to_statement_commitment_and_projected_da_hash` composes recipient decrypt-to-commitment with that selected privacy-game DA boundary, proving the selected output reconstructs the public/statement/proof-bound commitment while both worlds' selected projected DA bytes satisfy the explicit public ciphertext-hash predicate. These are selected-row implementation-equivalence boundaries for privacy/ciphertext refinement, not proofs of ML-KEM/AEAD security, BLAKE3 ciphertext-hash security, or simulator zero knowledge.
- The transaction note-commitment input kernel proves `Hegemon.Transaction.NoteCommitmentInputs.note_commitment_domain_tag_is_one`, `bytes32_to_felts_has_four_limbs`, `note_commitment_inputs_have_eighteen_limbs`, `note_commitment_inputs_start_with_value_and_asset`, `note_commitment_inputs_absorb_recipient_rho_randomness_auth`, and canonical asset-id facts for the native id, padding sentinel, padding field alias, field modulus, and ordinary ids. `gen_note_commitment_input_vectors` emits patterned 32-byte field cases and asset-id edge cases that Rust checks against the shared `transaction_core::hashing_pq::note_commitment_inputs` helper, while focused transaction and disclosure regressions require Plonky3, SmallWood, and disclosure preimage builders to use that helper and require note/public-input/disclosure boundaries to reject field-aliasing asset ids. This binds the deployed note commitment preimage order `value, asset_id, pk_recipient, rho, r, pk_auth` and 8-byte big-endian limb grammar; it does not prove Poseidon2 cryptographic binding/hiding, full Poseidon2 implementation equivalence, nullifier derivation, or deployed AIR/proof-system soundness.
- The transaction nullifier input kernel proves `Hegemon.Transaction.NullifierInputs.nullifier_domain_tag_is_two`, `nullifier_inputs_have_six_limbs`, `nullifier_inputs_start_with_prf_and_position`, `nullifier_inputs_absorb_rho_after_position`, and `nullifier_inputs_one_absorb_block`. `gen_nullifier_input_vectors` emits patterned rho cases that Rust checks against the shared `transaction_core::hashing_pq::nullifier_inputs` helper, while focused transaction regressions require Plonky3 and SmallWood nullifier preimage builders to use that helper. This binds the deployed nullifier preimage order `prf_key, position, rho` and 8-byte big-endian rho limb grammar; it does not prove Poseidon2 cryptographic security, nullifier PRF pseudorandomness, full Poseidon2 implementation equivalence, or deployed AIR/proof-system soundness.
- The consensus version-policy kernel proves initial bindings, activation/retirement boundary behavior, same-height retirement precedence, duplicate initial binding deduplication, and first unsupported transaction ordering with `Hegemon.Consensus.versionPolicy_initial_accepts` and the companion rejection theorems. `gen_version_policy_vectors` emits examples that Rust `VersionSchedule::validate_versions` checks on the PoW and BFT import paths, and the blueprint binds the PoW/BFT wrapper calls before proof verification, node insertion, vote-history mutation, slashing mutation, or fork mutation. This does not prove social upgrade governance, manifest correctness, per-version proof-system soundness, or native-node equivalence.
- The bridge message-root transcript grammar is part of the Lean bridge slice. `Hegemon.Bridge.MessageRoot` proves representative facts for exact root preimage domain/count/hash length-prefix bytes, invalid hash-length rejection, ordered-pair transcript construction, reversed-pair distinction, and count-prefix binding. `gen_bridge_vectors` emits those transcript examples alongside bridge encoding/replay examples, and the Rust `protocol-kernel` conformance test checks them against the production root preimage helper. This does not prove BLAKE3 cryptographic security or implementation equivalence.
- The bridge long-range proof-shape admission table is part of the Lean bridge slice. `Hegemon.Bridge.LongRange` proves representative facts for verifier-hash binding, message-count binding, header/MMR length shape, trusted/message/tip height ordering, selected message source, sample height/opening-index agreement, confirmation policy, tip-work policy, and claimed-output agreement. `gen_bridge_long_range_vectors` emits examples that the Rust `consensus-light-client` conformance test checks against the production helper called by the long-range verifier. The production wire decoder is additionally covered by Rust regressions for exact consumption, truncation, non-canonical compact lengths, allocation caps, and guest output-tail mismatch; those are hardening tests, not yet a Lean-modeled wire grammar. This does not prove SHA-256 implementation equivalence, PoW hash security, MMR hash binding, complete long-range proof wire-grammar equivalence, probabilistic FlyClient sampling soundness, or complete bridge light-client soundness.
- The bridge checkpoint-output binding kernel is part of the Lean bridge slice. `Hegemon.Bridge.CheckpointOutput` proves representative facts for the exact output domain, canonical-preimage/domain-plus-wire relation, fixed 404-byte journal tuple, scalar little-endian encodings, and max-scalar cases. `gen_bridge_checkpoint_output_vectors` emits canonical and journal byte examples that the Rust `consensus-light-client` conformance test checks against production output encoding and decoding helpers, including fixed-length rejection for truncated or trailing journal bytes. This does not prove BLAKE3 cryptographic security or implementation equivalence, bridge message-root/hash derivation, external verifier behavior, or complete bridge light-client soundness.
- The bridge header-MMR opening-shape kernel is part of the Lean bridge slice. `Hegemon.Bridge.HeaderMmr` proves representative facts for peak decomposition, context mismatch rejection, leaf bounds, sibling-count admission, local-index derivation, and left/right path orientation. `gen_bridge_header_mmr_vectors` emits examples that the Rust `consensus-light-client` conformance test checks against `evaluate_header_mmr_opening_shape`, the helper used by standalone and long-range MMR opening verification. This does not prove SHA-256 implementation equivalence, MMR parent/root hash security, FlyClient sampling soundness, or complete bridge light-client soundness.
- The bridge header-MMR parent/root transcript kernel is part of the Lean bridge slice. `Hegemon.Bridge.HeaderMmrTranscript` proves representative facts for exact parent/root domains, u32/u64 little-endian counters, left/right child order, ordered peak concatenation, empty roots, and reversed-peak distinction. `gen_bridge_header_mmr_transcript_vectors` emits examples that the Rust `consensus-light-client` conformance test checks against `header_mmr_parent_preimage_v1` and `header_mmr_root_preimage_v1`, the helpers hashed by MMR construction and verification. This does not prove BLAKE3 cryptographic security or implementation equivalence, SHA-256 header-hash implementation equivalence, MMR collision resistance, full MMR hash binding, FlyClient sampling soundness, or complete bridge light-client soundness.
- The bridge FlyClient sampling transcript/index kernel is part of the Lean bridge slice. `Hegemon.Bridge.FlyClient` proves representative facts for the exact sample transcript domain and little-endian range/sample-counter byte layout, digest-prefix modulo reduction, duplicate sample preservation, sample-count truncation, and empty/reversed ranges. `gen_bridge_flyclient_vectors` emits examples that the Rust `consensus-light-client` conformance test checks against the production helpers used by `flyclient_sample_indices`. This does not prove BLAKE3 cryptographic security or implementation equivalence, MMR hash binding, probabilistic FlyClient sampling soundness, or complete bridge light-client soundness.
- Every production-eligible blueprint node must name at least one cheap falsification case, such as an invalid vector, negative unit test, counterexample config, or checker case that would fail quickly if the claim were false. Target-review acceptance means the statement and evidence target have been reviewed for CI gating; it is not external cryptographic acceptance, and it does not change any ledger residual risk.
- A local pass is preflight evidence. Branch acceptance requires the CI `formal-core` job to run `bash scripts/check_formal_core.sh` and report the blueprint-DAG step passed. Passing `formal-core` is release-gate evidence, not a proof of the full Rust implementation and not a replacement for TLC/Apalache runs, external cryptanalysis, or checked-in acceptance artifacts.
- `circuits/formal/README.md` and `consensus/spec/formal/README.md` explain how to run the TLA+ models. Include the TLC/Apalache output summary in PR descriptions when those specs change; set `HEGEMON_FORMAL_RUN_MODEL_CHECKERS=1` before running `scripts/check_formal_core.sh` if local TLC/Apalache binaries are installed and you want the wrapper to run them too.
- `runbooks/security_testing.md` documents how to rerun the `security-adversarial` job locally, capture artifacts, and notify auditors if a regression appears on CI. Treat it as mandatory reading before release tagging.
- Run `./scripts/dependency-audit-gate.sh` for dependency advisories; CI and release builds fail on any unwaived finding. Use `./scripts/dependency-audit.sh --record` only to append a human-readable snapshot after updating `config/dependency-audit-waivers.json`.

### Documentation + threat-model synchronization

Whenever you touch an API, threat mitigation, or performance assumption:

1. Update the component README (e.g., `wallet/README.md`) with the new commands or invariants.
2. Update `docs/API_REFERENCE.md` so integrators can find the function signatures.
3. Update `docs/THREAT_MODEL.md` when security margins move.
4. Reflect the architectural impact in `DESIGN.md §6` (or the relevant subsystem section) and record the operational/testing changes here in METHODS.
5. Mention the change in `docs/CONTRIBUTING.md` so future contributors know which CI jobs/benchmarks cover it.

PRs missing any of these sync points should be blocked during review; CI surfaces the changed docs alongside code so reviewers can verify everything moved together.

### Aggregation authoring update (February 27, 2026)

- Local prover execution now uses bounded reusable work queues instead of per-job cold starts. This keeps recursion artifacts on stable worker threads and reduces repeated cache rebuilds caused by thread churn.
- Aggregation cache warmup is now explicit and checkpointed by default:
  - `HEGEMON_AGG_PREWARM_MAX_TXS` controls whether breadth warmup is attempted at all (unset defaults to no automatic max-target expansion on the hot path).
  - `HEGEMON_AGG_PREWARM_MODE=checkpoint` (default) expands warmup shapes geometrically (`1,2,4,8,...`) when a max tx cap is provided.
  - `HEGEMON_AGG_PREWARM_MODE=linear` restores legacy linear warmup.
  - `HEGEMON_AGG_WARMUP_TARGET_SHAPES` continues to support explicit shape lists.

Operationally, this change removes hidden O(target) warmup churn from live proving and makes warmup policy explicit in runbooks and benchmark configs.
