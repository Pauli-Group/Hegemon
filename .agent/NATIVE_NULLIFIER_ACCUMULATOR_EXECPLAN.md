# Make canonical nullifier state incremental and disk-authoritative

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current while work proceeds. Maintain this document in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Native block construction and canonical tip import must not copy, retain in RAM, or rehash every nullifier ever spent. After this change, exact duplicate detection is disk-authoritative through paired forward/reverse sled indexes, while a bounded structurally shared overlay serves uncommitted suffix work and a small append-only Merkle-mountain-range accumulator advances the consensus nullifier root. An operator can observe the result by importing multiple blocks, restarting, and reorganizing between forks: the same ordered nullifiers produce the same root, corrupted indexes, WAL rows, or accumulator state stop full validation before mutation, and per-append hashing and resident memory remain independent of total history.

This is a fresh-V3 storage and consensus integration. The accumulator algorithm, byte domains, order, and version must be named in the active V3 rules preimage before release. Until the separate V3 header, block-identity, and transport constants are frozen, this plan deliberately leaves the checked rules-hash and genesis fixtures unchanged and records that release blocker explicitly.

## Progress

- [x] (2026-08-17) Read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, and traced template preview, mined import, announced import, restart, replay, reorganization, repair, metadata, and rules-hash paths.
- [x] (2026-08-17) Added `PersistentKeySet48`, a compressed immutable Patricia set with exact full-key comparison, constant-work snapshot clones, path-copy mutation, lexicographic iteration, and randomized differential/invariant tests.
- [x] (2026-08-17) First migrated canonical nullifiers and consumed inbound-bridge replay keys to `PersistentKeySet48` while retaining separate pending indexes; this intermediate resident-history design is now superseded by the V3 disk-authoritative module below.
- [x] (2026-08-17) Added a versioned, length-framed RFC7693 BLAKE2b-384 append-order nullifier accumulator with a canonical `u64` leaf count, at most 64 peaks, checked append, fixed transcript vectors, and an independent full-recomputation oracle.
- [x] (2026-08-17) Replaced template and import root recomputation with accumulator snapshots/appends and persisted exact big-endian append indexes plus accumulator state in canonical transactions.
- [x] (2026-08-17) Added fail-closed startup parsing for malformed, duplicate, non-contiguous, out-of-range, reordered, missing, and corrupt persistent state, including namespace classification before any `open_tree` call and byte-for-byte no-mutation tests for partial, unknown, legacy-V1, and missing-best databases.
- [x] (2026-08-17) Added an executable Lean peak/carry/order model and JSON generator; its Rust consumer checks empty blocks, zero rejection without mutation, carry counts, peak grouping, and independently hashed peaks.
- [x] (2026-08-17) Integrated the schema-2 Lean generator and exact Rust consumer into the central formal runner; the generated vector consumer passes with `HEGEMON_LEAN_NULLIFIER_ACCUMULATOR_VECTORS` set.
- [x] (2026-08-17) Benchmarked the structurally shared set and hash primitive on the same machine. Persistent clone-plus-1,040 inserts is 0.251/0.269/0.420 ms at 65,536/262,144/1,000,000 historical keys, versus 1.157/4.062/18.189 ms for `BTreeSet`; root clones are 4-11 ns. On the exact production V2 length frame, the median aggregate for 1,040 leaf hashes plus the 1,038 start-from-empty parent merges was about 0.533 ms for BLAKE2b-384, 0.642 ms for the insecure BLAKE3-XOF48 comparator, and 0.947 ms for SHA-384; even the secure hash choice improves this isolated hot path.
- [x] (2026-08-17) Replaced the unbounded canonical in-memory-set design with an isolated V3 disk-authoritative membership module: paired generation-prefixed key/index bases for nullifiers and consumed bridge messages, a bounded exact cache, bounded path-copy overlays, compact snapshots, exact suffix deltas, and seven fixed V3 tree names/codecs.
- [x] (2026-08-17) Added a single-active-generation membership WAL with deterministic order/by-key/by-index cross-bindings, canonical streaming BLAKE2b-384 seal digest, bounded idempotent staging/finalization/cleanup, and transactional active/sealed guards. Focused BTreeSet differential, corruption/no-mutation, key-swap finalization, snapshot codec, epoch-token, cache-churn, and 65,536-row resident-bound regressions pass in the isolated module.
- [ ] Add and pass narrow mined-commit duplicate and reorg A-to-B-to-A atomic persistence tests after the concurrently owned canonical helper signatures freeze.
- [ ] Integrate `CanonicalMembershipIndexes48`/`CanonicalMembershipViews48`, the compact trusted snapshot, active-WAL manifest pointer, and direct-delta/finalizer helpers into startup, mined/import, and suffix-reorg flows without holding state locks across sled I/O or flush.
- [ ] Bind the final accumulator and membership schema into the active V3 rules preimage and regenerate exact genesis/rules fixtures only after the parent declares all V3 constants frozen.
- [ ] Finish formatting, the full node/formal gates, and a final integrated diff review after concurrent owners freeze the shared tree.

## Surprises & Discoveries

- Observation: A `BTreeSet` clone in a state snapshot is linear in all historical keys even when the caller only needs an immutable view.
  Evidence: the prior template/reorg snapshots cloned canonical nullifier and bridge sets; `PersistentKeySet48::shares_root_with` now shows that a snapshot increments exactly one root `Arc` and allocates no trie nodes.

- Observation: A binary trie that allocates one node per bit would consume up to 384 internal nodes per 48-byte key, which is unacceptable at realistic history sizes.
  Evidence: the compressed Patricia representation has exactly `2n - 1` reachable nodes for `n > 0`; the 65,536-key regression asserts this bound and reports a conservative live-node byte estimate.

- Observation: A set-sorted root cannot preserve consensus action order, while an append-order accumulator cannot by itself reject duplicates.
  Evidence: fixed vectors produce different roots for reversed leaves; exact duplicate rejection remains in `PersistentKeySet48` and at mined/reorg/repair persistence seams.

- Observation: A superficially independent MMR test can be tautological if it calls the production leaf and parent helpers.
  Evidence: the reference oracle now constructs literal domain transcripts in separate code and fixed roots pin domain bytes, height endianness, left/right order, peak order, and root framing.

- Observation: Existing synthetic transfer helpers rewrite public inputs around a checked-in proof and therefore cannot honestly establish successful multi-block proof replay.
  Evidence: cross-layer persistence tests are split at the durable commit/reorg seam; a true end-to-end two-transfer restart test remains impossible without a second distinct chained proof fixture or a real fixture generator.

- Observation: Missing `META_BEST_KEY` does not prove a fresh database.
  Evidence: startup originally considered only core block trees and opened current names before classification. The guard now snapshots `db.tree_names()` before any production `open_tree`, permits only a truly empty namespace or the exact active namespace, and rejects any non-empty tree before writing V2 genesis.

- Observation: BLAKE3 XOF output longer than 32 bytes does not turn its 256-bit chaining value into a 384-bit collision commitment.
  Evidence: the accumulator no longer calls BLAKE3 or `finalize_xof`; schema-2 domains name RFC7693 BLAKE2b-384, raw and framed known-answer tests pin the primitive, and persisted schema-1/BLAKE3 state rejects without mutation.

- Observation: the secure hash migration does not require a TPS concession.
  Evidence: both the requested unframed 79/131/3,115-byte primitive comparison and a second exact production-frame comparison put native BLAKE2b-384 ahead in aggregate of SHA-384 and the former BLAKE3-XOF48 comparator. The much larger gain comes from removing history-sized set clones and concatenation.

- Observation: even an optimal `2n-1` persistent Patricia tree is not a viable resident representation for worst-case canonical history.
  Evidence: at the protocol ceiling, 520 transfers times two nullifiers per block can accumulate roughly 547 million nullifiers per year. A full persistent trie would still retain more than one billion heap nodes; structural sharing fixes snapshot-copy cost but not resident-history cost.

- Observation: exact append-order validation and bounded-memory corruption audits require a paired reverse index, not only key-to-ordinal rows.
  Evidence: `canonical_membership.rs` streams ordinal-to-key and key-to-ordinal rows with at most one buffered key and rejects missing, duplicate, malformed, or non-bijective rows. The reverse tree also makes suffix rollback and ordinal lookup exact without scanning history.

- Observation: a caller-supplied "inactive generation" check is race-prone.
  Evidence: cleanup now reads the authoritative `active` pointer and requires `sealed/<generation>` to be absent in the same sled transaction that deletes a bounded batch. The outer reorg-WAL mutex additionally serializes stage, seal, cleanup, and flip.

- Observation: a bounded FIFO log can still lose its effective working-set capacity when old epoch entries become orphaned from the eviction queue.
  Evidence: the exact cache now clears on binding changes and removes matching entries whenever its order log is compacted; a many-epoch churn regression retains all current-binding hits at the configured capacity.

## Decision Log

- Decision: Use an internal compressed Patricia set instead of adding a third-party immutable-set dependency.
  Rationale: it keeps the dependency and license surface unchanged, provides exact `[u8; 48]` comparison, guarantees `O(n)` live nodes, and gives a directly testable constant-work snapshot clone.
  Date/Author: 2026-08-17 / Codex.

- Decision: Use native RFC7693 BLAKE2b-384 (`Blake2b<U48>`) with one centralized length-framed helper, distinct leaf/node/root/state V2 domains, a `u64` leaf count, and a parent-height field.
  Rationale: BLAKE2b-384 has a genuine 384-bit output/capacity profile suitable for the required generic 128-bit quantum collision bound, is an existing dependency, and was faster on the accumulator workloads than SHA-384 and the insecure BLAKE3-XOF48 baseline. Length-framing binds domain and part boundaries without concatenation ambiguity.
  Date/Author: 2026-08-17 / Codex.

- Decision: Reject schema-1/BLAKE3 accumulator records instead of silently upgrading them.
  Rationale: changing the hash primitive and domains changes every root. Startup therefore requires `nullifier_accumulator_v2` and the exact state-V2 prefix, preserving legacy rows byte-for-byte on rejection.
  Date/Author: 2026-08-17 / Codex.

- Decision: Store nullifier-to-append-index rows as exact eight-byte big-endian values while encoding accumulator counts little-endian inside its versioned record.
  Rationale: big-endian tree values are easy to inspect and sort conventionally; accumulator transcript endianness is independently domain-bound and fixed by vectors. Startup checks both encodings exactly rather than accepting legacy marker bytes.
  Date/Author: 2026-08-17 / Codex.

- Decision: Reject the all-zero nullifier inside `NullifierAccumulator::append`, before any mutation.
  Rationale: persistence replay must not depend on an upstream validator to reject a corrupt zero row. Duplicate rejection intentionally remains a separate exact-set invariant because an accumulator is not a membership structure.
  Date/Author: 2026-08-17 / Codex.

- Decision: Do not regenerate the active V3 rules hash while header identity, miner identity, and transport constants are changing concurrently.
  Rationale: repeatedly freezing partial preimages risks publishing internally inconsistent genesis fixtures. Release remains blocked until one coordinated final preimage/hash regeneration and old-profile rejection test.
  Date/Author: 2026-08-17 / Codex.

- Decision: Use `PersistentKeySet48` only for bounded pending/uncommitted overlays; make canonical nullifier and consumed-bridge membership disk-authoritative.
  Rationale: exact sled point reads avoid false positives and keep resident memory independent of historical cardinality. The bounded cache and path-copy overlay preserve hot repeated reads and constant-work snapshots without retaining the full canonical set.
  Date/Author: 2026-08-17 / Codex.

- Decision: Store both forward and reverse rows under an explicit base generation, and stage reorg suffix mutations in exactly three membership WAL trees: by-key, by-index, and canonical order.
  Rationale: paired rows support exact point membership, exact ordinal replay, O(1)-memory audits, key swaps, and resumable finalization. One order row represents the paired mutation so forward and reverse updates cannot be interpreted under different orderings.
  Date/Author: 2026-08-17 / Codex.

- Decision: Permit one visible sealed canonical WAL, but allow a subsequent reorg to external-normalize its validated unapplied ordered suffix with the new effective-view delta into one replacement generation.
  Rationale: mandatory full finalization makes reorg latency proportional to the prior WAL. Replacement streams one record at a time and CAS-binds the old generation, seal, progress, base generation, and epoch, so two WALs are never simultaneously visible.
  Date/Author: 2026-08-17 / Codex.

- Decision: Offer two explicit startup modes rather than overclaiming a cheap cryptographic audit of mutable local state.
  Rationale: the exact WAL seal digest authenticates staged WAL rows, but it does not authenticate every compacted base row. Fast open may trust the compact marker only under the named host-and-disk-integrity TCB; full validation streams both paired bases and the active WAL before mutation.
  Date/Author: 2026-08-17 / Codex.

## Outcomes & Retrospective

The incremental accumulator and isolated disk-membership structures are implemented. Template preview and ordinary accumulator append do one BLAKE2b-384 leaf hash plus at most 64 parent merges per new nullifier. The V3 membership module keeps historical keys in paired sled indexes and retains only a bounded exact cache plus bounded structurally shared suffix overlays in RAM. Protocol-level differential, structural-sharing, allocation-bound, fixed-transcript, zero-rejection, codec-corruption, startup no-mutation, Lean model, WAL cross-binding/digest, release-path rebase-token, cache-churn, and large-disk-history resident-bound checks pass. At one million keys, the bounded overlay’s measured snapshot-plus-1,040-insert cost was 0.420 ms versus 18.189 ms for a full `BTreeSet` clone; exact framed accumulator hashing adds about 0.533 ms for the 1,040-leaf start-from-empty carry schedule and remains independent of total history. These measurements characterize the isolated structures, not the still-pending outer V3 integration.

The change is not release-complete until the disk views replace the current full-history canonical fields in every outer path, commit/reorg transaction-boundary regressions pass, startup namespace and trusted-snapshot integration is complete, the final global V3 preimage/hash/genesis are regenerated once after the separate header-identity migration freezes, and full integrated node/formal validation is green. Those gaps are explicit release blockers rather than softened claims.

## Context and Orientation

A nullifier is a 48-byte value revealed when a shielded note is spent. The canonical set prevents the same value from being spent twice. `node/src/native/mod.rs` defines `NativeState`; `node/src/native/block_flow.rs` plans and previews action effects; `node/src/native/node_impl.rs` imports, replays, reorganizes, and commits blocks; and `node/src/native/storage.rs` creates genesis and reloads persistent state.

A Merkle mountain range, abbreviated MMR, is an append-only collection of perfect binary-tree roots called peaks. Appending one leaf merges only the trailing peaks implied by the old leaf count. `node/src/native/nullifier_accumulator.rs` implements this MMR. Its header root hashes the ordered peaks together with the exact leaf count, so empty history, append order, and tree shape are all bound.

`protocol/shielded-pool/src/persistent_set.rs` implements the exact immutable set used for bounded pending and uncommitted overlays. A Patricia trie stores a branch only at a bit where two keys differ. Nodes are immutable and owned through `Arc`, Rust's atomically reference-counted pointer, so cloning an overlay shares all existing nodes. Insertion and removal allocate only a copied search path. It is deliberately not the resident representation of all canonical history.

Sled is the embedded database used by the native node. The V3 compacted bases are `shielded_nullifiers_v3_by_key`, `shielded_nullifiers_v3_by_index`, `bridge_inbound_messages_v3_by_key`, and `bridge_inbound_messages_v3_by_index`. A forward key is `base_generation_be8 || key48` with `ordinal_be8`; a reverse key is `base_generation_be8 || ordinal_be8` with `key48`. Reorg staging uses `canonical_membership_v3_wal_by_key`, `canonical_membership_v3_wal_by_index`, and `canonical_membership_v3_wal_order`; the outer authoritative pointer is `active` in `native_reorg_wal_manifests_v3`. The `meta` tree still stores the encoded accumulator under `META_NULLIFIER_ACCUMULATOR_KEY`. Mined and reorg transactions must update block metadata, exact membership deltas or the active-WAL pointer, and accumulator state under one coordinated durability/publication protocol.

`formal/lean/Hegemon/Native/NullifierAccumulator.lean` is intentionally symbolic: it retains ordered leaf tags inside peaks instead of claiming to prove BLAKE2b. `GenerateNullifierAccumulatorVectors.lean` exports the peak grouping and carry schedule plus the exact schema-2 algorithm and domain labels. Rust independently hashes those groups with literal framed transcript bytes. This is an executable refinement check, not a cryptographic proof of BLAKE2b.

## Plan of Work

Keep `PersistentKeySet48` fixed to `[u8; 48]` for bounded overlays. Validate membership and iteration against `BTreeSet`; validate branch bits strictly increase down every path; validate every leaf matches all branch decisions; and validate insertion order does not affect membership, iteration, or live-node count. Enforce an explicit overlay key cap before publication.

Keep `NullifierAccumulator` small: `leaf_count: u64` and left-to-right `peaks: Vec<[u8; 48]>`. Reject zero and invalid shape before mutation, use checked count arithmetic, and encode a stored root in the durable record so bit corruption fails before state publication. Tests must not share production transcript helpers with the oracle.

At block preview and application, clone only the accumulator and bounded view overlay, query historical membership by exact disk point lookup plus cache, append nullifiers in canonical action order, and compare the resulting root to metadata. For ordinary small canonical advances with no active WAL, apply paired forward/reverse suffix rows and encoded accumulator state in the caller’s single sled transaction. Before any write, reject duplicate keys within a batch and any key already present in the effective canonical view.

At startup, classify the complete V3 namespace before creating any tree, exact-decode the compact trusted snapshot, and bind one stable even epoch, base generation, optional sealed active-WAL generation/digest, canonical tip, and base/final family counts. Full-audit mode streams both paired bases and the active WAL in O(1) auxiliary memory and requires exact bijection, order/count/digest cross-binding, and accumulator equality before mutation. Fast-open mode may trust the compact marker only under the explicit host-and-disk-integrity TCB. Never repair or bootstrap over a partial or legacy namespace.

For reorganization, derive only the old/new suffix delta at the common ancestor. Stage deterministic paired membership mutations into an inactive nonzero generation in bounded batches, audit the exact three-tree row stream, seal its central-domain digest, and atomically flip the authoritative active pointer together with best/tip/trusted snapshot. Point reads consult the active WAL before the compacted base. A resumable finalizer applies canonical order rows to both base indexes in bounded transactions while the WAL remains authoritative, then clears the pointer. If another reorg arrives first, pause finalization, validate seal and progress, stream the unapplied suffix with O(1) buffering, external-normalize it with the new effective-view delta, and CAS-replace the pointer; never layer visible WALs. Exercise branch A to B to A at the commit seam and compare exact rows, counts, snapshots, accumulator state, and roots after every transition. Do not label synthetic proof artifacts as valid end-to-end replay.

Once the V3 constants freeze, add the nullifier MMR algorithm/version, all four domains, membership schema/tree codecs, `u64` append index, and canonical block/action/nullifier order to the active rules preimage. Regenerate the exact active hash and genesis fixture once, then demonstrate that databases and peers advertising former or interim profiles reject rather than silently migrate.

## Concrete Steps

Run all commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

First validate the two reusable protocol structures:

    cargo test -p protocol-shielded-pool --lib
    cargo test -p protocol-kernel --lib

Expect 11 shielded-pool tests and 6 kernel tests to pass, including the 65,536-key compressed-shape regression.

Compile and run the isolated Lean model while central build targets are in flight:

    cd formal/lean
    lake env lean -o .lake/build/lib/lean/Hegemon/Native/NullifierAccumulator.olean Hegemon/Native/NullifierAccumulator.lean
    lake env lean -o .lake/build/lib/lean/Hegemon/Native/GenerateNullifierAccumulatorVectors.olean Hegemon/Native/GenerateNullifierAccumulatorVectors.lean
    lake env lean --run Hegemon/Native/GenerateNullifierAccumulatorVectors.lean

Expect JSON schema version 2 with RFC7693-BLAKE2b-384, exact V2 domains, and empty, singleton, multi-block-with-empty, eight-leaf carry, and zero-rejected cases. The central runner uses `lake exe gen_nullifier_accumulator_vectors` and passes its output through `HEGEMON_LEAN_NULLIFIER_ACCUMULATOR_VECTORS` to the exact Rust consumer.

When the native node interface is stable, run:

    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo check -p hegemon-node --lib
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p hegemon-node --lib canonical_membership::tests:: -- --test-threads=1
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p hegemon-node nullifier_accumulator::tests --lib
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p hegemon-node indexed_nullifier --lib
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p hegemon-node nullifier_accumulator_reload --lib
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p hegemon-node nullifier_commit --lib
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p hegemon-node nullifier_reorg --lib

Finally run the repository's formal gate and formatting/diff checks selected by the parent integration plan. Record any unrelated concurrent failure precisely; do not convert it into a pass claim.

## Validation and Acceptance

Acceptance requires all of the following observable behaviors.

The raw RFC7693 known-answer test and fixed Rust root vectors must fail if the primitive, frame prefix, a domain byte, count endianness, parent height, child order, peak order, part boundary, or root framing changes. The Lean-generated test must fail if Rust algorithm/version labels, carry scheduling, empty-block identity, zero rejection, peak grouping, or action order drift.

At 131,073 appended leaves, every append must report exactly one leaf hash and no more than 64 parent hashes. Root work must hash at most 64 peaks. Cloning an 8,192-key set snapshot must share exactly one root pointer, while a subsequent mutation must allocate no more than 386 nodes. A 65,536-key set must have exactly 131,071 live Patricia nodes.

Startup full-audit mode must reject every corrupted persistence fixture and leave a byte-for-byte snapshot of every tree unchanged. A valid indexed state must survive database close/reopen with exact paired family rows, base/active generations, counts, WAL seal digest, leaf count, peaks, and root. Fast-open tests must state and exercise only the compact-marker host/disk TCB, not imply that the WAL digest authenticates compacted base rows.

The canonical membership cache and every uncommitted overlay must remain bounded independently of disk history. A 65,536-row fixture must retain no full-history in-memory set; many stable-epoch changes must preserve the entire current cache working set. Publication must reject a foreign, reused, or stale committed-epoch token and mismatched final counts in release logic, not only through debug assertions.

Inactive-WAL cleanup must require the authoritative `active` pointer to differ from the target and `sealed/<generation>` to be absent in the same transaction as each bounded deletion batch. The plan-time seal digest and the restart audit digest must match exactly and change on any order/by-key/by-index key or value mutation.

A mined commit with duplicate keys in one batch, or a key already committed by its parent, must fail before changing any tree. Reorganization A to B to A must replace the index and accumulator exactly and reload successfully each time.

Release acceptance additionally requires the active V3 rules preimage to name the accumulator and membership schema and a fresh exact rules hash/genesis fixture. A database carrying V1, V2, or an interim V3 profile must fail closed without namespace creation or mutation.

## Idempotence and Recovery

All tests use temporary sled databases and may be rerun safely. The migration deliberately provides no in-place conversion from legacy marker rows, the former set-sorted root, or interim V2 membership trees. If startup detects old or partial state, preserve it unchanged and instruct the operator to use a new V3 base path.

If a sled transaction reports failure, do not publish the candidate `NativeState`. If the transaction commits but its durability barrier or readback is uncertain, poison native storage and stop further writes; recovery is an operator restart from a verified database or a fresh sync, not a silent retry.

Do not use destructive Git commands in this shared worktree. Concurrent header, transport, admission, and group-commit changes belong to their owners. Coordinate shared signatures, retain their new fields, and adapt only accumulator-specific callers after handoff.

## Artifacts and Notes

Current green evidence:

    protocol-shielded-pool: 11 passed; 0 failed
    protocol-kernel: 6 passed; 0 failed
    synthetic-crypto BLAKE2b-384 KAT/framing: 1 passed; 0 failed
    hegemon-node nullifier_accumulator::tests: 9 passed; 0 failed
    Lean schema-2 exact vector consumer: 1 passed; 0 failed
    hegemon-node canonical_membership::tests: 12 passed; 0 failed (isolated latest run; rerun required after outer integration)
    indexed reload/restart/corrupt-state/startup namespace exact tests: passed
    cargo check -p hegemon-node --lib: passed (unrelated warning remains)

## Interfaces and Dependencies

`protocol_shielded_pool::PersistentKeySet48` must retain these operations:

    pub const fn new() -> Self
    pub const fn len(&self) -> usize
    pub fn contains(&self, key: &[u8; 48]) -> bool
    pub fn insert(&mut self, key: [u8; 48]) -> bool
    pub fn remove(&mut self, key: &[u8; 48]) -> bool
    pub fn iter(&self) -> PersistentKeySet48Iter<'_>

`node::native::nullifier_accumulator::NullifierAccumulator` must retain a checked constructor, `leaf_count`, `root`, `append`, `append_all`, exact codec, and measured test interface. Production callers must never receive mutable access to its peaks.

The integrated `NativeState` must keep `nullifier_accumulator: NullifierAccumulator` and a bounded `CanonicalMembershipViews48`, not full-history `PersistentKeySet48` fields. `CanonicalMembershipIndexes48::from_open_trees` receives the exact seven preflighted tree handles and one shared `CanonicalMembershipEpoch`. `CanonicalMembershipSnapshotV3` has no variable-size fields and exact SCALE sizes of 100 bytes without an active WAL or 156 bytes with one; its tip binding is the raw 48 bytes of `BlockId48`. Pending nullifiers and bridge replay keys remain separate bounded derived indexes so admission rejects conflicts without scanning pending actions.

No new external crate is required. Production hashing uses the existing `blake2`, plus existing `alloc`, `serde`, `serde_json`, sled transaction, and Lean toolchain dependencies. The independent node-test oracle has its own direct `blake2` dev-dependency so it does not call the production framing helper.

Revision note (2026-08-17): Updated after the RFC7693-BLAKE2b-384 accumulator migration, schema-2 formal integration, V3 disk-authoritative membership/WAL implementation, startup namespace hardening, and same-machine performance measurements. Outer state/open/reorg integration and final global rules/genesis pins remain deliberately deferred to the coordinated V3 identity freeze.
