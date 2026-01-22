# DA Sidecar + Hot Availability: Make Ciphertexts Retrievable Without Bloated Blocks

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Make Hegemon usable for high-throughput private commerce by moving large ciphertext payloads out of the Substrate block body into a “DA sidecar” (a separately distributed blob of data), while still enforcing that the data is available for wallet sync.

This plan delivers two user-visible outcomes:

1. Nodes can accept blocks without embedding all ciphertext bytes in the block body.
2. Wallets can still discover and decrypt incoming notes because ciphertexts are retrievable via DA chunk requests during a configured “hot retention window.”

The “it works” proof is:

- A dev node mines a block where shielded transfer extrinsics do not carry ciphertext bytes.
- The block header commits to the ciphertext sidecar via `da_root`.
- `da_getChunk(da_root, index)` returns chunk bytes + Merkle proof for recent blocks.
- A fresh wallet can sync and decrypt new incoming notes by fetching ciphertexts through RPC that is backed by the DA store, not by block bodies.

This plan keeps post-quantum security intact. It does not change ML‑KEM‑1024. It treats bandwidth and storage as explicit protocol resources instead of accidental block bloat.

## Progress

- [x] (2026-01-21T00:00Z) Draft DA sidecar + hot availability ExecPlan (this file).
- [x] (2026-01-22T18:56Z) Record baseline DA parameters and limits (chunk size, sample count, max blob size) with concrete evidence.
- [x] (2026-01-22T19:04Z) Define and implement “multi-page DA encoding” so blocks can commit to blobs larger than 255 shards.
- [x] (2026-01-22T20:10Z) Make ciphertext bytes bind to transaction validity via ciphertext hashes (prevent miner ciphertext tampering).
- [x] (2026-01-22T20:55Z) Replace in-memory DA stores with a persistent store + pruning for a hot retention window.
- [x] (2026-01-23T00:00Z) Modify block production/import to use DA sidecars (ciphertexts are no longer in the block body).
- [x] (2026-01-23T00:00Z) Update wallet RPCs to fetch ciphertexts from DA store.
- [ ] End-to-end demo: mine a block, fetch chunks, sync wallet, decrypt note.

## Surprises & Discoveries

- Observation: The current DA encoder (`state/da`) uses 8-bit Reed–Solomon with `MAX_SHARDS = 255`, so a single DA-encoded blob cannot exceed ~170 data shards (the rest are parity), which is small at the current `daChunkSize = 1024`.
  Evidence: `state/da/src/lib.rs` defines `MAX_SHARDS: usize = 255`, `chunk_size` defaults to 1024, and parity is `ceil(data_shards/2)`.

- Observation: The node currently stores DA encodings only in memory with a small capacity (default 128 roots), which is not a “retention window.”
  Evidence: `node/src/substrate/service.rs` defines `DaChunkStore` as an in-memory LRU with `DEFAULT_DA_STORE_CAPACITY = 128`.

- Observation: Chain properties for dev set `daChunkSize = 1024` and `daSampleCount = 80`, which implies very aggressive sampling relative to the maximum shard count of 255.
  Evidence: `config/dev-chainspec.json` under `properties`.

- Observation: With `MAX_SHARDS = 255` and parity `ceil(k/2)`, the maximum data shards is 170, so at `daChunkSize = 1024` the largest single-page blob is 174,080 bytes.
  Evidence: `state/da/src/lib.rs` (`MAX_SHARDS = 255`, parity `ceil(k/2)`), computed locally with a short script.

## Decision Log

- Decision: Introduce “multi-page DA encoding” rather than trying to lift the 255-shard ceiling directly.
  Rationale: The current Reed–Solomon backend is limited to 255 shards by construction. For world-scale throughput we need blobs that are orders of magnitude larger. Segmenting into pages keeps code simple and keeps Merkle proofs small; the top-level `da_root` can commit to a Merkle root of page roots.
  Date/Author: 2026-01-21 / Codex

- Decision: Bind ciphertext bytes to transaction validity via per-ciphertext hashes that are checked during block import.
  Rationale: If ciphertext bytes are not committed and checked, block producers can tamper with ciphertexts (especially for unsigned shielded transfers) and make recipients unable to recover funds. Binding ciphertext hashes to the proof statement (and checking hash(ciphertext_bytes) == ciphertext_hash) prevents this without doing expensive in-circuit hashing.
  Date/Author: 2026-01-21 / Codex

- Decision: Treat “hot availability” as an enforceable consensus rule for a bounded time window, and treat multi-year storage as a separate “cold archive” product.
  Rationale: Forcing every consensus node to store years of ciphertexts is how chains centralize and die. The protocol must guarantee enough availability for offline receivers (hot window), and then allow optional markets for longer retention.
  Date/Author: 2026-01-21 / Codex

- Decision: Canonicalize ciphertext hashes as 48-byte field encodings derived from BLAKE3-384 limbs.
  Rationale: Transaction public inputs are field elements; mapping BLAKE3-384 output into canonical 48-byte encodings keeps STARK public inputs valid while preserving domain-separated hash binding to ciphertext bytes.
  Date/Author: 2026-01-22 / Codex

- Decision: Persist DA encodings in a sled-backed store keyed by block number/hash with retention pruning, plus a small in-memory cache for proofs.
  Rationale: The hot window must survive restarts and support wallet sync while keeping disk bounded; the cache avoids re-decoding on every chunk request.
  Date/Author: 2026-01-22 / Codex

- Decision: Include `da_root` explicitly in the `submit_commitment_proof` extrinsic.
  Rationale: Importers need the DA root before they can fetch sidecar bytes; the proof bytes alone do not expose public inputs.
  Date/Author: 2026-01-23 / Codex

## Outcomes & Retrospective

Not started. Update after the first end-to-end DA sidecar demo.

## Context and Orientation

What exists today:

- DA encoding and Merkle proofs: `state/da/src/lib.rs` implements `encode_da_blob`, `DaEncoding::proof`, and `verify_da_chunk`.
- DA chunk networking: `node/src/substrate/network_bridge.rs` defines `DaChunkProtocolMessage` request/response.
- DA RPC: `node/src/substrate/rpc/da.rs` exposes `da_getChunk` for chunk+proof retrieval.
- DA sampling during import exists (see the block import handler in `node/src/substrate/service.rs`), but today the DA blob is derived from block extrinsics; that makes it redundant.

What we need for “DA sidecar”:

- The block header must commit to a `da_root` that corresponds to ciphertext bytes that are *not* carried inside the block body.
- Nodes must be able to retrieve ciphertext bytes from peers by `da_root` and prove they match the commitment.
- Nodes must store ciphertext bytes for at least the hot retention window so wallets can sync.

Define “multi-page DA encoding” precisely (this plan uses these terms):

- A “page” is a byte slice of the overall ciphertext blob, small enough that `encode_da_blob(page, params)` is valid under the 255-shard constraint.
- A “page root” is the `DaRoot` returned by `DaEncoding::root()` for that page.
- The “block DA root” is a single 48-byte root that commits to the ordered list of page roots. It is computed as a Merkle root over the page roots using the same `da-node`/`da-leaf` domain tags, treating each page root as leaf data.

This “root of roots” keeps the existing header format (still one 48-byte `da_root`) while allowing arbitrarily large ciphertext blobs.

## Plan of Work

### Milestone 1: Implement multi-page DA encoding in `state/da`

Goal: support DA commitments for blobs larger than 255 shards without changing the header size.

Work:

- Add a new type (example name) `DaMultiEncoding` in `state/da/src/lib.rs` that:
  - splits a blob into pages (by maximum data length per page derived from params and the 255-shard rule),
  - creates a `DaEncoding` per page,
  - and builds a Merkle root over the page roots as the block-level `da_root`.
- Add a “global chunk index” scheme so that a chunk request `(da_root, global_index)` can be mapped to `(page_index, chunk_index_within_page)`.
  - Keep it simple and deterministic: define `global_index = page_index * MAX_SHARDS + chunk_index`.
  - Define `MAX_SHARDS` as 255 at the protocol level for this scheme; it is already in the code.
- Add `DaMultiEncoding::proof(global_index)` that returns a proof containing:
  - the page chunk proof (existing `DaChunkProof` for that page),
  - and the page-root Merkle path proving that page root is part of the block-level root.
- Add `verify_da_multi_chunk(da_root, proof)` that verifies both layers.

Acceptance:

- New unit tests in `state/da` that:
  - encode a blob large enough to require multiple pages,
  - verify random chunk proofs,
  - and fail when either the chunk data or either Merkle path is corrupted.

### Milestone 2: Bind ciphertexts to transaction validity via ciphertext hashes

Goal: prevent block producers from swapping or corrupting ciphertext bytes without being detected by block validity rules.

Work:

- Extend the shielded transfer public inputs to include a list of `ciphertext_hashes`, one per output note. A “ciphertext hash” is `BLAKE3-384(ciphertext_bytes)` (48 bytes), domain-separated (for example: prefix `b"ct-v1"`).
- Update the wallet transaction builder so it computes and includes these hashes when creating a transfer.
- Update verification code so that during block import, the node checks that each ciphertext bytes blob (from DA) matches the corresponding `ciphertext_hash` in the transaction’s bound public inputs.

Important constraint:

- Do not hash ciphertext bytes inside the ZK circuit. We bind hashes as public inputs and check hash preimages in native code during block import.

Acceptance:

- A dev transaction with a corrupted ciphertext bytes blob is rejected at block import time because `hash(ciphertext_bytes) != ciphertext_hash`, even if the proof and commitments are otherwise valid.

### Milestone 3: Persist DA sidecar data for a hot retention window

Goal: replace the current in-memory DA stores with a real retention mechanism.

Work:

- Introduce a persistent DA store (RocksDB column family or a simple file-backed store) keyed by:
  - `(block_hash -> da_root)`,
  - `(da_root, page_index, chunk_index) -> chunk_bytes`,
  - and optionally `(da_root, page_index) -> page_encoding_metadata` needed to serve proofs.
- Add pruning logic: keep the last `R_hot` blocks’ DA data (configurable; start with a simple “keep last N blocks”).
- Update `da_getChunk` RPC and DA chunk P2P responses to source proofs from the persistent store.

Acceptance:

- On a dev node, after mining > `R_hot` blocks, chunks from older blocks are pruned and `da_getChunk` returns `None` for those roots, while recent blocks still succeed.

### Milestone 4: Move ciphertexts out of block bodies (introduce a true sidecar)

Goal: shielded transfer extrinsics no longer carry ciphertext bytes; ciphertext bytes live only in the DA sidecar committed to by `da_root`.

Work:

- Define a new extrinsic format for shielded transfers that includes:
  - the proof,
  - nullifiers and commitments,
  - and ciphertext hashes (and any other metadata needed for wallet indexing),
  - but not the ciphertext bytes themselves.
- Update wallet submission code so it sends ciphertext bytes to the node as an out-of-band “blob” that the node stores into the DA sidecar store.
- Update block authoring so that when building a block, the author:
  - selects shielded transfer extrinsics,
  - assembles the corresponding ciphertext bytes from the sidecar input pool into the block’s DA blob,
  - computes the multi-page `da_root`,
  - and writes `da_root` into the header.
- Update block import so it:
  - retrieves all ciphertext bytes required to serve wallets and to check ciphertext hash bindings (during initial development, it is acceptable for full nodes to fetch all ciphertext bytes for new blocks),
  - verifies the multi-page DA root,
  - and stores the data into the hot DA store.

Acceptance:

- Inspecting a block body shows ciphertext bytes are not present in extrinsics.
- `da_root` is non-zero and `da_getChunk` can serve proofs.
- Wallet sync still returns ciphertexts through RPC for recent blocks.

## Concrete Steps

From the repository root:

0. If this is a fresh clone, install toolchains first:

    make setup

1. Build and run tests for DA encoding:

    cargo test -p state-da

2. Confirm current DA settings and block parameters:

    rg -n \"daChunkSize|daSampleCount\" config/dev-chainspec.json
    rg -n \"RuntimeBlockLength|PowTargetBlockTime\" runtime/src/lib.rs

3. Run a dev node and confirm DA RPC is wired:

    make node
    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

    In another terminal:
      curl -s -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"da_getParams\"}' http://127.0.0.1:9944

4. After implementing the sidecar milestones, run the end-to-end demo and record the log excerpts and RPC responses here.

## Validation and Acceptance

Final acceptance for this plan:

1. Blocks commit to ciphertext bytes via a `da_root` that is computed from data not present in the block body.
2. Nodes can retrieve DA chunks from peers and verify them with Merkle proofs.
3. Nodes retain DA data for the hot retention window and serve it via RPC to wallets.
4. Ciphertext bytes are bound to transaction validity via hashes and cannot be tampered without block rejection.

## Idempotence and Recovery

- Multi-page DA encoding should be purely functional: encoding the same blob twice yields the same root and the same proofs.
- The persistent DA store must be safe to wipe for dev (`--tmp`), and the plan must include how to reset it.
- During the migration where both “ciphertexts in block” and “ciphertexts in sidecar” exist, keep both code paths working behind a feature flag to avoid breaking devnet tooling mid-iteration.

## Artifacts and Notes

Record here as indented blocks:

- A multi-page encoding test output showing a blob spanning >1 page.
- A `da_getChunk` RPC response from a real mined block.
- A rejection log for a block whose ciphertext bytes do not match committed hashes.

## Interfaces and Dependencies

At the end of this plan, the repo must have:

- A `state/da` API for multi-page roots and multi-layer chunk proofs (example):
  - `encode_da_blob_multipage(blob, params) -> DaMultiEncoding`
  - `DaMultiEncoding::root() -> DaRoot`
  - `DaMultiEncoding::proof(global_index) -> DaMultiChunkProof`
  - `verify_da_multi_chunk(root, proof) -> Result<(), DaError>`
- A node-level persistent DA store with pruning keyed by block number/hash.
- A wallet RPC path that sources ciphertexts from DA storage, not from block extrinsic bytes.
