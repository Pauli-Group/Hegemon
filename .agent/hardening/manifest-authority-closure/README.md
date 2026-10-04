# Manifest authority closure screen

Verdict: **Merkle membership dominates a fixed-cap full-manifest witness, but
no candidate here is production-authorized.** W56 is the smallest
source-exact cost boundary and is now disqualified by strict composition: the
conservative two-input, `2^32`-proof epoch secret-prefix hybrid is `2^-126`,
not at most `2^-128`. W64 has the same selected-path hash count and is the
minimum width surviving this screen, but it remains conditional on an explicit
BLAKE2b-512 QRO instantiation and every other proof/consensus gate.

## Three surfaces that must not be conflated

`compat183` is the exact current-kernel compatibility row. Its byte layout is:

    0..4     asset_id:u32le
    4..8     oracle_feed:u32le
    8..16    attestation_id:u64le
    16..32   min_collateral_ratio_ppm:u128le
    32..48   max_mint_per_epoch:u128le
    48..56   oracle_max_age:u64le
    56..64   oracle_submitted_at:u64le
    64..72   enabled_at:u64le
    72       retired_present:u8
    73..81   retired_at:u64le (zero iff absent)
    81..85   policy_version:u32le
    85       active:u8
    86..134  oracle_commitment48
    134..182 attestation_commitment48
    182      attestation_disputed:u8

The policy hash is independently recomputed with the live 140-byte framed
BLAKE2b-384 constructor. The two stored 48-byte values are only compared for
equality by scalar, M4, and native admission; no oracle or attestation preimage
constructor exists in the inspected current sources. A wider manifest root
cannot increase their collision authority. Therefore this route is an exact
compatibility closure and cost baseline, never a fully qualified destination.

`fresh-v2/W56` is a separate prospective 199-byte row. Bytes `0..86` are
unchanged, `86..142` is `oracle_commitment56`, `142..198` is
`attestation_commitment56`, and byte `198` is the dispute flag. Its policy
identity is BLAKE2b-448 over the exact 61-byte tuple with a role/width-specific
RFC 7693 personalization. It is smaller than W64 but disqualified by the
`2^-126` composition result.

`fresh-v2/all-W64` is the minimum-width surviving source candidate. It is
exactly 215 bytes: bytes `0..86` are unchanged, `86..150` is
`oracle_commitment64`, `150..214` is `attestation_commitment64`, and byte `214`
is the dispute flag. Its policy, oracle, attestation, leaf, node, root, and
snapshot constructors all use 64-byte outputs with width-bound
personalizations. It is still conditional, not production-qualified.

No row is converted by padding, truncation, or hashing an old digest. Moving
from live48 to W56, or W56 to W64, requires rerunning the selected constructor
over its canonical source at a fresh genesis or explicitly activated state
transition. Every direct conversion rejects.

## Canonical cap-16 Merkle grammar

Rows are strictly increasing by numeric `(asset_id:u32, policy_version:u32)`.
An exact duplicate and a different row with the same key both reject. A state
writer must reject a noncanonical old vector; sorting or deduplication during
migration is forbidden.

A leaf is `present:u8 || row`. Present is exactly zero or one. Present leaves
form a prefix. An empty leaf is the all-zero slot: 184 bytes for `compat183`,
200 bytes for W56 V2, and 216 bytes for all-W64 V2. Each leaf hashes in two
BLAKE2b compressions. The depth-four tree uses one compression per internal
node. Leaf, full-vector, snapshot, and all four node levels use distinct exact
16-byte personalizations:

    "HGMAROOT" || role:u8 || row_profile:u8 || width:u8 ||
    log2(cap):u8 || level:u8 || 0x000000

The selected witness is `index:u32le || row || sibling[0..4]`, exact
consumption only. The transaction profile fixes row grammar, width, cap,
version, and domains; none is prover-selected.

## Exact source-static cost comparison

These counts apply the pinned odd-field Boolean R1CS macros: one BLAKE2b
compression is 576 64-bit additions, 403 word XORs, 136,384 R1CS rows, 99,520
derived variables, and 570,752 matrix nonzeros. M4 counts are source-static,
before compiler DCE. They are not proof-byte measurements.

| Row/root profile | Mode | Relation compressions | Semantic witness | M4 words | Exact macro-R1CS rows |
|---|---:|---:|---:|---:|---:|
| compat183 / W56 | Merkle | **8** = policy 2 + leaf 2 + path 4 | 411 B | 52 | 1,100,277 |
| compat183 / W56 | Full vector | 25 = policy 2 + root 23 | 2,948 B | 369 | 3,485,843 |
| compat183 / W64 root | Merkle | 8 | 443 B | 56 | 1,101,301 |
| V2 row199 / W56 | Merkle | 7 = policy 1 + leaf 2 + path 4 | 427 B | 54 | 964,085 |
| V2 row199 / W56 | Full vector | 26 = policy 1 + root 25 | 3,204 B | 401 | 3,628,307 |
| V2 row199 / W64 root-only screen | Merkle | 7 | 459 B | 58 | 965,109 |
| V2 row215 / all-W64 | Merkle | **7** | 475 B | 60 | 965,301 |
| V2 row215 / all-W64 | Full vector | 28 = policy 1 + root 27 | 3,460 B | 433 | 3,907,411 |

Holding row199 fixed, changing only the Merkle/root identity W56 to W64 adds
exactly 32 path bytes, eight public bytes, four M4 words, and 1,024 R1CS rows,
with no new compression. Fully widening the row authorities as well adds 48
witness bytes, eight public bytes, six M4 words, and 1,216 rows relative to the
row199/W56 screen. The stablecoin statement's three identities add 24 bytes.

At cap 16, building a complete Merkle state root costs 32 leaf plus 15 node
compressions = 47; an incremental selected-leaf update costs 2 + 4 = 6. The
transaction relation repeats only the selected leaf/path and policy identity.
The optional state snapshot is one separate compression.

## Constructor proposal and authority boundary

The reference fixes executable prospective source grammars so their byte and
compression costs are not hand-waved:

    oracle = asset_id:u32le || policy_version:u32le || oracle_feed:u32le ||
             submitted_at:u64le || source_id:[u8;32] || payload_len:u16le ||
             canonical_observation_payload[1..4096]

    attestation = asset_id:u32le || policy_version:u32le ||
                  attestation_id:u64le || created_at:u64le ||
                  issuer_id:[u8;32] || payload_len:u16le ||
                  canonical_attestation_payload[1..4096]

Policy construction is one compression. Oracle and attestation construction
each cost `ceil((54+n)/128)` and `ceil((58+n)/128)` respectively: one to 33
compressions at the fixed payload cap. These constructors belong to the
consensus state writer, not the per-transaction membership relation.

The current oracle and attestation subsystems do not own, implement, or refine
these grammars. Consequently constructor authority remains false even though
the proposal and KATs are executable. The live48 fields remain proven
equality-only.

## Parent-state authentication is outside membership

The proof-public suffix is exactly `manifest_root_W || parent_height:u64le`.
In-relation logic recomputes selected membership and stablecoin lifecycle at
that height. Before proof verification, the native verifier must obtain the
typed root and height from authenticated canonical parent state and compare
both exactly. That outer comparison is not a Merkle constraint and cannot be
self-asserted by the prover. Mempool reload, mining, block import, sync,
restart, and reorg must repeat the same parent-state comparison.

The executable checker covers all 16 paths, every byte of rows 183, 199, and
215, every sibling level, index direction, root, public height, parent root,
parent height, snapshot, order, duplicate, empty padding, presence, width,
trailing, truncation, and constructor-source mutations. Retained JSON is
canonical and byte-checked.

Production remains fail-closed: no current state writer/global-root migration,
oracle/attestation constructor authority, explicit W64 QRO instantiation,
composed proof-system bound, complete-ZK proof, compiled geometry, formal/Rust
refinement, retained proof, measured proof bytes, or release manifest exists.
