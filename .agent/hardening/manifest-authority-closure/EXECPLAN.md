# Close the HX448C02 manifest-authority boundary without activation

This is a living source-only ExecPlan under `.agent/PLANS.md`. It owns only
this directory. No Cargo, rustc, Lake, proof build, dependency install, or
production route is permitted while the repository disk gate is closed.

## Purpose

The frozen `HX448C02` M4 inventory has four host-only predicates: exact
61-byte policy-identity hashing, whole-manifest hashing, selected-entry
membership, and authentication of the verifier's expected root and height.
This plan specifies the smallest fixed successor surface that closes the first
three inside an exact relation and makes the fourth an explicit typed verifier
input comparison to parent consensus state. It must not pretend that a proof
can authenticate the chain state that defines its own public input.

## Current result

- [x] Inspected the scalar relation, M4 lowering, inactive kernel v1
  commitment, protocol manifest, and native stablecoin admission.
- [x] Froze the existing 183-byte entry row and 61-byte policy tuple, then
  separated it from prospective 199-byte W56 and 215-byte all-W64 V2 rows.
- [x] Defined separate fixed-cap full-vector and ordered-Merkle roots with
  native-output RFC 7693 BLAKE2b-448/512 and exact 16-byte personalizations.
- [x] Defined strict numeric `(asset_id, policy_version)` ordering, duplicate
  key rejection, prefix-present/full-slot semantics, and canonical empty
  leaves.
- [x] Implemented exact public/witness codecs, all-16-path membership,
  parent-state snapshot comparison, KATs, exhaustive 183/199/215-byte
  mutations, and a source-only Boolean/R1CS/M4 cost ledger.
- [x] Specified executable prospective oracle/attestation constructor grammars
  while keeping their current subsystem authority and refinement false.
- [x] Recorded the conservative W56 composed epoch failure probability
  `2^-126`, disqualified W56 from PQ128, and retained W64 only conditionally.
- [x] Kept concrete QRO instantiation, compiled geometry, formal refinement,
  release authorization, and production false.
- [ ] Port the selected relation into a fresh production identity only after
  the root task approves the architecture and the disk gate opens.

## Decision

Merkle membership is the architecture winner over a full-vector witness. For
the exact live row, W56 performs two compatibility-policy, two leaf, and four
path compressions: exactly eight versus 25 for the full vector. It uses 411
semantic witness bytes and 1,100,277 exact macro-R1CS rows.

W56 is only the smallest source-exact boundary: strict composition gives
`2^-126` for the conservative two-input, `2^32`-proof epoch secret-prefix
hybrid, so it is disqualified from PQ128. Holding a row fixed, W64 keeps the
same hash count but adds 32 path bytes, four M4 words, and 1,024 rows. W64 is
the minimum width surviving the current screen, conditional on a concrete
BLAKE2b-512 QRO instantiation.

The W56 V2 row is 199 bytes and also disqualified. A fully widened W64 V2 row
is 215 bytes and has a 475-byte selected witness, 60 M4 words, seven
compressions, and 965,301 exact macro-R1CS rows. This is a source architecture
result, not compiled geometry, proof-byte measurement, or production winner.

## Canonical semantics

The source vector must already be in strict numeric order by
`(asset_id:u32, policy_version:u32)`. Exact duplicates and two different rows
with the same key both reject. Migration rejects a noncanonical old vector; it
does not silently sort or deduplicate it. One slot is exactly
`present:u8 || row`; present is only 0 or 1. Empty is exactly 184, 200, or 216
zero bytes for the compatibility, W56 V2, or all-W64 V2 grammar. In a full
vector, present slots form a prefix and absent rows are zero. In the Merkle
tree, slot position commits order and each level has a distinct
personalization. Canonical global ordering is a state-writer obligation; a
selected path alone cannot prove absence of another duplicate.

The 48-byte live policy, oracle, and attestation fields remain exactly 48
bytes. The policy value is independently recomputed from the current framed
61-byte source. The compatibility W56 root is recomputed from the 183-byte
source rows, never from the old 48-byte manifest digest. The old inactive v1 digest
remains a compatibility KAT and is retired from successor validity. Padding,
truncation, or `H(new_domain || old_digest)` is forbidden at every
48 -> 56 -> 64 boundary. A new identity requires the canonical source.

The prospective V2 constructor sources use exact length-prefixed raw payload
grammars capped at 4,096 bytes. The reference checks them and produces W56/W64
KATs, but no current oracle or attestation subsystem owns those grammars. They
are therefore specifications, not constructor authority.

## Consensus boundary

The proof-public suffix is exactly `root_W || u64le(parent_height)`; the fresh
transaction identity fixes W, cap, version, and all personalizations. The
selected entry and its `log2(cap)` siblings are private proof inputs. The
relation recomputes membership and lifecycle at the public parent height.

Before invoking the proof verifier, native admission must obtain the typed
root and height from the canonical parent state, validate its snapshot
commitment, and require exact equality to the proof-public suffix. Mempool
reload and reorg paths rerun the same comparison. This verifier comparison is
not counted as in-relation Merkle membership. A fresh state writer and a
wider kernel/global-root migration are still absent, so production remains
closed.

## Validation

Run only:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/manifest-authority-closure/manifest_authority.py emit
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/manifest-authority-closure/manifest_authority.py check
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/manifest-authority-closure/test_manifest_authority.py
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/manifest-authority-closure/manifest_authority.py summary

Acceptance requires byte-identical retained JSON, all sixteen index paths,
all 183/199/215 row-byte mutations, every path/root/index/height mutation,
legacy KAT parity, constructor KATs, role/level/profile/width domain
separation, and all fail-closed flags.

## Remaining blockers

The native oracle and attestation commitments remain opaque 48-byte values,
and the prospective V2 source grammars have no authoritative owner,
implementation, activation, or refinement. W56 fails strict composition.
W64 has no explicit QRO instantiation. The composed proof-system bound,
complete-ZK proof, compiled M4/R1CS geometry, canonical state writer/global
root, sync/restart/reorg integration, Rust/formal refinement, retained proof,
and measured bytes also remain absent. None is assigned zero loss.
