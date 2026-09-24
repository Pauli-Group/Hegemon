# Evidence context

## Assets reviewed

The audit read the repository instructions and architecture/method documents, the living standalone mixed-field ExecPlan, the retained M4/Boolean prototypes, the pinned Binius M4/BaseFold sources, the 115 KiB `complete_zk.rs` interface inventory, the E384 VEIL rank audit, and the SmallWood QROM-accounting material. It made no change to those sources or shared documents.

The decision-critical implementation facts are:

- Pinned Binius `fri/encode.rs:84-96,132-170` constructs a random mask of the same length and encodes the concatenation `message || mask` with batch size two.
- `merkle_channel.rs:215-245` serializes every scalar in a selected leaf; `248-258` serializes the complete terminal vector.
- `m4-prover/src/composite.rs:200-204` describes the composite proof as transparent and selects `create_channel_without_zk_from_transcript`.
- The retained `complete_zk.rs:1608-1624` defines a witness-free whole-view simulator interface, but `2362-2379` leaves every theorem/implementation premise and authorization false.

`source-manifest.json` binds the exact local files used.

## Claim boundary

The executable model establishes finite-dimensional identities and a concrete information-theoretic counterexample. It does not claim to formalize Rust semantics, prove SHA-512 collision resistance, prove a QROM Fiat–Shamir theorem, or implement a new PCS. The byte totals are exact for the named retained synthetic serializer geometry and the named direct-mask payload; they are not measurements and not an exact Hiding-WHIR/M4 proof size.

## Constraints honored

- conventional SHA-512/SHAKE256-512 only as eligible cryptographic hashes;
- no ECC, pairings, RSA, Poseidon validity, sidecars, aggregation, receipts, or caches;
- no build or proof runs;
- no production flags or shared documents changed;
- all outputs confined to this directory.

