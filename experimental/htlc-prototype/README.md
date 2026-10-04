# Isolated HTLC development prototype

This standalone crate supplies an actually checked SHA-256 hashlock circuit for exactly 32-byte secrets and executable host reference semantics for a future shielded HTLC. It is isolated from the production workspace at baseline `47072042`; no live transaction, proof metadata, formal endpoint, configuration or node path is changed.

A second completed increment adds witness-independent field lowering and the nested [`proof-backend`](proof-backend/README.md) native SmallWood source facade. A real private SHA-256 preimage-equality component proof, with public context binding, was generated and verified, including fresh-process readback and an unchecked invalid-witness engine test. Its measured 311,938 bytes exceed the unchanged 164,113-byte production cap. See [`proof-backend/MEASUREMENTS.md`](proof-backend/MEASUREMENTS.md) for exact evidence and exclusions.

Run from this directory with cached dependencies:

```sh
CARGO_TARGET_DIR=/private/tmp/hegemon-htlc-target-20261002 CARGO_BUILD_JOBS=1 cargo test --offline --locked -- --nocapture
CARGO_TARGET_DIR=/private/tmp/hegemon-htlc-target-20261002 CARGO_BUILD_JOBS=1 cargo clippy --offline --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

The standalone `[workspace]` keeps these commands independent of the parent workspace. The pinned sha2 dependency is an independent differential oracle for the gadget and a host commitment hash for the reference relation. The constraint checker does not invoke sha2 or the witness evaluator.

## SHA-256 gadget

`hashlock::Sha256Hashlock::new()` builds a fixed circuit. `evaluate(&preimage)` proposes an assignment. `verify(&preimage, &expected_digest, &assignment)` independently enforces every equation, each wire's Boolean domain, the 256 input bits and 256 digest output bits. `digest(&assignment)` only extracts proposed digest bytes; it is not a substitute for `verify`.

The circuit handles one SHA-256 compression block: the 32-byte message, mandatory `0x80` padding, zeros, and a big-endian 64-bit length of 256 bits. All initialization, round and padding bits reference two constrained constants. Message schedule, 64 rounds and feed-forward use explicit Boolean equations. Bit rotations are wiring permutations and logical shifts insert the zero wire. Additions use parity/majority carry equations and discard the final carry for addition modulo 2^32. XOR is quadratic; three-input parity and majority are cubic ordinary integer Boolean polynomials. The field lowering in `src/lowering.rs` enforces canonical-wire Booleanity, packed gate equations and occurrence-copy equalities; its measured cost is recorded in the nested backend's measurement report.

Each input has an input pin; each other wire has exactly one defining gate. Every assignment must have the exact circuit wire count, and byte-valued supplied values above 1 reject. Circuit topology and output-wire selection are private and independent of witness values.

Measured circuit counts:

| Item | Count |
| --- | ---: |
| Assignment wires / Boolean-domain constraints | 55,466 |
| Constant equations | 2 |
| NOT equations | 2,048 |
| XOR equations | 2,048 |
| AND equations | 4,096 |
| Three-input parity equations | 26,368 |
| Three-input majority equations | 20,648 |
| Total defining-gate equations | 55,210 |
| Input pin equations | 256 |
| Digest output pin equations | 256 |
| Total Boolean IR constraints | 111,188 |

These are counts of this explicit standalone IR. They are not RP05 rows or evidence that the HTLC fits any existing proof/carrier cap. The nested component proof has its own measured lowering and byte counts; no proof of the complete HTLC reference relation has been generated. The experimental SHA-256 commitment/nullifier constructions inherit no production PQ128 security claim; no composed post-quantum security bound has been established here.

## HTLC reference semantics

`relation::LockedNote` is the private opening of a domain-separated versioned commitment. It commits policy version, SHA-256 digest, claim authority, refund authority, Hegemon timeout height, asset, value, note ID and private nullifier key. The local nullifier hash uses that same private key, note ID and commitment in both branches, independently of branch, signer, and spend intent. Changing the key changes the opened note and fails the original commitment check. This is an experimental host construction, not a change to Hegemon's production note/nullifier hash.

`SpendIntent` is an exact fixed-width single-output same-asset transfer intent: network ID, recipient commitment, asset, output value, fee and operation nonce. The host reference checks positive locked/output value and checked `output_value + fee == locked_value`. Fees in this prototype are in the locked asset; this does not define production fee semantics. The model has no issuer, stablecoin extension or mint/burn route.

`check_spend` opens the exact locked-note commitment, checks the shared nullifier and intent, obtains authenticated chain context, verifies the selected branch and asks the external authorizer to verify evidence. Its authorization message commits the note commitment, nullifier, branch, complete intent commitment, network ID, parent hash and parent height. Transitively the note commitment binds all policy/asset/value/authority/timeout fields. It never publishes or inserts the preimage into the authorization transcript.

A claim requires a 32-byte preimage, its valid SHA assignment matching the committed hashlock, and authorization by the committed claim authority. Claim validity has no timeout expiry. A refund requires authorization by the committed refund authority and authenticated Hegemon parent height at least the committed timeout. At and after timeout, both branches can be individually valid and race to consume the same nullifier. The unit-test ledger exercises both first-spend orders and rejects both subsequent paths after consumption.

## Explicit trust and scope boundaries

`Authorizer` is the external cryptographic authorization interface: its implementation must validate exact committed authority/key identity, exact message, canonical evidence and signer possession. The tests use an explicit matching authority/message receipt fixture; that fixture is not a signature scheme and supplies no signature or PQ security evidence. There is no untrusted caller-supplied authorization-valid Boolean.

`AuthenticatedChain` is the external consensus state interface: its implementation must authenticate the network/parent hash/height, validate locked-note inclusion, and check the nullifier remains unspent in that same context. Node admission must recheck and atomically consume against current state. The tests use an in-memory authenticated-context fixture and spent set. They do not establish live consensus authentication, transaction inclusion, concurrency safety, mempool policy, restart durability or reorg behavior.

The complete HTLC reference relation remains host code. Only the 32-byte SHA-256 preimage equality has explicit gate constraints here. Note/intent/nullifier commitment hashes, version/balance/timelock/authorization/context rules are not compiled into a proof. The prototype passes private opening/preimage to a local checker and makes no zero-knowledge or deployed privacy claim.

No live successor transaction relation, production transaction proof generation, Rust-to-Lean refinement, release qualification, activation, production feature switch, node lifecycle validation or Bitcoin connector is included. The independent unchanged-byte proof path through wallet/RPC, relay, mempool, mining, blocks, sync, restart, reorg and fresh nodes remains a future integration obligation. A future swap flow should make Hegemon the longer-refund leg: reveal the secret on Bitcoin, then consume it privately on Hegemon after proof integration. Time margins must use authenticated per-chain contexts and conservative elapsed-time assumptions; comparing raw block heights across chains is invalid. This prototype does not establish an atomic swap or make Bitcoin quantum secure.

## Checked evidence

Tests compare 68 fixed/reproducible random 32-byte vectors against sha2, including an independently pinned all-zero known digest. They reject a single flipped wire and a non-Boolean value at every one of the 55,466 assignment positions. The exhaustive negative tests rotate the same full checker's gate traversal to the changed wire's defining equation to avoid quadratic work; successful verification still checks every gate and every wire's Boolean domain. Another 215 internal-wire flips use the ordinary public `verify` traversal. Input/output pin mismatch, truncated/extra assignments and all eight Boolean full-adder input cases are also checked.

Reference tests cover claim before/at/after timeout, refund maturity, wrong preimage/assignment, each committed note field, branch-specific key substitution, shared nullifier races, wrong authority/branch/receipt, recipient/nonce/asset/network/value/fee intent changes, parent hash/height changes, unauthenticated context, missing note, spent state, zero values and arithmetic overflow.

Exact test and lint results are recorded in `EXECPLAN.md`. The original locked test run passed nine tests in 0.92 seconds; the second increment passed all eleven tests in 1.37 seconds, including four packing geometries and field-Booleanity negatives. Parent-crate clippy passed with warnings denied and formatting passed. The separate small build directory occupied 22 MiB; the isolated native facade release target occupied 306 MiB. No node or production build was started.
