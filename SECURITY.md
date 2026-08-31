# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to: support@pauli.group

Do NOT open public issues for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Block Validity Architecture

Any production-authorized shielded route must enforce **independent transaction
proofs plus deterministic consensus replay**:

1. **Transaction proofs**: The current candidate is one canonical SMZ9 proof of
   the HGV8RP03 Poseidon2 V8 relation per shielded transfer. Import must verify
   every proof independently in block order. The production capability registry
   currently returns `None`, so the route is not active.
2. **Block commitments**: The header binds the ordered action body, state roots,
   supply transition, and DA fields. Consensus recomputes those values while
   replaying the block.
3. **Ciphertext-DA commitment**: Full nodes receive the complete canonical
   block body, deterministically rebuild the erasure encoding of transfer
   ciphertext bytes, and require its exact metadata and Merkle root to match
   the PoW-bound header. `da_getChunk` serves an explicitly requested shard and
   opening, but the shipped node does not yet run an automatic randomized
   sampling protocol. Transaction-proof/action bytes are authenticated by the
   block-body locator and action root, not covered by this ciphertext-only
   erasure code.

The retained HGV8RP03 primary and independent proofs measure 122,735 and
122,607 bytes. Both cryptographically verify from the frozen 830-file source
inventory and survive the exact RPC, relay, mempool, mining, import, restart,
reorganization, and fresh-node replay fixture without changing proof bytes.
This is retained implementation evidence, not release authority; the source
capability and successor registry remain empty.

The old commitment-proof and recursive/aggregate authoring backends are not
executable. Retained recursive decoders have no production block-validity
authority. A coordinated release may authorize an exact inclusive historical
height range, but the production manifest currently authorizes none.

## Known Security Limitations

### Deterministic State Replay

- **State transition scope**: Note-tree updates, nullifier uniqueness, supply,
  and block-body commitments are deterministic consensus computations outside
  each transaction proof. The formal supply chain binds accepted transaction
  relations to the ordered block transition, while arbitrary compiled
  native-node refinement remains an explicit assumption.
- **Coinbase-only blocks**: Blocks with no shielded transactions are validated
  directly by the ordinary consensus and supply rules. The selected V8
  positive-value source is miner-local coinbase action `11`, which is valid
  only as the unique final block action after V8 activation and is rejected
  from RPC, peer relay, and the mempool. It remains inactive with the V8
  capability.

### Historical Recursive Proofs

Fresh blocks currently authorize no shielded-transfer proof profile. V4/Gamma
is historical only, and the SMZ9 Poseidon2 V8 route remains fail closed. If V8
is activated, each transfer will carry one independently verified proof and no
recursive, accumulated, receipt-root, or aggregate authoring artifact. The
historical `recursive_block_v2` decoder/verifier remains compatibility code;
native import cannot reach it without a separate release-owned height range,
and the production manifest contains no such range.
Plonky3 authoring crates, source modules, workspace members, and locked
dependencies have been removed. `scripts/check_native_runtime_dependencies.sh`
also fails if a Plonky3 package is reintroduced into a shipped binary graph.

### PQ Security Margins

- Note encryption and PQ transport handshake use ML-KEM-1024 (NIST Level 5) with 32-byte shared secrets.
- V8 ciphertext commitments use conventional BLAKE2b-384. Its note
  commitments, nullifiers, and Merkle roots are seven canonical Goldilocks
  limbs produced by the exact width-16 Poseidon2 relation. Concrete hash
  reductions for the shipped domains remain release blockers.
- The inactive SMZ9 V8 profile fixes `rho = 5`, six PIOP openings, `beta = 2`,
  a `2^23` DECS domain, twenty DECS openings, twenty independent 64-byte tapes,
  and `eta = 5`. Its exact maximum-shape proof projection is 122,863 bytes.
  V4/Gamma, V2/Beta, and V3/Beta remain historical; production configures no
  proof capability.

### Soundness Accounting (Engineering Estimate)

For this repository we track soundness as the minimum of (a) hash-based binding
security for the exact commitment and Fiat-Shamir domains and (b) the SmallWood
PCS/PIOP/DECS soundness terms for the exact candidate statement geometry.

The deterministic 31,956-byte HGV8RP03 source-security diagnostic has SHA-512
`4308fb56c68be761de1f2db8411e26fb5f0addeaa279f52a10e245b5a23b727112fecc9401969305a00c2858ca4c2e8a179a033affaf7b46ea606c0857350fee`.
It records a 288-bit interactive floor, a 157-bit ideal composition floor for
one global `2^64` quantum-query budget, and a 136-bit union over the exact
2,138,112-proof finite screen before external losses. Four external per-proof
terms each need at least 152 bits to retain a conditional 128-bit result over
that screen. Those bounds are conditional: the report explicitly records
`production_eligible=false` and no deployed floor.

The deterministic 2,963-byte executable zero-knowledge refinement report has
SHA-512
`df0b7a7e09b46b79bac097c08bcf947fe012a8514d3b6b8c638a0387323919120710f6f834e6b5563ee2f5da533104f985a6059929a716645c0a19051d1e8907`.
It verifies exact executable ROM replay and honest-map dimensions without using
witness words. It is refinement evidence, not the missing adaptive
repeated-proof zero-knowledge theorem or global SHA-512 QROM lifetime theorem.

The Lean cryptography package proves an exact finite-QROM extraction statement
for an ideal logical-oracle game. Its block-supply theorem is separate and
requires caller-supplied per-proof extraction success, exact-map-to-canonical
semantic refinement, and Poseidon2 constraint-digest/no-collision evidence.
No theorem constructs those premises from arbitrary compiled Rust acceptance
or transfers the ideal bound to deployed domain-separated SHA-512. The indexed
formal authority API therefore has no deployed-end-to-end constructor. This is
strong internal evidence, not production authorization, an independent
cryptographic review, or permission to claim a NIST level from the interactive
floor alone.

Every PR/main release aggregate and every tag release runs the research-package
isolation check, the complete `formal/crypto` kernel/axiom gate, the exact
Lean-generated proof-wire regression, and the production-verifier evidence
regression. These gates prevent silent drift; they do not discharge the named
semantic, hash-instantiation, or universal compiled-execution assumptions.

### References (Starting Point)

- Quantum collision finding (collision problem): https://arxiv.org/abs/quant-ph/9705002
- Fiat–Shamir in the quantum random oracle model (QROM): https://eprint.iacr.org/2014/587
- Post-quantum security of Fiat–Shamir: https://eprint.iacr.org/2017/398
- SmallWood transparent arguments for small circuits: https://eprint.iacr.org/2025/1085
- Tip5 (Triton/Neptune) sponge capacity and PQ collision discussion: https://eprint.iacr.org/2023/107.pdf
- RPO (Miden) security levels and 256-bit vs 384-bit capacity variants: https://eprint.iacr.org/2022/1577.pdf
- Poseidon2 design and security discussion: https://eprint.iacr.org/2023/323.pdf
- STARK soundness overview and common 96-bit classical target discussion (blog-level): https://www.starknet.io/blog/safe-and-sound-a-deep-dive-into-stark-security/
