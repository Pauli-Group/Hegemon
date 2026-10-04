# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to: support@pauli.group

Do NOT open public issues for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Block Validity Architecture

Any production-authorized shielded route must enforce **independent transaction
proofs plus deterministic consensus replay**:

1. **Transaction proofs**: The current candidate is one canonical SMZ9 proof of
   the 853,429-byte Poseidon2 V8 relation per shielded transfer. Its program has
   SHA-512
   `7e50eba07d84433a53a6c85ed2b3efecbeff103ca402bb931831e1598e6c9ab8fa138c9b2f0cb9d21bf2bf044b50d4d057ae0bb12e4def00ec52765245cf9e17`
   and relation id
   `7e50eba07d84433a53a6c85ed2b3efecbeff103ca402bb931831e1598e6c9ab8fa138c9b2f0cb9d21bf2bf044b50d4d0`.
   `HGV8RP03` is its eight-byte format magic and lineage marker, not its relation
   identity. Import must verify every proof independently in block order. The
   production capability registry currently returns `None`, so the route is not
   active.
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

The retained primary and independent proofs measure 122,735 and 122,607 bytes.
They are historical evidence for the pre-repair 852,305-byte HGV8RP03-format
program at SHA-512
`8477896dc765c3776fefc93bb74fb0c7668a677abdc60697b0c216bc9b4363e46a8b7cadc557dba4a1e4ccdfe572e5b2833879dd465079b12b6044a51a5612c3`.
Both cryptographically verify from their frozen 830-file source inventory and
survive the exact RPC, relay, mempool, mining, import, restart, reorganization,
and fresh-node replay fixture without changing proof bytes. They neither verify
nor bind the current repaired program. No proof or lifecycle receipt is retained
for the current relation id. This is historical implementation evidence, not
release authority; the source capability and successor registry remain empty.

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

The deterministic 136,119-byte current-source security diagnostic has SHA-512
`5346d68e30c7ec99d197669679159af777ae7663029e22fc84da8fbf5e353b1829b4f4368b6449510b25bbf1e1022281891a114f51783148e2423c538e0b5110`.
It is bound to the current program digest above. Under its uninstantiated
assumptions it records a 288-bit interactive floor and a conditional 157-bit
soundness/composition screen for one global `2^64` quantum-query budget. Its
4,096-block and 2,097,152-accepted-proof arithmetic is a finite diagnostic, not a
cryptographic reset or a protocol-lifetime bound. Required refinement,
primitive, whole-view, history, budget-binding, and independent-review receipts
remain absent. The report explicitly records `production_eligible=false`, no
deployed composed floor, and no production authority.

The deterministic 4,230-byte executable zero-knowledge refinement diagnostic
has SHA-512
`e89ff29b047d85c6121689c4d298f031141d2dac6452f182d5d8d53cdd4ef7694c8616909ade6be95bcf1b1e06e98dd25b13df79bd7372be9a5af0500fe9015b`.
It is bound to the same current relation id and verifies exact executable ROM
replay and honest-map dimensions without using witness words. It records
`production_eligible=false` and no executable whole-view refinement. It is
diagnostic refinement evidence, not the missing adaptive repeated-proof
zero-knowledge theorem, global SHA-512 QROM lifetime theorem, or production
authorization.

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
