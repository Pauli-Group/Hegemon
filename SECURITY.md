# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to: support@pauli.group

Do NOT open public issues for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Block Validity Architecture

Shielded validity uses **independent transaction proofs plus deterministic
consensus replay**. Every carried proof is verified in block order; a cache,
sidecar, receipt or historical decoder cannot replace that verification.

The selected release route is circuit 12,
`Hegemon.PrivateSpend.BoundedPolicy.CompFF01.Packed.v4`: 86 public words,
SMZL/q38, and the `HGPSLC02` common carrier for ordinary, treasury,
bounded-policy and HTLC spends. The exact source identity and network tuple are
recorded in [the v0.11 successor configuration](config/v011-release-successor.json)
and enforced by the source-owned registry in
[`protocol/versioning/src/launch_candidate.rs`](protocol/versioning/src/launch_candidate.rs).
That registry contains an exact **pre-mainnet** capability. A changed network,
genesis, manifest, relation or route must obtain its own matching authority.
The old `smallwood_poseidon2_production_capability()` returning `None` concerns
the separate historical RP03/SMZ9 route, not the current PrivateSpend registry.

The successor configuration limits its evidence to the exact reviewed source,
final-artifact cryptographic backend verification and isolated height-zero
startup. Its predecessor G8 lifecycle remains historical evidence. It does not
establish a fresh-network full lifecycle or authorize mainnet deployment.
Mainnet qualification must bind the actual source, proof identity, produced
binaries, manifest and unchanged-proof lifecycle; documentation and local test
success cannot grant release authority.

The header binds the ordered action body, state roots, supply transition and
DA fields. Full nodes replay those transitions and compare their results with
the header. Ciphertext data availability is checked by rebuilding the canonical
erasure encoding, metadata and Merkle root from the full body. `da_getChunk`
serves requested shards and openings; the shipped node does not run an automatic
randomized sampling protocol. The ciphertext erasure code does not cover
transaction-proof/action bytes, which are authenticated by the body locator
and action root.

## Known Security Limitations

### State Replay and Supply Accounting

Note-tree updates, nullifier uniqueness, reward issuance and header commitments
are checked by deterministic consensus replay in addition to transaction proof
verification. The current proof relation enforces input value = output value +
fee. Miner and funding rewards recycle the fee and add the scheduled subsidy.

The header and RPC field `supply_digest` is a **gross fee-inclusive accounting
counter**. With a coinbase it advances by subsidy + included fees; without a
coinbase it does not advance. It is not circulating supply and must not be
compared with the 21M monetary cap as though it were. Fees can be counted again
each time existing value is spent and paid in coinbase. The schedule cap, actual
subsidy issuance and spendable-wealth conservation are distinct claims; see
[native supply accounting](docs/NATIVE_SUPPLY_ACCOUNTING.md). This documents the
existing checked arithmetic and changes no consensus rule or RPC field.

### Historical Proof Paths

V4/Gamma, RP03/SMZ9 and the retained recursive relations have separate historical
identities. Their proof measurements, vectors and theorem scopes do not qualify
the selected circuit-12 relation. Old SMZ9 diagnostics and its published
extraction-bound limitation describe that profile, not the current SMZL/q38
analysis.

Native V3 rejects historical candidate-artifact actions, the production manifest
contains no historical recursive authorization range, and fresh launch
capabilities reject recursive-block authority. The V1 predecessor-descriptor
and BaseA defects must be repaired before any reuse; separate V2 descriptor
checks do not repair V1. An independent-transaction-proof launch does not rely
on either recursive authoring path. Plonky3 authoring crates and dependencies
are excluded from shipped binaries by
`scripts/check_native_runtime_dependencies.sh`.

Historical Lean statements that assume absolute hash injectivity do not express
computational collision resistance. Standard-axiom kernel checking does not make
an impossible premise usable. Mainnet security claims must use the applicable
collision-producing reductions and exact source qualification, rather than
crediting the historical V4 no-counterfeit premise as deployed security.

### Conditional Formal Guarantees and Implementation Trust

The maintained [RP05 conservation endpoint](formal/rp05/Rp05/Conservation.lean)
bounds accepted initialized-history conservation failure by an extraction-loss
term plus six actual primitive-game advantage terms. Its authorization,
soundness and zero-knowledge endpoints are conditional model theorems; they are
more than honest-witness fixtures, but do not automatically cover a changed
relation or arbitrary compiled Rust execution. Current compact-source reuse
must bind the exact relation, source inputs, roles, public schema and accounting.

The [independent-review disposition](docs/crypto/RP05_INDEPENDENT_REVIEW_RESOLUTIONS.md)
and [implementation boundary](docs/crypto/RP05_IMPLEMENTATION_BOUNDARY.md) retain
explicit trust in Rust implementation, serialization interpretation, compiler
and platform behavior. Finite correspondence tests and source-pinned reviews
are not universal Rust-to-Lean refinement. The launch qualification contract
uses that disclosed implementation boundary; it does not claim universal Rust
equivalence. Efficient extraction remains an inherited open boundary recorded
in [the design](DESIGN.md#03-native-node-cutover-posture).

Primitive-game bounds, the ideal SHA-512 quantum random oracle, independent
coins, adaptive reprogramming and the inclusive query/attempt budgets remain
explicit hypotheses. Failed, partial and unused prover/verifier/trace attempts
must be charged to the same initialized experiment. Ongoing HGN has no accepted
proof quota or release expiry; this does not remove the mathematical resource
hypotheses or turn them into runtime-enforced limits. Separate soundness and
privacy bounds do not establish an unconditional or joint 128-bit product claim.

### Primitive and Product Security

Note encryption and PQ transport use ML-KEM-1024 with 32-byte shared secrets.
Their confidentiality, ML-DSA authentication, symmetric encryption/KDFs and OS
randomness have separate implementation and cryptographic assumptions from the
transaction-proof theorem.

The current note commitment, nullifier and Merkle outputs use seven canonical
Goldilocks limbs from width-16 Poseidon2. Security analysis must cover the exact
current domains, feed-forward compression construction and adversarial budgets;
historical raw-compression results or generic digest-width arithmetic are
insufficient. Ciphertext binding separately requires the exact framed
BLAKE2b-384 function after six digest chunks are reduced modulo the field.
Raw BLAKE2b collision resistance alone does not bound collisions introduced by
that projection. Primitive correctness/interpretation is a separate trust
boundary from binding advantage.

Lean kernel/axiom, source-isolation and implementation regression gates prevent
silent drift within their declared scopes. They do not discharge these
primitive, oracle, randomness, efficient-extraction or implementation hypotheses,
and do not grant production authorization.

### References (Starting Point)

- Quantum collision finding (collision problem): https://arxiv.org/abs/quant-ph/9705002
- Fiat–Shamir in the quantum random oracle model (QROM): https://eprint.iacr.org/2014/587
- Post-quantum security of Fiat–Shamir: https://eprint.iacr.org/2017/398
- SmallWood transparent arguments for small circuits: https://eprint.iacr.org/2025/1085
- Tip5 (Triton/Neptune) sponge capacity and PQ collision discussion: https://eprint.iacr.org/2023/107.pdf
- RPO (Miden) security levels and 256-bit vs 384-bit capacity variants: https://eprint.iacr.org/2022/1577.pdf
- Poseidon2 design and security discussion: https://eprint.iacr.org/2023/323.pdf
- STARK soundness overview and common 96-bit classical target discussion (blog-level): https://www.starknet.io/blog/safe-and-sound-a-deep-dive-into-stark-security/
