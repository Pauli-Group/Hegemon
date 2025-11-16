# Synthetic Hegemonic Currency

Quantum-resistant private payments

![Interlocking triad logo showing three rhombi forming a hexagon](docs/assets/shc-interlocking-triad.svg)

## Whitepaper

### Abstract
Synthetic Hegemonic Currency (SHC) establishes a unified, privacy-preserving settlement layer that remains secure even in the presence of large-scale quantum adversaries. The project combines a post-quantum shielded pool, programmable governance, and settlement-grade consensus into a single monetary primitive that can serve both retail and interbank use cases. This whitepaper summarizes the core principles guiding the repo and connects them to the implementation artifacts contained in this monorepo.

### Motivation
The global financial system is fragmenting across jurisdictions, while zero-knowledge and post-quantum cryptography are racing toward production readiness. SHC treats these two forces as complementary: a neutral, credibly-private currency that is quantum-resistant by default can anchor trade between competing blocs while shielding individuals from surveillance. The motivating use cases are:

1. **Digital bearer instrument** – Users custody notes locally via the `wallet/` client and transact without revealing balances, ownership, or memo data.
2. **Cross-border settlement rail** – Validators running the `consensus/` stack deliver deterministic finality for interbank transfers and bridge interfaces.
3. **Programmable safety net** – Governance modules under `governance/` can enact capped issuance, capital controls, or demurrage in response to macro shocks, while remaining auditable.

### Protocol overview
The SHC protocol consists of four tightly-coupled subsystems:

1. **Shielded pool and cryptography (`crypto/`, `circuits/`, `wallet/`)** – The pool is modeled as a sparse Merkle accumulator proven via STARKs. ML-DSA/SLH-DSA signature primitives, ML-KEM key encapsulation, and Pedersen-style commitments underpin the spend authorization flow. Notes transition between states through the circuits defined in `circuits/`, and users interface with them via the wallet note-management APIs.
2. **Consensus and networking (`consensus/`, `network/`)** – A leader-based BFT protocol seals batches of shielded transactions. The Go `netbench` tooling simulates adversarial bandwidth conditions, while the Rust consensus service enforces validity proofs and data-availability sampling.
3. **State and execution (`state/`, `protocol/`)** – Validator nodes maintain on-disk Merkle forests, apply deterministic fee burning, and expose programmable hooks for sidecar applications. The `protocol/` crate codifies transaction formats, serialization, and proof verification limits.
4. **Governance and runbooks (`governance/`, `runbooks/`)** – Multi-tier governance defines monetary policy, validator admission, and emergency brake conditions. Operational runbooks document incident response, upgrade ceremonies, and regulator disclosures.

#### Shielded transactions and PQ cryptography
Each note in the MASP-style pool carries `(value, asset_id, pk_recipient, rho, r)` as described in `METHODS.md §1`, and the wallet logic in `wallet/` maintains those fields while deriving commitments via `cm = Hc("note" || enc(value) || asset_id || pk_recipient || rho || r)` before inserting them into the STARK-proven Merkle forest in `state/`. The `circuits/transaction` crate enforces that every published commitment matches an in-circuit re-computation, while the note handling API exposes the corresponding secrets so a sender can prove knowledge without leaking them on-chain.

Spend authorization follows the hash-based nullifier scheme from `METHODS.md §1.2` and `DESIGN.md §1`: the `crypto/` primitives derive `nk = H("nk" || sk_spend)` and `nf = H("nf" || nk || rho || pos)` per note, and the STARK constraints in `circuits/transaction` bind each public nullifier to its witness data so the `state/` nullifier set catches double-spends. Proof witnesses also include Merkle paths for inputs, and the verifier logic wired through `protocol/` only accepts transactions whose STARK proofs simultaneously demonstrate membership, note opening correctness, and adherence to the MASP value equations.

Multi-asset conservation is implemented exactly as `METHODS.md §2` prescribes: the circuit forms a permutation-checked multiset of `(asset_id, signed_delta)` pairs, sorts and compresses them, and emits a `balance_tag` commitment that nodes in `consensus/` compare against fee and issuance rules. By constraining the integer ranges in-field and collapsing per-asset totals, the prover shows that every input and output balances out, and `wallet/` surfaces the same accounting so users can audit multi-asset flows locally.

Post-quantum security hinges on the primitives cataloged in `DESIGN.md §1`: ML-DSA handles validator and governance signatures, SLH-DSA anchors long-lived roots of trust, and ML-KEM drives note/viewing key encryption, all exposed via the unified `crypto/` crate. Because the STARK proving stack in `circuits/transaction` and the note authorization flow rely only on hash-based commitments and lattice primitives, the pool stays quantum-safe—no elliptic curves or pairing-based assumptions remain for Shor’s algorithm to break, and Grover merely halves the effective hash security margin already accounted for with 256-bit digests.

These guarantees are not just prose: `circuits/formal` captures the nullifier uniqueness and MASP balance invariants in TLA+, and `circuits-bench` plus the `wallet-bench` suite publish the prover and client performance envelopes so reviewers can correlate the whitepaper claims with reproducible benchmarking and formal artifacts.

### Monetary model
SHC targets a basket-pegged unit of account. Key levers include:

- **Supply management** – Validators enforce capped issuance defined in `DESIGN.md`, and surplus fees route to a stabilization reserve to dampen volatility.
- **Liquidity incentives** – Wallet and validator clients expose hooks for automated market makers to provide cross-asset liquidity while preserving shielded ownership.
- **Stability metrics** – Oracles feed transparent macro indicators (CPI baskets, FX indices) into governance circuits to automatically adjust collateral ratios.

### Privacy, security, and compliance
The architecture prioritizes defense-in-depth:

- **Post-quantum guarantees** – All signatures and key exchanges default to PQ-safe primitives maintained in `crypto/`.
- **Soundness and correctness** – Every critical path change must update `DESIGN.md`, `METHODS.md`, and any relevant specification artifacts to keep the implementation auditable.
- **Selective disclosure** – View keys allow auditors or regulators to inspect specific flows without deanonymizing the entire ledger, aligning with multi-jurisdiction privacy requirements.

### Roadmap
1. **Alpha** – Deliver end-to-end shielded transfers with synthetic test assets, benchmarked via `circuits-bench` and `wallet-bench`.
2. **Beta** – Harden consensus, integrate governance hooks, and onboard external validators through documented runbooks.
3. **Launch** – Freeze the monetary policy smart contracts, publish third-party audits, and release reproducible builds for wallet and validator binaries.

---

## Monorepo layout

| Path | Purpose |
| --- | --- |
| `crypto/` | Rust crate (`synthetic-crypto`) with ML-DSA/SLH-DSA signatures, ML-KEM, and hash/commitment utilities. |
| `circuits/` | Transaction/block STARK circuits plus the `circuits-bench` prover benchmark. |
| `consensus/` | Ledger/validator logic and the Go `netbench` throughput simulator under `consensus/bench`. |
| `wallet/` | CLI wallet plus the `wallet-bench` binary for note/key performance measurements. |
| `docs/` | Contributor docs (`CONTRIBUTING.md`), threat model, and API references that stay in sync with `DESIGN.md`/`METHODS.md`. |

## Getting started

1. Install Rust 1.75+, Go 1.21, and (optionally) clang-format for C++ style checks.
2. Run the full Rust workspace tests:
   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-targets --all-features
   cargo test --workspace
   ```
3. Run the smoke benchmarks to capture prover/network/wallet baselines:
   ```bash
   cargo run -p circuits-bench -- --smoke --prove --json
   cargo run -p wallet-bench -- --smoke --json
   (cd consensus/bench && go run ./cmd/netbench --smoke --json)
   ```
4. Read `docs/CONTRIBUTING.md` and keep `DESIGN.md`/`METHODS.md` synchronized with any implementation updates.

CI (`.github/workflows/ci.yml`) runs these commands automatically plus targeted crypto, consensus, and wallet jobs. See `docs/CONTRIBUTING.md` for the exact job breakdown.
