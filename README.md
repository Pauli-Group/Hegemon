# Synthetic Hegemonic Currency

Quantum-resistant private payments

![Interlocking triad logo showing three rhombi forming a hexagon](docs/assets/shc-interlocking-triad.svg)

## Whitepaper

### Abstract
Synthetic Hegemonic Currency (SHC) establishes a unified, privacy-preserving settlement layer that remains secure even in the presence of large-scale quantum adversaries. The project combines a post-quantum shielded pool, programmable governance, and settlement-grade consensus into a single monetary primitive that can serve both retail and interbank use cases. This whitepaper summarizes the core principles guiding the repo and connects them to the implementation artifacts contained in this monorepo.

### Motivation
SHC is a post-quantum, Zcash-inspired settlement layer focused entirely on shielded transactions. The motivation comes from two converging pressures. First, Shor/Grover-class adversaries threaten to rewind the privacy guarantees of legacy shielded pools that still rely on elliptic curves or pairings. Second, the most commercially interesting private-payment applications still need instant settlement, programmability, and selective disclosure without surrendering supply controls. SHC combines PQ cryptography, MASP-style circuits, and governance hooks to deliver that blend. Privacy is a first-order commercial requirement because merchants, suppliers, and consumers routinely expose strategic information—such as inventory positions, negotiated discounts, or sensitive purchase histories—when forced to transact on transparent ledgers. Once adversaries or competitors can scrape that data, they can front-run contracts, profile customers for coercive price discrimination, or deanonymize activists, making private commerce practically impossible. The motivating use cases are:

1. **Digital bearer instrument** – Users custody notes locally via the `wallet/` client and transact without revealing balances, ownership, or memo data.
2. **Cross-border settlement rail** – Miners running the PoW `consensus/` stack deliver eventual finality for interbank transfers and bridge interfaces while preserving the privacy pool semantics.
3. **Programmable safety net** – Governance modules under `governance/` can enact capped issuance, capital controls, or demurrage in response to macro shocks, while remaining auditable.

### Protocol overview
The SHC protocol consists of four tightly-coupled subsystems:

1. **Shielded pool and cryptography (`crypto/`, `circuits/`, `wallet/`)** – The pool is modeled as a sparse Merkle accumulator proven via STARKs. ML-DSA/SLH-DSA signature primitives, ML-KEM key encapsulation, and Pedersen-style commitments underpin the spend authorization flow. Notes transition between states through the circuits defined in `circuits/`, and users interface with them via the wallet note-management APIs.
2. **Consensus and networking (`consensus/`, `network/`)** – A PoW protocol seals batches of shielded transactions. The Go `netbench` tooling simulates adversarial bandwidth conditions, while the Rust consensus service enforces validity proofs and data-availability sampling for miners.
3. **State and execution (`state/`, `protocol/`)** – Mining nodes maintain on-disk Merkle forests, apply deterministic fee burning, and expose programmable hooks for sidecar applications. The `protocol/` crate codifies transaction formats, serialization, and proof verification limits.
4. **Governance and runbooks (`governance/`, `runbooks/`)** – Multi-tier governance defines monetary policy, mining incentives, and emergency brake conditions. Operational runbooks document incident response, upgrade ceremonies, and regulator disclosures for PoW operators; see [runbooks/miner_wallet_quickstart.md](runbooks/miner_wallet_quickstart.md) for the end-to-end node + wallet pairing walkthrough referenced throughout this whitepaper.

#### Consensus, block proofs, and state management
`DESIGN.md §6` and `METHODS.md §5` describe how the `state/merkle`, `circuits/block`, and `protocol-versioning` crates collaborate to keep the chain coherent as primitives evolve. Miners append transactions to the Poseidon-based forests in `state/merkle`, then call `circuits/block::prove_block` locally before broadcasting a PoW solution. Every transaction carries a `VersionBinding { circuit, crypto }`, and block producers batch those into a `VersionMatrix` whose hash becomes the header’s `version_commitment`. The `protocol-versioning` crate exposes helpers for encoding that matrix plus the `VersionBinding` counts that recursive proofs publish so the network can attest exactly which circuit/crypto combinations were accepted in a slot. On ingest, PoW nodes query `VersionSchedule::first_unsupported` before finalizing state; if a block references a binding that governance has not scheduled, consensus raises `ConsensusError::UnsupportedVersion` and refuses to advance the Merkle roots even if the hashpower majority momentarily disagrees.

Governance rolls new bindings through the flow in `governance/VERSIONING.md`: authors submit a `VersionProposal`, reviewers stage verifying keys and recursive proof parameters, and once ratified the proposal is inserted into the canonical `VersionSchedule`. Proposals can include `UpgradeDirective`s that mandate a dedicated migration circuit, and both the base binding and upgrade circuit appear in the block’s `version_commitment` so operators can measure uptake via the recursive proof’s `version_counts`. The consensus crate enforces these policies by matching each observed binding against the live schedule, surfacing errors for unsanctioned bindings, and honoring retirement heights so deprecated circuits fall out automatically.

Operational touchpoints anchor the theory to daily practice. `consensus/bench` replays the ML-DSA/STARK payload sizes described in `DESIGN.md §6` so operators can benchmark PQ-era throughput before activating new bindings. During an emergency swap, `runbooks/emergency_version_swap.md` walks operators through drafting the `VersionProposal`, enabling the mandated `UpgradeDirective`, and monitoring `version_counts` until the `VersionSchedule` retires the compromised binding. Together, the recursive block proofs, version commitments, and governance hooks keep consensus, state, and operations synchronized without cloning the privacy pool.

#### Shielded transactions and PQ cryptography
Each note in the MASP-style pool carries `(value, asset_id, pk_recipient, rho, r)` as described in `METHODS.md §1`, and the wallet logic in `wallet/` maintains those fields while deriving commitments via `cm = Hc("note" || enc(value) || asset_id || pk_recipient || rho || r)` before inserting them into the STARK-proven Merkle forest in `state/`. The `circuits/transaction` crate enforces that every published commitment matches an in-circuit re-computation, while the note handling API exposes the corresponding secrets so a sender can prove knowledge without leaking them on-chain.

Spend authorization follows the hash-based nullifier scheme from `METHODS.md §1.2` and `DESIGN.md §1`: the `crypto/` primitives derive `nk = H("nk" || sk_spend)` and `nf = H("nf" || nk || rho || pos)` per note, and the STARK constraints in `circuits/transaction` bind each public nullifier to its witness data so the `state/` nullifier set catches double-spends. Proof witnesses also include Merkle paths for inputs, and the verifier logic wired through `protocol/` only accepts transactions whose STARK proofs simultaneously demonstrate membership, note opening correctness, and adherence to the MASP value equations.

Multi-asset conservation is implemented exactly as `METHODS.md §2` prescribes: the circuit forms a permutation-checked multiset of `(asset_id, signed_delta)` pairs, sorts and compresses them, and emits a `balance_tag` commitment that nodes in `consensus/` compare against fee and issuance rules. By constraining the integer ranges in-field and collapsing per-asset totals, the prover shows that every input and output balances out, and `wallet/` surfaces the same accounting so users can audit multi-asset flows locally.

Post-quantum security hinges on the primitives cataloged in `DESIGN.md §1`: ML-DSA handles miner and governance signatures, SLH-DSA anchors long-lived roots of trust, and ML-KEM drives note/viewing key encryption, all exposed via the unified `crypto/` crate. Because the STARK proving stack in `circuits/transaction` and the note authorization flow rely only on hash-based commitments and lattice primitives, the pool stays quantum-safe—no elliptic curves or pairing-based assumptions remain for Shor’s algorithm to break, and Grover merely halves the effective hash security margin already accounted for with 256-bit digests.

These guarantees are not just prose: `circuits/formal` captures the nullifier uniqueness and MASP balance invariants in TLA+, and `circuits-bench` plus the `wallet-bench` suite publish the prover and client performance envelopes so reviewers can correlate the whitepaper claims with reproducible benchmarking and formal artifacts.

#### Assessing resistance to Shor’s algorithm
SHC deliberately removes every discrete-log or factoring dependency that Shor’s algorithm could exploit. The `crypto/` crate standardizes on lattice- and hash-based primitives—ML-DSA (Dilithium-like) for miner/governance signatures, SLH-DSA (SPHINCS+) for long-lived trust roots, and ML-KEM (Kyber-like) for encrypting note/viewing keys—so there are no RSA or elliptic-curve targets to collapse. Hash commitments rely on SHA-256, BLAKE3-256, and Poseidon-style permutations with ≥256-bit outputs, meaning Grover’s quadratic speedup is already absorbed into the security margin. The STARK proving system is fully transparent and anchored in hash collision resistance, so its soundness does not rely on pairings or number-theoretic assumptions either. Finally, the threat model assumes adversaries already possess Shor/Grover-class hardware, which is why consensus governance bans downgrades to classical primitives and enforces PQ-safe key sizes. Together, these design choices provide a high degree of resistance to Shor’s algorithm across the entire stack—from note commitments and proofs to networking, governance, and operational guardrails.

### Monetary model
SHC targets a basket-pegged unit of account. Key levers include:

- **Supply management** – Mining nodes enforce capped issuance defined in `DESIGN.md`, and surplus fees route to a stabilization reserve to dampen volatility.
- **Liquidity incentives** – Wallet and miner clients expose hooks for automated market makers to provide cross-asset liquidity while preserving shielded ownership.
- **Stability metrics** – Oracles feed transparent macro indicators (CPI baskets, FX indices) into governance circuits to automatically adjust collateral ratios.

In the live system, these levers become explicit mining duties wired through `governance/` and `state/`. Issuance limits are encoded in `VersionProposal`s that describe the capped schedule alongside any reserve-ratio tweaks; once ratified they are registered into the consensus `VersionSchedule`, so every block producer rejects mint transactions whose proofs exceed the supply cap recorded in `state/` metadata. Fees and demurrage routed into the stabilization reserve are audited inside the same ledger trees, and the rebalancing instructions (sell/buy operations or cross-pool transfers) live as governance modules so operators can trace reserve movements back to the policy artifact that authorized them.

Liquidity hooks live in `protocol/` where transaction structs expose sidecar commitments for AMM routers, and miners enforce that those hooks only net out if they reference bindings blessed by the active `VersionSchedule`. Governance modules described in `governance/` determine which automated market maker programs are permitted, while the `wallet/` glue code simply passes through the hook payload so shielded ownership never leaves the MASP. Because the same versioning apparatus backs these hooks, rolling out a new liquidity primitive is as simple as drafting a `VersionProposal` with an `UpgradeDirective` that migrates existing liquidity notes without fragmenting the pool.

Stability oracles are modeled as miners consuming commitments produced by adapters implemented in `protocol/` and then anchoring the values into the Merkle forests maintained under `state/`. Governance schedules define which CPI/FX feeds are valid, the quorum required to rotate them, and how deviations drive collateral-ratio changes. Miners must attest that each oracle update references a `VersionSchedule`-approved binding; otherwise the block is rejected, ensuring that a rogue oracle cannot silently erode the supply controls or liquidity programs.

Policy changes and primitive upgrades therefore share the same lifecycle: a `VersionProposal` describes the new cap, reserve policy, oracle feed, or liquidity hook; a `VersionSchedule` entry sets the activation/retirement heights; and an optional `UpgradeDirective` codifies how in-flight notes migrate (e.g., swapping to a patched stabilization reserve circuit). This keeps monetary policy atomic—operators only need to track the schedule rather than bespoke forks—and the relevant code paths stay discoverable (`governance/` for policy logic, `protocol/` for transaction formats, `state/` for persistence).

Emergency actions reuse the checklist in `runbooks/emergency_version_swap.md`. If the stabilization reserve circuit or an oracle binding is compromised, operators follow that runbook to draft a fast-track `VersionProposal`, regenerate the required proving/verifying keys, and push the updated `VersionSchedule` to all miners. The runbook’s upgrade circuit requirements ensure that reserve balances or oracle attestations can be rolled forward without losing assets, while the staged miner rollout (keys → binaries → monitoring) keeps the monetary safety net intact: consensus refuses unsupported bindings, upgrade transactions prove reserve/oracle continuity, and the final retirement step prunes the vulnerable path once all miners attest to the new schedule.

### Privacy, security, and compliance
The architecture prioritizes defense-in-depth:

- **Post-quantum guarantees** – All signatures and key exchanges default to PQ-safe primitives maintained in `crypto/`.
- **Soundness and correctness** – Every critical path change must update `DESIGN.md`, `METHODS.md`, and any relevant specification artifacts to keep the implementation auditable.
- **Selective disclosure** – View keys allow auditors or regulators to inspect specific flows without deanonymizing the entire ledger, aligning with multi-jurisdiction privacy requirements.

#### Security and assurance program
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) documents the baseline adversary: Shor/Grover-era attackers can compromise miners on demand, replay malformed traffic, and attempt to bias randomness. This is why every primitive in `crypto/` sticks to ML-DSA/SLH-DSA signatures, ML-KEM key exchange, and ≥256-bit hashes, why the STARK proving system avoids trusted setups entirely, and why adaptive compromise controls (view-key rotation, nullifier privacy, parameter pinning) must survive even when an attacker briefly controls wallets or consensus nodes.

[DESIGN.md §8](DESIGN.md#8-security-assurance-program) outlines the feedback loops that keep those assumptions observable. External cryptanalysis and third-party audits—tracked in [docs/SECURITY_REVIEWS.md](docs/SECURITY_REVIEWS.md)—tie concrete findings back to functions and commits so the PQ parameter set never drifts silently. The TLA+ models under `circuits/formal/` and `consensus/spec/formal/` make witness layouts, balance invariants, and HotStuff phases reviewable at every release gate, giving reviewers a mechanical view of each subsystem’s state. Continuous integration runs the `security-adversarial` workflow plus dedicated fuzz/property tests for transactions, network handshakes, wallet address derivations, and the root-level `tests/security_pipeline.rs`, so regressions surface as blocking signals with attached artifacts. Together, audits, formal specs, and CI logs ensure every subsystem—from proofs to networking—emits evidence that the live system still matches the whitepaper.

Operators follow [runbooks/security_testing.md](runbooks/security_testing.md) whenever the adversarial suite fails, before releases, or after touching witnesses, networking, or wallet encodings. The runbook pins `PROPTEST_MAX_CASES`, executes the four adversarial `cargo test` commands (transaction circuit fuzzing, network handshake mutations, wallet address fuzzing, and the cross-component pipeline), and, when necessary, re-runs the TLA+/Apalache jobs for circuit balance and HotStuff safety. Findings, seeds, and transcripts are captured and logged into [docs/SECURITY_REVIEWS.md](docs/SECURITY_REVIEWS.md), which enforces that mitigation PRs add regression tests plus design updates. This workflow closes the loop between operator playbooks and the canonical review ledger so the assurance process remains enforceable rather than aspirational.

### Roadmap
1. **Alpha** – Deliver end-to-end shielded transfers with synthetic test assets, benchmarked via `circuits-bench` and `wallet-bench`.
2. **Beta** – Harden the PoW consensus path, integrate governance hooks, and document how external miners can sync, mine, and upgrade safely.
3. **Launch** – Freeze the monetary policy smart contracts, publish third-party audits, and release reproducible builds for wallet and mining node binaries.

---

## Monorepo layout

| Path | Purpose |
| --- | --- |
| `crypto/` | Rust crate (`synthetic-crypto`) with ML-DSA/SLH-DSA signatures, ML-KEM, and hash/commitment utilities. |
| `circuits/` | Transaction/block STARK circuits plus the `circuits-bench` prover benchmark. |
| `consensus/` | Ledger/miner logic and the Go `netbench` throughput simulator under `consensus/bench`. |
| `wallet/` | CLI wallet plus the `wallet-bench` binary for note/key performance measurements. |
| `docs/` | Contributor docs (`CONTRIBUTING.md`), threat model, and API references that stay in sync with `DESIGN.md`/`METHODS.md`. |

## Getting started

### Fast path

1. `./scripts/dev-setup.sh` installs Rust, Go, clang-format, jq, and the other CLI dependencies on Debian/Ubuntu hosts. The script is idempotent, so re-running it will simply ensure the required toolchains stay patched.
2. `make check` formats, lints, and tests the entire workspace with the same flags that CI enforces.
3. `make bench` executes the smoke benchmarks for the prover, wallet, and networking stacks so you can capture baseline performance before touching hot paths.
4. `make wallet-demo` runs `scripts/wallet-demo.sh` which walks through generating a throwaway wallet, crafting a sample transaction, and scanning the resulting ciphertexts. The artifacts land in `wallet-demo-artifacts/` for easy inspection or debugging.
5. Read `docs/CONTRIBUTING.md` and keep `DESIGN.md`/`METHODS.md` synchronized with any implementation updates.

Want everything above bundled together? Run `make quickstart` (or `./scripts/dashboard.py --run quickstart`) to execute the setup script, CI-equivalent `make check`, the full benchmark suite, and the wallet demo sequentially via the dashboard.

### Manual install/run steps

If you prefer to provision dependencies yourself:

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

CI (`.github/workflows/ci.yml`) runs these commands automatically plus targeted crypto, consensus, and wallet jobs. See `docs/CONTRIBUTING.md` for the exact job breakdown.

### Helpful `make` targets

| Target | Purpose |
| --- | --- |
| `make setup` | Runs `scripts/dev-setup.sh` to install toolchains and CLI prerequisites. |
| `make check` | Formats, lints, and tests the entire Rust workspace. |
| `make bench` | Executes the prover, wallet, and network smoke benchmarks. |
| `make wallet-demo` | Generates example wallet artifacts plus a balance report inside `wallet-demo-artifacts/`. |
| `make dashboard` | Launches the interactive dashboard that wraps setup, test, demo, and benchmark workflows. |
| `make quickstart` | Calls the dashboard's quickstart action (dev setup → `make check` → `make bench` → wallet demo). |

### Operations dashboard

The `scripts/dashboard.py` CLI exposes the most common repo workflows through a
single menu:

```bash
./scripts/dashboard.py          # interactive menu
./scripts/dashboard.py --list   # print the catalog of actions
./scripts/dashboard.py --run check   # run a specific action by slug
./scripts/dashboard.py --run quickstart   # run the full workstation bootstrap sequence
```

Each action simply shells out to the documented commands (`make check`,
`cargo run -p circuits-bench …`, etc.), so the dashboard doubles as living
documentation for the official workflows. Use it when you need to install
toolchains, run the wallet demo, or capture benchmark baselines without
memorizing the exact commands.

Need a graphical experience? Start the FastAPI wrapper and the Vite UI, which
drive the same `_actions()` catalog via streaming NDJSON events:

```bash
pip install -r scripts/dashboard_requirements.txt
uvicorn scripts.dashboard_service:app --host 0.0.0.0 --port 8001

cd dashboard-ui
npm install
VITE_DASHBOARD_SERVICE_URL=http://127.0.0.1:8001 npm run dev
```

Open `http://localhost:5173` and click any action to watch live JetBrains Mono
logs, Guard Rail red error highlights, Proof Green confirmation toasts, and
progress shimmers that mirror the CLI execution order. See
`runbooks/dashboard_troubleshooting.md` for tips that map UI actions back to
`make dashboard` and `./scripts/dashboard.py --run <slug>` commands.
