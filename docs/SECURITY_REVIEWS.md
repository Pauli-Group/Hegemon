# Security Reviews, Cryptanalysis, and Audit Integration

This document defines how we commission third-party reviews for the post-quantum primitives, integrate their findings, and keep the repository’s verification artifacts plus adversarial test harnesses aligned with proof-of-work (PoW) miner operations.

## 1. Commissioning miner identity and pool cryptanalysis

We currently rely on:

- **ML-DSA-65** (Dilithium3 profile) for miner rig identities, pool controller signatures, and block announcements.
- **SLH-DSA** (SPHINCS+-SHA2-128f) for governance keys and long-lived pool treasury authorizations.
- **ML-KEM-768** (Kyber) for encryption and key agreement on miner <-> pool control channels.
- **Poseidon-like hash** inside the STARK AIR plus SHA-256/BLAKE3 externally for share commitments and nullifier derivations.

Commissioning requirements:

1. **Parameter validation brief** – Hand vendors `DESIGN.md §1` plus `crypto/README.md` (if updated) and request:
   - Side-channel considerations for deterministic RNG wrappers used in `crypto::ml_dsa`/`ml_kem`, with explicit coverage of rack-level miners that share chassis power/temperature envelopes.
   - State-of-the-art lattice reduction cost estimates for ML-DSA-65 and ML-KEM-768 under BKZ 2.0 and dual attacks with quantum sieving assumptions, highlighting replay risk if pool identities are rotated slowly.
   - Hash/collision resistance assessments for the Poseidon width/rounds defined in `circuits/transaction/src/hashing.rs` and the SHA-256-based Merkle layers that encode miner share proofs.
2. **Deliverables** – Require a written report with:
   - Attack models and concrete security estimates (bits) for each primitive plus explicit call-outs on miner impersonation or pool takeover implications.
   - Annotated diff suggestions mapped to function names (e.g., `crypto::hashes::poseidon::permutation`).
   - Test vectors or scripts to reproduce any exploit, especially those that would let an attacker spoof PoW share telemetry or tamper with block templates mid-flight.
3. **Tracking** – Log every finding using the JSON template in §4 and reference them inside `DESIGN.md`/`METHODS.md` with the finding ID.
4. **Cadence** – Trigger a review whenever:
   - Upgrading parameter sets (e.g., bumping to ML-DSA-87 for miner identities).
   - Touching STARK hash parameters or note commitment definitions that govern share proofs.
   - Annually, even without code changes, to capture new cryptanalytic results relevant to mining pools.

## 2. Third-party audit scopes

We separate audit scopes into three tracks so teams can bid independently:

| Track | Scope | Entry materials | Exit criteria |
| --- | --- | --- | --- |
| Cryptography | `crypto/`, `circuits/transaction`, `circuits/block` | `DESIGN.md §1`, `METHODS.md §1-3`, formal specs under `circuits/formal/` | All proofs verified, parameter justifications signed off, new issues filed. |
| Protocol / PoW coordination | `consensus/`, `protocol/`, `network/` | `DESIGN.md §2-4`, `consensus/spec/`, `consensus/spec/formal/` | PoW admission-control limits confirmed, miner share forgery tests documented, consensus doc updated with mitigations. |
| Implementation & pool ops | `wallet/`, `network/`, `state/`, CLI tooling, `runbooks/` | `METHODS.md` operational sections, `runbooks/` | Continuous security tests pass on patched builds; new regression tests added for each finding with miner/pool reproduction steps. |

Audit execution steps:

1. **Scope doc** – Provide auditors with this file and highlight specific commits/tags.
2. **Kickoff** – Walk auditors through the PoW-oriented model-checking specs and fuzz harnesses. Capture questions in `docs/SECURITY_REVIEWS.md#finding-log`.
3. **Remediation workflow** – Each finding becomes a GitHub issue linking to the affected file, severity, and recommended fix. Patches must include:
   - Test demonstrating the exploit before the fix (e.g., spoofed miner identity, pool payout tampering).
   - Update to `DESIGN.md` or `METHODS.md` describing the mitigation rationale and any impact on mining pool workflows.
4. **Integration** – After merging fixes, append a short summary to `DESIGN.md` (architecture impact) and to the relevant runbook.

## 3. Formal verification & continuous security testing

- Formal specs live under `circuits/formal/` and `consensus/spec/formal/`. Run them with either [TLC](https://github.com/tlaplus/tlaplus) or [Apalache](https://apalache.informal.systems/):
  ```bash
  # Example: verify MASP balance preservation
  cd circuits/formal
  tlc -deadlock transaction_balance.tla -config transaction_balance.cfg

  # Example: check PoW gossip safety invariants up to 5 rounds
  cd consensus/spec/formal
  apalache-mc check --max-steps=10 --inv=NoDoubleCommit hotstuff_safety.tla
  ```
- Continuous security testing harnesses:
  - `circuits/transaction/tests/security_fuzz.rs` – property-based witness validation (balance slots, nullifiers, input/output bounds).
  - `network/tests/adversarial.rs` – tampered handshake transcripts and miner-share control messages must be rejected deterministically.
  - `wallet/tests/address_fuzz.rs` – randomized address derivations plus adversarial mutations.
  - Root-level `tests/security_pipeline.rs` orchestrates cross-component adversarial flows, including simulated pool payout tampering.
- CI job `security-adversarial` (see `.github/workflows/ci.yml`) runs these harnesses on every push/PR. Failures block merges until triaged via `runbooks/security_testing.md`.

## 4. Finding log template

Document each review or audit item under this heading so engineers and auditors see a unified ledger.

```json
{
  "id": "SEC-2025-0001",
  "source": "Cryptanalysis / Lattice",
  "component": "crypto::ml_kem",
  "description": "Side-channel leakage in deterministic keygen seed schedule",
  "severity": "high",
  "status": "patched",
  "evidence": "link to PoC or transcript",
  "remediation": "reference to PR + commit",
  "design_notes": "DESIGN.md §1 updated with new randomness domain separation",
  "tests": ["cargo test -p synthetic-crypto --test kem_regression"]
}
```

Keep the log chronological; when closing a finding, link the merge commit and update the affected documents.

## 5. Local checklist

1. Read `DESIGN.md`, `METHODS.md`, and this file before any cryptographic, miner-identity, or network change.
2. If modifying circuits or hashes, update `circuits/formal/README.md` and rerun TLC; paste the summary output into the PR description.
3. If touching consensus logic, rerun `consensus/spec/formal` checks plus the network adversarial test with PoW-specific seeds.
4. Before tagging a release, run `./runbooks/security_testing.md` steps to collect fresh artifacts for miners, pool maintainers, and auditors.
