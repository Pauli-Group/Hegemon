# PQ Transport and Supply-Chain Hardening

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

This work closes five concrete security gaps in Hegemon's post-quantum transport and release process. After the change, PQ handshakes use secret encapsulation randomness instead of public transcript-derived randomness, legacy network channels use independent directional AEAD keys, PQ primitive dependencies are upgraded or explicitly waived when no final crate exists, the native backend remains blocked from production acceptance until external cryptanalysis is complete, and CI rejects unwaived dependency advisories. A reviewer can see the work by running targeted network/PQ tests and the dependency audit gate from the repository root.

## Progress

- [x] (2026-05-31 05:06Z) Read `.agent/PLANS.md`, `DESIGN.md`, and `METHODS.md`; confirmed design requires fresh OS-random KEM encapsulation seeds and treats the native backend as candidate-under-review.
- [x] (2026-05-31 05:06Z) Checked current RustCrypto PQ crate state: `ml-kem` latest is `0.3.2`, `ml-dsa` latest is `0.1.0`, and `slh-dsa` latest remains `0.2.0-rc.5`.
- [x] (2026-05-31 05:16Z) Patched `pq-noise` to use `OsRng` for ML-KEM encapsulation seeds and added a regression test that the old public transcript-derived seeds no longer reproduce response or finish ciphertexts.
- [x] (2026-05-31 05:18Z) Patched `network::SecureChannel` to derive independent directional AES-GCM keys and added a regression test for same-plaintext first frames in opposite directions.
- [x] (2026-05-31 05:22Z) Upgraded `ml-kem` to `0.3.2`, `ml-dsa` to `0.1.0`, and `slh-dsa` to `0.2.0-rc.5`; kept the SLH-DSA RC as an explicit tracked exception.
- [x] (2026-05-31 05:24Z) Moved `network` and `pq-noise` trust-boundary encodings from `bincode` to bounded postcard codecs with version markers.
- [x] (2026-05-31 05:25Z) Added release/CI gates for native backend candidate posture and dependency advisories with expiring waivers.
- [x] (2026-05-31 05:29Z) Ran targeted tests and recorded outcomes.

## Surprises & Discoveries

- Observation: The repository has two different PQ transport surfaces. `network::PeerIdentity` already uses OS-random encapsulation seeds, while `pq-noise::PqHandshake` derives encapsulation seeds from public transcript hashes.
  Evidence: `network/src/lib.rs` calls `random_encapsulation_seed()`, while `pq-noise/src/handshake.rs` derives `sha256(transcript || "encap1")` and `sha256(transcript || "encap2")`.
- Observation: RustCrypto has final releases for ML-KEM and ML-DSA, but not for SLH-DSA as of this run.
  Evidence: `cargo info ml-kem@0.3.2`, `cargo info ml-dsa@0.1.0`, and `cargo info slh-dsa@0.2.0-rc.5`.
- Observation: Upgrading `ml-kem` removes the yanked `kem 0.4.0-rc.4` path; the lockfile now resolves `kem` at `0.3.0`.
  Evidence: `Cargo.lock` after `cargo update -p ml-kem -p ml-dsa -p slh-dsa`.
- Observation: `bincode` remains in consensus/proof/wallet compatibility paths, but no longer in `network` or `pq-noise`.
  Evidence: `rg -n "bincode" network pq-noise -g '*.rs' -g 'Cargo.toml'` returns no matches; `cargo tree -i bincode@1.3.3` still lists consensus/proof crates.

## Decision Log

- Decision: Fix production callers before broad serialization migration.
  Rationale: The KEM randomness and bidirectional AEAD key bugs are live cryptographic hazards. Full migration away from `bincode` across consensus/proof artifacts is large and requires versioned wire-format work; this plan adds a dependency gate with explicit waivers now and records bounded canonical codec migration as enforced follow-up.
  Date/Author: 2026-05-31 / Codex.
- Decision: Upgrade `ml-kem` and `ml-dsa` to final current releases, but keep `slh-dsa` on the newest RC with an explicit waiver until a maintained final Rust crate exists.
  Rationale: Replacing SLH-DSA with an unaudited tiny crate would be worse than explicitly tracking the RC risk.
  Date/Author: 2026-05-31 / Codex.

## Outcomes & Retrospective

The live transport bugs are closed. `pq-noise` encapsulation randomness is secret OS entropy, the legacy secure channel uses directional keys, and both transport surfaces now use bounded postcard codecs instead of bincode. The available PQ primitive crates are on final releases except SLH-DSA, which remains an explicit expiring RC exception because no final RustCrypto crate exists yet. CI and tag releases now run a dependency audit gate, and the native backend package gate enforces `candidate_under_review` / `structural_candidate` posture.

The remaining bincode risk is intentionally visible rather than hidden: consensus/proof/wallet compatibility paths still depend on `bincode 1.3.3`, and `config/dependency-audit-waivers.json` expires that waiver on 2026-08-31. Removing it requires a versioned canonical artifact migration across consensus/proof carriers.

## Context and Orientation

`pq-noise/` is the newer transport handshake used by `network/src/pq_transport.rs`. A KEM, or key-encapsulation mechanism, lets one side create a ciphertext plus shared secret for the holder of a public key. The random coins used for encapsulation must be secret. If they are derived only from public transcript bytes, a passive observer can recompute the same ciphertext and shared secret.

`network/src/lib.rs` contains an older in-process handshake and `SecureChannel`. It currently derives one 32-byte AES-GCM key for both directions and starts both send and receive counters at zero. AES-GCM requires a unique key/nonce pair. Directional keys are the simplest fix because both peers can keep counter zero in each direction without reusing the same key/nonce pair.

`crypto/Cargo.toml` wraps RustCrypto PQ crates. `ml-kem` and `ml-dsa` have newer final releases available. `slh-dsa` remains release-candidate-only in RustCrypto and must be tracked explicitly.

`docs/crypto/native_backend_security_analysis.md` says the native backend is a structural candidate and not production-ready. Release tooling must preserve that posture so an engineer cannot accidentally ship it as externally accepted crypto.

`.github/workflows/ci.yml` now runs tests, native backend security checks, and the dependency audit gate. `docs/DEPENDENCY_AUDITS.md` records snapshots, while `config/dependency-audit-waivers.json` is the blocking policy. Full removal of `bincode` from the remaining consensus/proof/wallet compatibility paths should be a separate versioned artifact migration because those byte formats are consensus-visible.

## Plan of Work

First, edit `pq-noise/src/handshake.rs`. Replace transcript-derived encapsulation seed derivation with a helper that fills 32 bytes from `rand::rngs::OsRng`. Keep transcript hashes only in signatures and `SessionKeys::derive`, where they serve as public context rather than secret material. Add a test in the same crate that performs two handshakes with the same static identities and checks the first encrypted frame differs, then add a lower-level assertion that the old public transcript-derived seed no longer reproduces either first encrypted frame.

Second, edit `network/src/lib.rs`. Change `derive_session_material` to return two keys plus AAD. Change `SecureChannel` to store send and receive ciphers selected by a role enum, so initiator send equals responder receive and responder send equals initiator receive. Update handshake constructors to pass the correct role. Add a regression test that both directions encrypt identical first plaintext into different ciphertexts.

Third, edit `crypto/Cargo.toml` and the lockfile by running Cargo commands. Bump `ml-kem` to `0.3.2` and `ml-dsa` to `0.1.0`. Bump `slh-dsa` to `0.2.0-rc.5` if it compiles, and document the temporary RC exception in `docs/SECURITY_REVIEWS.md` or a dependency waiver file. If APIs changed, adjust wrappers in `crypto/src/ml_kem.rs`, `crypto/src/ml_dsa.rs`, and `crypto/src/slh_dsa.rs` without changing public Hegemon wrapper sizes unless the upstream final encoding changed.

Fourth, add release gating for the native backend candidate posture. The minimal enforcement is a test or script that reads the native backend claim and fails if a production/release command tries to mark it accepted without an external review artifact. Documentation should state that the backend remains blocked for production acceptance.

Fifth, add a dependency audit gate to CI. Create a policy file containing explicit waivers with reason and expiry for advisories that cannot be removed in this turn. Update `.github/workflows/ci.yml` to run the script. The script should fail on unwaived vulnerabilities and yanked crates, especially the old yanked `kem` path. Keep `bincode` migration as an explicit tracked gap unless a safe bounded-codec migration can be completed without breaking versioned artifacts.

## Concrete Steps

Run all commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

After the transport patches, run:

    cargo test -p pq-noise
    cargo test -p network --test adversarial -- --nocapture
    cargo test -p network --test handshake -- --nocapture
    cargo test -p network --test pq_handshake -- --nocapture

After dependency changes, run:

    cargo test -p synthetic-crypto
    cargo audit --color never

If `cargo audit` still reports waived issues, run the new audit gate script and expect it to pass only when every remaining advisory is listed in the waiver file with a reason and expiry.

## Validation and Acceptance

The KEM randomness fix is accepted when public transcript-derived seeds can no longer reproduce either ML-KEM handshake ciphertext. The directional AEAD fix is accepted when the legacy network channel can exchange messages and equal first plaintexts in opposite directions produce different ciphertexts. The dependency fix is accepted when the old yanked `kem 0.4.0-rc.4` path disappears or is no longer reachable through `ml-kem`, and CI has a dependency audit gate with explicit waivers for every remaining issue. The native backend posture fix is accepted when release validation fails closed unless external review acceptance is explicitly present.

## Idempotence and Recovery

The edits are additive or local replacements. Tests can be rerun safely. If a dependency upgrade changes upstream byte encodings, stop and record the exact size changes before updating Hegemon constants because consensus and wallet artifacts depend on those sizes. Do not force-lock a downgrade to silence audit output.

## Artifacts and Notes

- `cargo test -p pq-noise` passed: 16 unit tests, 1 ignored doctest.
- `cargo test -p network` passed: 39 unit tests, 3 adversarial tests, 3 handshake tests, 3 P2P integration tests, and 9 PQ handshake tests.
- `cargo test -p synthetic-crypto` passed: 15 unit tests and 4 vector tests.
- `./scripts/dependency-audit-gate.sh` passed with 11 current findings, all explicitly waived through 2026-08-31.
- `./scripts/check_native_backend_release_posture.sh --package audits/native-backend-128b/native-backend-128b-review-package.tar.gz` passed in candidate-under-review mode.

## Interfaces and Dependencies

`pq-noise::PqHandshake` must continue to expose the same public handshake functions. Internally it must use a helper equivalent to:

    fn random_encapsulation_seed() -> [u8; 32]

`network::SecureChannel` must keep:

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NetworkError>
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NetworkError>

but it must internally hold directional send and receive ciphers rather than one shared cipher.

The dependency audit gate must be runnable locally from the repository root and from GitHub Actions.
