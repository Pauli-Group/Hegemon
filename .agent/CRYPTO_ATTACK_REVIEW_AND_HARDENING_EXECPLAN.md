# Crypto Attack Review And Hardening

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

Hegemon already uses serious cryptography: ML-KEM-1024 for note and peer encryption, ML-DSA for peer signatures, and proof systems that rely on Fiat-Shamir transcripts and post-quantum-friendly verification layers. The weak point in systems like this is often not “the math is broken”; it is that implementations accidentally recreate the same exploit conditions recent papers keep using: parser malleability, side-channel-friendly secret handling, decapsulation oracles, or unsafe downgrade knobs.

After this work, a maintainer can point to concrete hardening in the live code instead of vague claims. The observable outcome is that malformed note ciphertext encodings are rejected canonically, ML-KEM secrets and shared secrets wipe themselves on drop and stop exposing raw debug/equality behavior, and the node’s network decapsulation path no longer distinguishes parse failure from decapsulation failure. Focused regressions prove the new behavior.

## Progress

- [x] (2026-04-20 00:31 MDT) Re-read `.agent/PLANS.md`, `DESIGN.md`, and `METHODS.md` to pin down the shipped cryptographic surfaces before editing code.
- [x] (2026-04-20 00:34 MDT) Reviewed the current ML-KEM, note-encryption, wallet key-derivation, and network decapsulation code paths in `crypto/src/ml_kem.rs`, `crypto/src/note_encryption.rs`, `wallet/src/keys.rs`, and `node/src/substrate/network.rs`.
- [x] (2026-04-20 00:42 MDT) Cross-checked those surfaces against recent primary-source attacks, especially ML-KEM implementation attacks and modern Fiat-Shamir/proof implementation cautions.
- [x] (2026-04-20 01:29 MDT) Implemented live hardening for three concrete exploit analogues: canonical note ciphertext parsing, ML-KEM secret/shared-secret memory hygiene, and generic decapsulation failure reporting in the network KEM path.
- [x] (2026-04-20 01:29 MDT) Added focused regressions that fail if trailing bytes are accepted, malformed KEM lengths are accepted, ML-KEM secret wrappers stop zeroizing, or decapsulation failures become distinguishable again.
- [x] (2026-04-20 01:47 MDT) Ran focused validation: `cargo test -p synthetic-crypto ml_kem -- --nocapture`, `cargo test -p synthetic-crypto note_encryption -- --nocapture`, `cargo test -p wallet keys -- --nocapture`, and `cargo test -p hegemon-node decapsulation_errors_are_generic -- --nocapture` all passed.

## Surprises & Discoveries

- Observation: the most actionable modern attack analogues were implementation-level, not algebraic breaks of the underlying primitives.
  Evidence: the primary-source ML-KEM papers reviewed here concentrate on timing, power, FO-transform comparison, and oracle construction, while Hegemon’s clearest local defects were parser prefix acceptance and ordinary heap/stack handling of secrets.

- Observation: `crypto::note_encryption::NoteCiphertext::from_bytes` accepted a valid serialized prefix plus arbitrary trailing bytes.
  Evidence: before the patch, the parser consumed the final memo payload but never verified `offset + memo_len == bytes.len()`.

- Observation: Hegemon’s ML-KEM wrapper was stricter about key validity than about secret hygiene.
  Evidence: `MlKemSecretKey` already redacted `Debug`, but `MlKemSharedSecret` still derived `Debug`, shared-secret and secret-key equality were plain `==`, and several temporary secret buffers were left as ordinary arrays or `Vec<u8>`.

- Observation: the node-side network decapsulation helper surfaced different failure strings for malformed ciphertext length versus decapsulation failure.
  Evidence: `node/src/substrate/network.rs` returned `"Invalid ciphertext: ..."` for parse failure and `"Decapsulation failed: ..."` for decapsulation failure before the patch.

- Observation: for ML-KEM, “fixed-length garbage ciphertext” is not a parse failure and may still decapsulate to a fallback shared secret.
  Evidence: the first version of the node regression expected a 1568-byte garbage ciphertext to fail, but the test instead received a 32-byte shared secret. The regression was corrected to assert indistinguishable parse-boundary failures (short vs. long ciphertext) rather than claiming all garbage bytes are rejected by decapsulation.

## Decision Log

- Decision: prioritize implementation hardening that directly mirrors active ML-KEM and proof-system implementation attacks instead of attempting speculative cryptanalytic changes.
  Rationale: recent primary sources point at side channels, oracles, and transcript/parser mistakes as the exploit path that repeatedly becomes real. Hegemon had local analogues of those bugs today.
  Date/Author: 2026-04-20 / Codex

- Decision: treat note ciphertext parsing as a canonicalization boundary and fail closed on trailing bytes or the wrong ML-KEM ciphertext length.
  Rationale: prefix-accepting parsers create aliasing and downgrade room. The serialized object should have one accepted byte representation, not “valid prefix plus ignored tail.”
  Date/Author: 2026-04-20 / Codex

- Decision: make the network KEM decapsulation helper report one generic failure string.
  Rationale: modern chosen-ciphertext and side-channel work repeatedly amplifies any distinguisher around decapsulation. Hegemon does not need to volunteer that distinguisher in its own API surface.
  Date/Author: 2026-04-20 / Codex

- Decision: harden secret handling in wrappers and temporary derivation buffers even though Rust does not magically make memory remanence disappear.
  Rationale: secret-bearing arrays and `Vec<u8>` still live in memory until overwritten. Zeroization on drop plus `Zeroizing<Vec<u8>>` for transient materials reduces obvious retention without changing the protocol.
  Date/Author: 2026-04-20 / Codex

## Outcomes & Retrospective

Implemented and validated. The repository now has concrete defenses against three exploit classes that were previously plausible in local code:

- malformed or aliased note ciphertext encodings,
- secret retention and secret-friendly debug/equality behavior in ML-KEM wrappers, and
- distinguishable node-side decapsulation failures.

This does not mean the broader cryptographic story is “finished.” The remaining open risk is the same one the repo already acknowledges for the proving backend and for PQ implementation security generally: external cryptanalysis and side-channel review still matter. This pass removed obvious local footguns; it did not magically audit the mathematics of every primitive.

Focused validation succeeded with these commands:

    cargo test -p synthetic-crypto ml_kem -- --nocapture
    cargo test -p synthetic-crypto note_encryption -- --nocapture
    cargo test -p wallet keys -- --nocapture
    cargo test -p hegemon-node decapsulation_errors_are_generic -- --nocapture

## Context and Orientation

The relevant cryptographic surfaces are spread across four files.

`crypto/src/ml_kem.rs` is Hegemon’s wrapper around the `ml-kem` crate for ML-KEM-1024. This file defines the public key, secret key, shared secret, ciphertext, and keypair wrappers used by both the wallet and the node.

`crypto/src/note_encryption.rs` defines the serialized note ciphertext format and the hybrid note encryption scheme: ML-KEM establishes a shared secret and ChaCha20Poly1305 encrypts the note and memo payloads.

`wallet/src/keys.rs` derives wallet keys and note-encryption keypairs. This is where several transient secret-derivation buffers are assembled.

`node/src/substrate/network.rs` defines the PQ peer identity material and a helper that decapsulates network ciphertexts for post-quantum peer communication.

The attack language in this plan is intentionally plain. A “decapsulation oracle” means any behavior that helps an attacker distinguish why a KEM ciphertext failed. A “canonical parser” means one serialized object has exactly one accepted byte encoding rather than “any byte string with the right prefix.” “Zeroization” means explicitly overwriting secret material in memory when it is no longer needed.

## Plan of Work

The first edit is in `crypto/src/ml_kem.rs`. Add constant-time equality for secret keys and shared secrets, remove raw debug exposure for shared secrets, derive zeroization-on-drop for the secret-bearing wrapper types, and explicitly wipe temporary secret arrays used during deterministic key generation and shared-secret extraction.

The second edit is in `crypto/src/note_encryption.rs`. Tighten `NoteCiphertext::from_bytes` so it rejects any trailing bytes after the declared memo payload and rejects serialized note ciphertexts whose KEM component is not exactly `ML_KEM_CIPHERTEXT_LEN`. Also wrap the transient AEAD derivation material in a zeroizing buffer.

The third edit is in `wallet/src/keys.rs`. Replace ordinary `Vec<u8>` secret-derivation buffers with `Zeroizing<Vec<u8>>` so wallet subkey derivation and address KEM-seed derivation do not leave raw secret concatenations sitting in heap allocations.

The fourth edit is in `node/src/substrate/network.rs`. Collapse decapsulation failure reporting to one generic error string and add a regression that proves malformed ciphertexts and valid-length garbage ciphertexts are indistinguishable at that boundary.

## Concrete Steps

All commands run from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

The implementation sequence for this plan is:

    1. Patch `crypto/Cargo.toml` and `crypto/src/ml_kem.rs`.
    2. Patch `crypto/src/note_encryption.rs`.
    3. Patch `wallet/src/keys.rs`.
    4. Patch `node/src/substrate/network.rs`.
    5. Run focused tests for the affected crates.

The focused validation commands are:

    cargo test -p synthetic-crypto ml_kem -- --nocapture
    cargo test -p synthetic-crypto note_encryption -- --nocapture
    cargo test -p wallet keys -- --nocapture
    cargo test -p hegemon-node pq_network -- --nocapture

The expected behavior after the patch is:

    running ... test_from_bytes_rejects_trailing_bytes ... ok
    running ... test_from_bytes_rejects_invalid_kem_length ... ok
    running ... test_ml_kem_secret_zeroize ... ok
    running ... test_ml_kem_shared_secret_zeroize ... ok
    running ... test_decapsulation_errors_are_generic ... ok

## Validation and Acceptance

Acceptance is behavioral.

First, `crypto::note_encryption::NoteCiphertext::from_bytes` must reject both appended trailing bytes and a serialized ciphertext whose KEM component is not the ML-KEM-1024 length.

Second, the ML-KEM wrapper types must wipe secret material when explicitly zeroized in tests, and shared-secret debug output must no longer expose raw bytes.

Third, `node::substrate::network::PqNetworkKeypair::decapsulate` must return the same failure string for a malformed ciphertext length and a valid-length garbage ciphertext.

Fourth, the ordinary roundtrip ML-KEM and note-encryption tests must still pass, proving the hardening did not break the live happy path.

## Idempotence and Recovery

These edits are safe to reapply because they are additive hardening and regressions, not data migrations. If a test fails after a partial edit, rerun the exact focused crate test for the file being changed before broadening out to larger suites. No persistent state or network environment is touched by this plan.

## Artifacts and Notes

Primary-source references that drove the implementation choices:

- Bernstein et al., “KyberSlash: Exploiting secret-dependent division timings in Kyber implementations” (IACR ePrint 2024/1049).
- Hermelink et al., “The Insecurity of Masked Comparisons: SCAs on ML-KEM’s FO-Transform” (IACR ePrint 2024/060).
- Berzati et al., “Simple Power Analysis assisted Chosen Cipher-Text Attack on ML-KEM” (IACR ePrint 2024/2051).
- Block and Tiwari, “On the Concrete Security of Non-interactive FRI” (IACR ePrint 2024/1161).
- NIST FIPS 203, “Module-Lattice-Based Key-Encapsulation Mechanism Standard.”

The proof-system sources informed prioritization, but this implementation pass only patches Hegemon code where there was a direct analogue with a clear, testable defect.

## Interfaces and Dependencies

The new interfaces remain intentionally small.

In `crypto/src/ml_kem.rs`, the following invariants must hold:

    MlKemSecretKey: Zeroize + ZeroizeOnDrop, redacted Debug, constant-time PartialEq
    MlKemSharedSecret: Zeroize + ZeroizeOnDrop, redacted Debug, constant-time PartialEq
    MlKemKeyPair: Zeroize + ZeroizeOnDrop

In `crypto/src/note_encryption.rs`, `NoteCiphertext::from_bytes(&[u8]) -> Result<NoteCiphertext, CryptoError>` must reject:

    - any encoding with trailing bytes after the declared memo payload
    - any encoding whose `kem_ciphertext` length is not `ML_KEM_CIPHERTEXT_LEN`

In `node/src/substrate/network.rs`, `PqNetworkKeypair::decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String>` must return the generic string `"decapsulation failed"` for all malformed or invalid ciphertext inputs.

Revision note (2026-04-20): created this ExecPlan and filled it with the concrete implementation work after the attack review converged on implementation-level ML-KEM and parser hardening rather than speculative algebraic changes.
