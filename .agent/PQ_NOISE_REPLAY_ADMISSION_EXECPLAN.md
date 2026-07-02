# PQ Noise Failed-Open Replay Admission Gate

This ExecPlan is a living document. It follows `.agent/PLANS.md` and must keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current as work proceeds.

## Purpose / Big Picture

The PQ Noise session must not let a forged, duplicated, or out-of-order encrypted frame desynchronize the receiver. After this change, a failed AEAD open preserves the receive nonce counter, so the next valid frame for the current counter can still be admitted. The behavior is visible by running the Lean-generated PQ Noise vector gate and a focused `pq-noise` test: duplicate and future frames fail closed without consuming the production receive counter, and the following valid frame decrypts.

## Progress

- [x] 2026-06-18T05:49:55Z Read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, existing `Hegemon.Network.PqNoise*` Lean modules, `pq-noise/src/noise.rs`, `pq-noise/src/lib.rs`, and the formal-core PQ hook.
- [x] 2026-06-18T05:49:55Z Identified the concrete implementation-equivalence gap: `NoiseCipher::decrypt` advances `recv_nonce` before AEAD authentication succeeds.
- [ ] Add Lean executable receive-admission helpers and theorems for authenticated open, failed-auth counter preservation, duplicate rejection, and future-frame rejection.
- [ ] Extend `gen_pq_noise_vectors` with schema-v5 replay/desync cases.
- [ ] Patch production `NoiseCipher::decrypt` to commit the receive counter only after successful AEAD authentication.
- [ ] Extend `pq-noise` vector conformance and add a focused regression that fails on the old eager-counter behavior.
- [ ] Update network-only formal claim, blueprint, and matrix entries if the theorem/vector evidence verifies.
- [ ] Run targeted Lean, vector generation, and Rust tests; record exact results.

## Surprises & Discoveries

- Observation: The existing Lean surface already covers directional slots, nonce sequence shape, OS-RNG KEM seed source, transcript/KDF binding, wrapper completion, and raw ciphertext conformance, but it does not yet state that failed frame authentication preserves receive state.
  Evidence: `formal/lean/Hegemon/Network/PqNoise.lean` has `openFrame` that advances on structural counter admission; `pq-noise/src/noise.rs` currently assigns `self.recv_nonce = next_nonce` before `recv_cipher.decrypt`.

## Decision Log

- Decision: Model replay/desync safety at the PQ Noise channel-admission layer rather than adding a new network wrapper abstraction.
  Rationale: The production bug and invariant live in `NoiseCipher` receive state. Binding it directly to `gen_pq_noise_vectors` gives a no-runtime-cost implementation-equivalence gate against the actual AEAD boundary.
  Date/Author: 2026-06-18 / Codex

- Decision: Treat both stale duplicate frames and future out-of-order frames as rejected observations that must preserve the receive counter.
  Rationale: A duplicate frame after accepting frame 0 and a frame 1 presented before frame 0 exercise both nonce-reuse and gap/desync classes while staying deterministic under generated test vectors.
  Date/Author: 2026-06-18 / Codex

## Outcomes & Retrospective

Pending completion.

## Context and Orientation

The production PQ Noise session is in `pq-noise/src/noise.rs`. `NoiseCipher::encrypt` uses the send key and the current send nonce; `NoiseCipher::decrypt` uses the receive key and the current receive nonce. The receive counter is security-sensitive: if a malformed frame consumes it, an attacker can make the next legitimate frame fail even though no valid frame was admitted.

The Lean executable model is in `formal/lean/Hegemon/Network/PqNoise.lean`, and the handshake/channel composition theorem is in `formal/lean/Hegemon/Network/PqNoiseHandshakeChannel.lean`. Generated JSON vectors come from `formal/lean/Hegemon/Network/GeneratePqNoiseVectors.lean` through `lake exe gen_pq_noise_vectors`. Production conformance is checked by `pq-noise/src/lib.rs` under the `HEGEMON_LEAN_PQ_NOISE_VECTORS` environment variable, and `scripts/check_formal_core.sh` already generates and runs that vector gate.

## Plan of Work

Add an authenticated receive-admission helper to the Lean PQ Noise model. It will compute the expected receive slot and nonce from the current receiver state and accept only when the observed wire slot and observed nonce match and the current counter can advance. On rejection it will return the unchanged state. Prove small facts for success, stale duplicate rejection after frame 0, and future frame rejection before frame 0.

Extend `gen_pq_noise_vectors` with replay/desync cases using the same schema as existing frame sequence vectors. The Rust conformance test will derive expected ciphertexts from the generated nonce and slot, then verify production `NoiseCipher` keeps `recv_nonce` unchanged after a duplicate or future ciphertext rejection and can still decrypt the next valid ciphertext.

Patch `NoiseCipher::decrypt` so it computes the candidate nonce, attempts AEAD open, and only then assigns `self.recv_nonce = next_nonce`. This has no extra cryptographic operation and does not change successful-frame behavior.

Update network-only security metadata after the theorem/vector/test evidence exists: `config/formal-security-claims.json`, `config/formal-security-blueprint.json`, and `config/highest-standard-formal-verification-matrix.json`.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Run:

    cd formal/lean && lake env lean Hegemon/Network/PqNoise.lean
    cd formal/lean && lake env lean Hegemon/Network/PqNoiseHandshakeChannel.lean
    cd formal/lean && lake exe gen_pq_noise_vectors > /tmp/hegemon-pq-noise-vectors.json
    python3 -m json.tool /tmp/hegemon-pq-noise-vectors.json >/dev/null
    HEGEMON_LEAN_PQ_NOISE_VECTORS=/tmp/hegemon-pq-noise-vectors.json cargo test -p pq-noise lean_generated_pq_noise_vectors_match_production -- --nocapture
    cargo test -p pq-noise failed_open_preserves_receive_nonce -- --nocapture

## Validation and Acceptance

Acceptance requires the generated PQ Noise vectors to parse as JSON, the Lean PQ Noise modules to compile, the production vector conformance test to pass with schema v5, and the focused `failed_open_preserves_receive_nonce` regression to pass. The new test should fail against the old eager receive-counter implementation because the duplicate or future rejected frame would consume the nonce needed by the next valid ciphertext.

## Idempotence and Recovery

The vector generation command writes to `/tmp` and can be repeated safely. The production code change is a local assignment-order change in `NoiseCipher::decrypt`; if later verification reveals a mismatch, restore only that local function body to the previous successful behavior and keep the generated vectors as evidence of the expected invariant.

## Artifacts and Notes

Pending final command transcripts.

## Interfaces and Dependencies

In `formal/lean/Hegemon/Network/PqNoise.lean`, add `OpenFrameAdmissionResult`, `openFrameWithObservedWire`, and theorems describing accepted and rejected state transitions. In `formal/lean/Hegemon/Network/GeneratePqNoiseVectors.lean`, add `replay_admission_cases` to the JSON. In `pq-noise/src/lib.rs`, deserialize and exercise those cases against `NoiseCipher`. In `pq-noise/src/noise.rs`, keep the `NoiseCipher::decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>>` signature unchanged.
