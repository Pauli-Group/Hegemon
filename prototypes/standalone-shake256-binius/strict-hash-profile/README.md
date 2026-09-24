# Strict SHAKE256-512 proof hash profile

This isolated crate supplies the missing 64-byte SHAKE256 proof-hash plumbing for Binius:

- independently domain-separated Merkle leaves, Merkle nodes, and Fiat–Shamir transcripts;
- a `HashSuite` compatible with Binius' generic Merkle/BaseFold interfaces;
- a fixed-output SHAKE256-512 challenger digest;
- a canonical pre-statement transcript context binding the backend revision, inline circuit ID,
  relation/hash profile IDs, challenge-field modulus/basis/encoding ID, framed source-bundle
  digest, and inverse-rate;
- a fixed Python `hashlib`/OpenSSL SHAKE KAT, reset/domain tests, parallel-versus-sequential leaf
  hashing, ordered-node tests, and challenger/context-state KATs.

`m4_strict_hash` observes that context on both prover and verifier before the public words and
requires exact transcript exhaustion. The context is not written to the proof tape, so it changes
Fiat–Shamir challenges without adding proof bytes. A wrong-rate or wrong-field context, changed
public input, changed proof byte, or trailing proof byte must reject. The active field ID names
the backend's actual B128 GHASH field; the E384 identifier is used only as a negative separator
until mixed-field verifier arithmetic exists.

It is one strict-profile component, not a proof-security claim. The real Pay1x2
M4 integration at inverse-rate log two produced 149,360 proof bytes and rejected
changed public input, changed proof bytes, and trailing bytes. The retained
measurement is `measurements/pay1x2-rate2-shake512-2026-08-21.json`; it predates
the context preamble and is explicitly marked that way. Because the preamble is
observe-only, the protocol writes the same number and widths of proof messages,
so 149,360 bytes remains the structural size prediction. A context-bound proof
artifact must be rerun before calling that prediction a fresh measurement.

That measurement is not a production frontier point: the transcript is
transparent, the algebraic challenge field remains GF(2^128), the query profile
remains nonqualifying, and Pay1x2 is narrower than the maximum production
relation. The complete backend still needs an end-to-end zero-knowledge
compiler, strict algebraic soundness, full QROM review, exact maximum-relation
measurement, formal refinement, and consensus authorization.
