# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to: support@pauli.group

Do NOT open public issues for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Known Security Limitations (Recursive Proofs)

Recursive epoch proofs (proof-of-proof) are currently **experimental** and should not be treated
as a hardened consensus-critical trust boundary until Phase 4 audit/hardening is complete.

Current known limitations:

- **Query-position sort+dedup modeling**: `StarkVerifierAir` does not yet fully model Winterfell’s
  `draw_integers` sort+dedup semantics for query positions. This is a known soundness hardening
  item tracked in `.agent/RECURSIVE_PROOFS_EXECPLAN.md` and should be treated as a potential risk
  if recursive verification is used adversarially.
- **Inner-proof specialization**: `StarkVerifierAir` is currently specialized to RPO-friendly
  inner proofs with `RpoAir`-like assumptions (e.g. trace width/partition sizing expectations).
  Generalizing recursion to verify epoch/transaction proofs inside other proofs is not yet
  supported.
- **Non-self-recursive outer proofs**: Outer proofs are generated with native Blake3
  Fiat–Shamir and are not yet recursively verifiable themselves.
