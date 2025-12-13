# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to: support@pauli.group

Do NOT open public issues for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Known Security Limitations (Recursive Proofs)

Recursive epoch proofs (proof-of-proof) are currently **experimental** and should not be treated
as a hardened consensus-critical trust boundary until Phase 4 audit/hardening is complete.

Current known limitations:

- **Inner-proof specialization**: `StarkVerifierAir` is currently specialized to RPO-friendly
  inner proofs with `RpoAir`-like assumptions (e.g. trace width/partition sizing expectations).
  Generalizing recursion to verify epoch/transaction proofs inside other proofs is not yet
  supported.
- **Depth-2 recursion not shipped**: Outer verifier proofs can be generated with either native
  Blake3 Fiat–Shamir (default) or RPO commitments + RPO Fiat–Shamir (set
  `HEGEMON_RECURSIVE_EPOCH_PROOFS_OUTER_RPO=1`), but we do not yet ship an in-circuit verifier for
  `StarkVerifierAir` proofs.
