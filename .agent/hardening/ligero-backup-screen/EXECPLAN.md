# Ligero-family backup architecture screen

This ExecPlan is a living record for a bounded source-and-arithmetic tournament.
It follows `.agent/PLANS.md`.  The lane is deliberately isolated: it may only
write this directory, may not build or fetch proof-system dependencies, and may
not grant production authority.

## Purpose

Determine whether a transparent hash-based Ligero, Ligero++, BooLigero,
Ligerito, or Flock-style construction can already prove the exact frozen
Goldilocks Boolean/R1CS relation with complete whole-view zero knowledge, a
finite-QROM Fiat-Shamir composition, conventional wide hashes, one canonical
self-contained proof, and an implementable verifier/refinement path.  If the
papers do not determine exact proof bytes for this relation, retain `null`.

## Progress

- [x] Read repository instructions, DESIGN.md, METHODS.md, README, and
  `.agent/PLANS.md` before writing.
- [x] Pin the exact relation geometry and source-manifest digest.
- [x] Inspect the primary Ligero, BooLigero, Ligerito, CMS QROM, Block IOP
  soundness, and Flock papers, including rendered-page visual checks.
- [x] Record Ligero++ as source-incomplete instead of inheriting claims from an
  abstract or predecessor.
- [x] Derive an exact-rational Ligero paper-expression optimizer for the frozen
  relation and retain the arithmetic, not a proof-size claim.
- [x] Enumerate PCS/IOP, zero-knowledge, Fiat-Shamir, concrete-hash, grinding,
  union, parser, refinement, and production gaps.
- [x] Compare the CFW26 105-oracle carrier and ProveKit no-go.
- [x] Add a canonical ledger, dependency-free checker, and mutation tests.
- [x] Verify the checker, tests, source hashes, and whitespace.

## Findings and decisions

Original Ligero is the closest theorem shape.  Its primary paper supplies an
explicit perfect-view simulator, a theorem claiming identical-view ZK for the
interactive oracle protocol, a round-by-round soundness analysis for its own
protocol, and a classical-ROM BCS compilation discussion.  That is materially
stronger than witness masking folklore.  It is still not a qualifying concrete
architecture: there is no implemented and refined adapter for the exact frozen
relation, no exact CMS finite-QROM instantiation with augmented-query arity, no
concrete SHA-512/SHAKE-to-QRO reduction, no canonical wire, and no retained
same-relation proof.

The exact paper-expression screen pads `max(m,n)` into `rows * ell`, uses the
paper's improved `e=k`, `n_code=3k` choice, and minimizes the printed Section
5.3 expression.  At source error `2^-264` and a 640-bit Merkle/transcript output
it selects `k=32768`, `ell=32267`, `rows=634`, `sigma=5`, `t=455`, and evaluates
to 16,437,920 bytes.  This is neither a measured proof nor a lower/upper proof
bound: the paper does not define Hegemon's canonical wire, adapter, root/salt
framing, or exact BCS/CMS compilation.

BCS's direct statistical-ZK term uses total IOP proof length `p(x)` in bits,
not the number of Merkle leaves.  Even the optimistic floor contributed by the
screened field transcript is 126,552,960 bits for the source-264 profile.  At
lambda 512 this term has only about 99.08 security bits.  Lambda 632 is merely
the first byte-aligned value that passes this floor term in isolation; actual
`p(x)` and the required lambda remain unknown.

The optimized `e=k,n=3k` arithmetic is explicitly tied to Section 5.3 and the
later Appendix C `e<d/2` refined analysis.  It is not a direct instantiation of
Theorem 4.7's printed `e<(n-k)/4` premise.  The ledger preserves this boundary
instead of treating the printed theorem and refined size profile as identical.

BooLigero changes the arithmetic to binary extension fields, so it needs a new
proved compiler rather than reusing the frozen odd-field R1CS.  Ligerito is a
non-ZK PCS/inner-product construction and lacks an applicable RBR theorem.
Flock explicitly does not provide zero knowledge and its evaluated profiles
use SHA-256 at 100/120-bit targets.  Ligero++ is not promoted because a pinned
full primary source and exact construction audit were unavailable.

CFW26's 105-oracle carrier remains theorem-unauthorized: in addition to the
coefficient and typed-main-form defects, the printed endpoint `st2` selects the
coefficient of X rather than evaluating at one; `s=X^2-X` is an honest
counterexample.  ProveKit remains ineligible because its complete whole-view ZK
and finite-QROM composition are absent and a 256-bit binding surface has an
85.33-bit generic quantum collision ceiling.

## Claim boundary

This package is a negative architecture screen and exact arithmetic receipt.
It selects no architecture, proves no exact relation refinement, measures no
proof, establishes no composed PQ/QROM security, and changes no production
code.  Every authority gate remains false and all proof-byte fields remain
null.
