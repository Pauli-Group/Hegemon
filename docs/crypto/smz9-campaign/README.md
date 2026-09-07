# SMZ9 privacy and soundness research dossier

Date: 2026-09-07 UTC. Target: unchanged HGV8RP03 / SMZ9 profile 6.

## Decision

**End-to-end privacy and quantum knowledge soundness are not established.** This
campaign lands checked local mathematics and a concrete rejection of the current
soundness proof shortcut. It does not enable a proof profile, grant a security
receipt, or claim that an SMZ9 transaction has been forged.

The initial positive privacy result is the exact LVCS later-challenge law: the 240
combination-tail words and the 2,560 subsequent subset evaluations retain their
joint law when the later challenge depends on those earlier words. The proof
includes the source head/tail interpolation split and an abstract failure branch,
conditional on fixed public context and an admissibility-certified selector.
Runtime selector/error refinement and placement inside a valid commitment-hiding
quantum experiment remain open.

The follow-up now derives the required fresh LVCS tails after the generated
public prefix inside the independent-randomized-leaf hybrid. It preserves the
original masks and correlated final overlay and composes both abort levels.
The first ideal-QROM transition into this hybrid now has a reviewed reduction
to the published adaptive-reprogramming theorem, with exact source-shaped fresh
input laws and physical query constructions checked in Lean. The published
distance theorem itself is external. Post-proof hidden-leaf treatment and
concrete/runtime refinements remain open; restricted non-leaf equality alone
would not supply this new transition.

On soundness, the fixed two-monomial source now has a complete Lean bound for
matrix-dependent responses followed by fresh twenty-subset queries. General
independent-support and affine-incidence identities are also proved. The
reviewed same-support weighted bound suppresses a high-rank branch, but its
approximately 286.64-bit partial sum explicitly omits large-agreement local
ranks 1 through 19. It is not an accepted-proof or quantum-security bound.

The concrete current-coset high-rank count is now proved in Lean, including
Vandermonde independence, quotient dimension and adaptive agreement selection.
A separate specified finite-list scan now has a complete joint finite-experiment
bound: if L fixed polynomial patches of degree 387 cover the source except at
h positions, its accepted-query recovery failure is at most
`choose(387L+h,20)/choose(2^23,20) + L/p^5`. This recovers a query-consistent
DECS candidate, not a valid transaction witness. Constructing such a small cover
for arbitrary malicious sources remains open.

The decisive soundness finding is that the full-domain fixed-oracle `p^-5` event
does not bound a completion selected after the matrix challenge. The new
fixed-source construction exhibits that failure. The published SmallWood
support-union bound is already greater than one at the current parameters, so
it cannot supply the missing extraction theorem.

## Evidence and scope

| Artifact | Result | Boundary |
| --- | --- | --- |
| [Triangular algebraic law](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9TriangularAlgebraicLaw.lean) | Explicit inverse and joint uniform/history laws with retained-output challenge feedback | Requires the first projection to be independent of the later challenge |
| [Exact local privacy steps](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9SingleProofPrivacy.lean) | Source-shaped LVCS feedback/abort law; simulator high-coordinate injection; explicit target-first counterexample | Not complete proof-byte or quantum-oracle privacy |
| [Accumulated-support analysis](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9AccumulatedExtraction.lean) | Fixed two-indicator source, zero response, adaptive support obstruction; corrected fixed-family `L*p^-5` bound | Not an extractor, efficient attack, or full-verifier forgery |
| [Published-bound no-go](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9PublishedBound.lean) | `choose(2^23,389) >= 2^5446`; published first error term exceeds one | Certificate vacuity, not a lower bound on forgery probability |
| [Privacy argument](privacy-argument.md) | Honest-side chronological hybrid and exact completed/missing transitions | Hidden-leaf, commitment-feedback, and full quantum composition remain unproved |
| [Soundness argument](soundness-argument.md) | Source selection analysis, published bound, stronger externally justified support-count obstruction, and repair constraints | External combinatorial results are not mechanized Lean results |
| [Quantum reduction assessment](quantum-reduction.md) | Exact reprogramming hypotheses, generic four-stage compiler loss, CMS applicability and global resource accounting | No concrete SHA-512 or source-specific instability certificate |
| [Independent review](independent-review.md) | Separate adversarial source review of claims and constructions | Internal research review, not external cryptographic certification |
| [Security contract](security-contract.md) | Fixed game endpoints, semantic target, physical quantum operations and resource meanings | A specification of acceptance, not satisfaction of it |
| [Sampled acceptance](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9SampledAcceptance.lean) | Exact two-zero-column probability and fresh-subset mixture bound for arbitrary matrix-dependent responses | Fixed two-monomial source only; not general extraction |
| [Rank incidence binding](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9RankIncidenceBinding.lean) | Concrete Vandermonde/quotient bridge, exact five-row support fibers and adaptive current-coset high-rank count | Weighted exact-20 composition, low-rank coverage and verifier/QROM binding remain separate |
| [Joint extraction research](joint-extraction-research.md) | Same-agreement-set weighted bound; constructive small-global-dimension decoder; robust fixed-list mismatch lemma | Low-local-rank large-agreement coverage and semantic witness extraction remain open |
| [Honest hybrid](honest-hybrid-research.md) | Generated-prefix LVCS freshness, retained-overlay coupling, literal role separation and restricted oracle delay | Ideal randomized leaves; no unrestricted QROM transition |
| [Exhaustive diagnostic](../../../scripts/smz9_joint_acceptance_probe.py) | Exact small-field response optimization, affine-rank checks and current-profile partial arithmetic | Not a security certificate or Goldilocks exhaustive search |
| [Specified piecewise recovery](../../../formal/crypto/HegemonCrypto/SmallWoodV8Smz9PiecewiseRecovery.lean) | First-projecting-candidate scan and joint exact-20 failure bound, composing patch coverage and `L/p^5` mismatch | Requires a prefix-fixed cover; no arbitrary-source construction or witness-semantic claim |
| [Piecewise recovery research](piecewise-recovery-research.md) | Global-rank-140 two-patch case; exact screens; guards against inadequate interpolated lifts and rank-collapse claims | Research examples do not restrict arbitrary malicious sources |
| [First hidden-leaf QROM transition](hidden-leaf-qrom-step.md) | Explicit reduction to published adaptive reprogramming; checked fresh-input law and two-query domain simulation | External distance theorem, ideal tape/oracle model, persistent overlay and explicit query costs |

The original [SmallWood paper, revision 20260213:134127](https://eprint.iacr.org/archive/2025/1085/20260213:134127)
charges `choose(N,d_decs+2)/p^eta` even for full uniform matrices (Theorem 1,
Equation 14). Substitution gives approximately `2^5835.76`; the Lean no-go
does not depend on that floating approximation. Increasing the number of
matrix coefficients alone therefore does not justify deleting the support
factor. A new event-specific extractor or sufficiently strong masked/interleaved
proximity theorem is required.

## Verification and landing

The six-module continuation passes the full coordinator gate: **2,754 jobs,
145 allowed-axiom roots**, unchanged wire vectors and all 48 exact generated
program modules. Minimum sampled free disk was 40.176918 GiB. Independent
mathematical review approves the scope and probability composition. The exhaustive probe
now has eleven passing tests; the [hidden-leaf arithmetic checker](../../../scripts/smz9_hidden_leaf_qrom_screen.py)
has three. These include exact boundary/successor comparisons, explicit
inclusive-query feasibility limits, and the separate two-query domain-reduction
accounting. An initial build caught one omitted explicit type binder; the
corrected source passes the complete strict gate. No theorem statement or
checking policy was weakened. The prior checkpoint below is historical.

Local commit `814b68fb` preserves the first joint-event checkpoint, which passed **2,748 jobs
and 129 audited roots**, unchanged wire vectors and all 48 exact generated
program modules. Minimum sampled free disk was 40.133030 GiB. Its eight probe
tests pass; three default experiments enumerate 99,771 matrices and check 229
fixed supports and 20 rank strata. A separate literal enumerator agreed on 733
tiny cases. The profile screen verifies exact rational integer-floor bounds
while explicitly retaining the omitted low-rank branch. These results are
recorded in the [joint-event ExecPlan](../../../.agent/SMZ9_JOINT_ACCEPTANCE_EXECPLAN.md).

The preceding managed-campaign checkpoint is retained below as historical
verification, not substituted for the current gate.

The prior ideal-event checkpoint was preserved in local commit `de2f827d`.
That checkpoint's modules were imported into the formal-crypto umbrella and their key
closures are listed in the 114-declaration axiom inventory. The following
coordinator-run gate passed on 2026-09-07 UTC:

```sh
HEGEMON_FORMAL_CRYPTO_MIN_FREE_GIB=40 bash scripts/check_formal_crypto.sh
git diff --check
```

The complete build passed 2,745 jobs; all 114 credited declarations use only
`propext`, `Classical.choice`, and `Quot.sound`. All three generated wire vectors
and all 48 generated-program modules match their source artifacts. The first
integrated attempt rejected one unnecessary `simpa` under warnings-as-errors;
the corrected proof passes without changing its statement or the lint policy.
The successful run's minimum sampled disk availability was 40.0605 GiB under
a guard preserving the 40 GiB reserve. Its outcome is recorded in the living
[ExecPlan](../../../.agent/SMALLWOOD_POSEIDON2_PRODUCTION_EXECPLAN.md).
Source review separately checks theorem adequacy; a passing gate does not
turn these local results into either security endpoint.

The independent review is retained at its pre-integration snapshot. Its wording
findings were corrected in the argument and summaries: the LVCS theorem fixes
public context and uses an admissibility-certified selector; its abstract `none`
branch is not Rust error refinement; and ideal RNG independence is not inferred
from `CryptoRng`. The security contract now labels its identity table a summary
and includes canonical program, parameter-set, and zero-grinding bindings.

No Rust runtime, wire format, dependency, node/wallet state, retained proof,
successor selection, or production capability is changed by this campaign.
The pre-existing AGENTS and testnet-skill edits remain outside its commits.

## Remaining research decision

Keep the carrier and production gate unchanged. Privacy continues from the
honest-order randomized-leaf hybrid, with generated-prefix freshness now derived
and the correlated final overlay retained. Its first ideal-QROM transition is
externally justified by the reviewed adaptive-reprogramming reduction; final
hidden-leaf treatment, whole-witness independence, runtime refinement and full
history composition remain separate obligations.
Soundness must replace the invalid selected-completion event bound before any
CMS arithmetic is credited. The report's stronger support-count obstruction
also rules out simply assigning the old 288-bit screen to that broad event.
Neither a new record of assumed probabilities nor the old published theorem
can fill that gap. No protocol redesign or parameter change is silently
authorized by these findings.
