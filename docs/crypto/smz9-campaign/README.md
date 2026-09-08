# SMZ9 privacy and soundness research dossier

Date: 2026-09-07 UTC. Target: repaired 853,429-byte program in the HGV8RP03
format lineage / SMZ9 profile 6, SHA-512
`180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`.

## Decision

**End-to-end privacy and quantum knowledge soundness are not established.** This
campaign lands checked local mathematics and a concrete rejection of the current
soundness proof shortcut. It does not enable a proof profile, grant a security
receipt, or claim that an SMZ9 transaction has been forged.

## Current continuation

The repaired-source snapshot `cee3cb81` now has two independently generated,
cross-verified 122,543-byte proofs and a completed real HTTP/PQ socket
lifecycle for both. Exact bytes and canonical state survive relay, mining,
locator/body import, clean restart and fresh-node sync; the separate
in-process reorg test also passes. See the [source-frozen artifact and
carrier receipt](repaired-proof-execution.md#completed-source-frozen-local-carrier-milestone).
This is local integration evidence with production authority still disabled.

The [actual Rust scalar refinement](native-scalar-refinement.md) now covers
subtraction/inverse for canonical U64 operands and addition/multiplication
for all U64 operands, including successful checked arithmetic, actual
inverse-loop termination and exact original Lean field results. Its isolated
nine-root v2 and five-root inverse-v3 evidence gates pass; this is not yet
the complete expression evaluator or R0.

The [honest-construction and batch-law increment](honest-construction-and-batch-law.md)
now constructs all 43,904 canonical words from the typed witness and
actual ordered 125-call hash schedule, without supplied auxiliary/hash/tail
inputs. It derives all five nonlinear range roots, seven actual sparse
reconstruction residuals, all 15,561 raw replication residuals and all 332
generated hash roots, with exact raw source-frame and packed hash readbacks.
The next source proofs add 1,920 actual Merkle CSR residuals and 26 stable
selector/inverse/Boolean/radix roots on that same constructed candidate.
Another 64 policy-initial attempts and all early, balance, inline and
multiplication roots first gave 17,552 CSR attempts and 488 nonlinear roots.
The next reviewed increment derives 496 stable-tail CSR attempts, all
448 inactive-Merkle-right attempts and 145 authorization roots. Coverage is
now 18,496/20,605 CSR attempts and 633/830 nonlinear roots. The remaining
197 nonlinear positions are exactly `252..448`; the 2,109 remaining CSR
attempts are tracked separately.
It also proves the remaining-count sampler's exact
finite ideal trace law. Full packed acceptance and remaining generated
equations are active work; no accepted-packed premise claims their completion.

The [complete-security ExecPlan](../../../.agent/SMZ9_COMPLETE_SECURITY_EXECPLAN.md)
retains both complete game endpoints as the acceptance condition. The following
table is an earlier ingredient ledger: its per-module original boundaries
are not a current inventory of aggregate endpoint gaps. The completed modeled
source-lifetime privacy and packed semantic endpoints described below
supersede their corresponding local gaps. The full integrated formal gate
passes all 1,356 credited roots; these results are not a completed concrete
security argument.

| Earlier ingredient | What is established | Original local boundary |
| --- | --- | --- |
| [Eager privacy](eager-privacy-proof.md), [public simulator](eager-simulator-proof.md), [current-program adapter](current-program-piop-proof.md) | Explicit joint PIOP/DECS inverse, correct cross-column PCS map, dependent witness/PCS/LVCS law, public reconstruction and actual field-expression adapter | Honest whole-byte correspondence and complete quantum-game composition |
| [Hidden patch](hidden-patch-proof.md) and [game composition](privacy-game-composition-proof.md) | Physical raw-domain full-versus-opened oracle bound `4Q / 2^256`, including retained context and arbitrary future queries, with no tree-size union factor | Source-generated outer experiment, initial reprogramming and final composed privacy bound |
| [Arbitrary-source recovery](mca-recovery-proof.md) | Exact joint coefficient/twenty-subset failure bound in terms of a defined weighted MCA budget; specified pre-query interpolation decoder and complete response projection | Concrete unrestricted budget bound and quantum extraction of its input table |
| [PIOP soundness](piop-soundness-proof.md) | Fixed-pre-batching-candidate bound `p^-5 + epsilon3` for arbitrary later transcripts and fresh admissible six-point queries | Candidate extraction, current constraint-family instantiation and raw Fiat–Shamir transfer |
| [Current program polynomials](program-polynomials-proof.md) | All 8,271 actual field-expression instructions, degree-zero inverse/selector checks, degree at most 552 for all 830 roots, and source-interpreter evaluation correspondence | Full polynomial/PCS/Rust execution pipeline |
| [Current opening binding](current-program-opening-binding.md) and [indexed privacy game](current-privacy-game-proof.md) | Actual 736-column/140-row source reconstruction, equality of genuine opened suffixes, and randomized-label source versus witness-free reference loss `4Q / 2^256` | Earlier honest-hash QROM hybrids, exact public CSR binding and Rust execution |
| [Merkle extraction geometry](coherent-merkle-geometry-proof.md) | Deterministic finite recorded-map extractor, exact raw-key framing and classical instability `3t / 2^512` through both wrappers | Physical coherent extraction commutator, accepted-opening consistency and full quantum transfer |
| [Semantic binding](semantic-adequacy-proof.md), [dense values](semantic-dense-range-proof.md), [typed projection](semantic-decoder-proof.md) | Accepted-source Boolean/zero/radix constraints, seven integer 61-bit bounds, typed note values and positions, exact one-hot authorization mode | Complete canonical witness, hash/authorization/integer-conservation/stablecoin semantics and Rust refinement |
| [Asset membership](semantic-asset-membership-proof.md) | Actual nonlinear roots force each active note into one of the four public assets and derive the typed one-hot selectors | Integer conservation and the other full semantic families |

The [weighted-MCA research](weighted-mca-research.md) proves the requested
weighted bound through global quotient dimension four, using finite incidence
and a published list-correlated-agreement theorem. Unrestricted dimensions
five and six remain unproved. Its additional rational-pole family exclusion
does not close that universal gap.

Two earlier source-binding claims required correction. The legacy PCS map used
a same-column subtraction; Rust subtracts from the next column. New privacy
modules use the corrected map, while the verifier's conservative old opening
admissibility policy remains unchanged. The semantic padding asset is
`u64::MAX mod p = 4294967294`, not `p-1`. Public canonicality is a frontend
admission condition, not a consequence of raw packed equations. These changes
correct the model and claim boundaries, not the runtime protocol.

The coordinator's temporary 40 GiB cutoff was not a user requirement and has
been removed. Bounded warm compilation continues with disk monitoring. Only
two validated disposable Cargo incremental-cache directories were reclaimed;
proof artifacts, dependencies, node/wallet state and Lean caches were preserved.
`McaSourceBinding`, the completed `EagerOracleGame` comparison, and
`CurrentProgramPiop` now pass strict checks and central builds. The integrated
207-root crypto gate passed (2,770 jobs), as did all 2,745 base claimed-theorem
axiom checks and the relevant generated semantic vectors. The expanded
integration now also passes: **2,776 jobs and 238 audited declarations**,
unchanged wire vectors and all 48 generated program files. This includes the
source-opening/privacy/asset/Merkle modules, the
[raw-counter compiler](raw-counter-compiler-proof.md), and the
[factor-free recovery bound](random-direction-recovery-proof.md).
The corrected source gamma cap is included: it depends on retained linear
rows. The pre-repair checkpoint bounded it by 12,860 raw blocks; the repaired
20,605-attempt relation raises the current bound to 12,883, not the earlier
523-block nonlinear-only undercount. The generic two-query simulation is unchanged.

The refreshed policy checks passed the 121-node claims/blueprint policies,
six system-model gates and bridge vectors. The broader formal-core policy
script subsequently failed at its unchanged native-backend review-bundle
guard: the unsupported BLAKE2b-384 production relation cannot be authorized
by legacy Poseidon review vectors. That unrelated refusal is retained;
the entire policy script is not reported as passing.

The current quantum-framework review derives a leading `320 t^2 kappa` loss;
it does not treat the published framework as an automatic source instantiation.
A proof-only random-direction argument has passed the full exact probability
and source-decoder proof, replacing the 140-column union factor by `p/(p-1)`.
The unrestricted weighted budget remains open; neither improvement is an
endpoint receipt.

The sections below retain the prior landed checkpoint and historical rationale;
their older gate counts do not certify the current continuation.

## Earlier checkpoint

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

## Earlier verification and landing

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

## Remaining complete-proof obligations

Keep the carrier and production gate unchanged. Privacy must connect the new
public simulator and physical hidden-patch theorem to the actual admitted
statement, current field-expression program, complete bytes, persistent oracle,
all aborts and the complete history experiment. An old arithmetic-expression
interface is not an identification with the live `FieldExpression` program.

Soundness requires the still-open unrestricted weighted-MCA bound, a coherent
commitment substitution and extraction procedure with exact raw-oracle resource
losses, and complete semantic adequacy of the extracted witness. The older
classical measured-database extractor and postulated CMS accounting do not
establish that chronology. Neither the old support-union theorem nor a record
containing the desired success probability supplies these missing results.
No redesign, parameter change, release, deletion or reserve relaxation is
silently authorized.
