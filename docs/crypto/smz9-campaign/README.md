# SMZ9 privacy and soundness research dossier

Date: 2026-09-07 UTC. Target: unchanged HGV8RP03 / SMZ9 profile 6.

## Decision

**End-to-end privacy and quantum knowledge soundness are not established.** This
campaign lands checked local mathematics and a concrete rejection of the current
soundness proof shortcut. It does not enable a proof profile, grant a security
receipt, or claim that an SMZ9 transaction has been forged.

The positive privacy result is the exact LVCS later-challenge law: the 240
combination-tail words and the 2,560 subsequent subset evaluations retain their
joint law when the later challenge depends on those earlier words. The proof
includes the source head/tail interpolation split and an abstract failure branch,
conditional on fixed public context and an admissibility-certified selector.
Runtime selector/error refinement and placement inside a valid commitment-hiding
quantum experiment remain open.

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

The original [SmallWood paper, revision 20260213:134127](https://eprint.iacr.org/archive/2025/1085/20260213:134127)
charges `choose(N,d_decs+2)/p^eta` even for full uniform matrices (Theorem 1,
Equation 14). Substitution gives approximately `2^5835.76`; the Lean no-go
does not depend on that floating approximation. Increasing the number of
matrix coefficients alone therefore does not justify deleting the support
factor. A new event-specific extractor or sufficiently strong masked/interleaved
proximity theorem is required.

## Verification and landing

The prior ideal-event checkpoint was preserved in local commit `de2f827d`.
The new modules are imported into the formal-crypto umbrella and their key
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

Keep the carrier and production gate unchanged. Privacy can continue from the
explicit honest-side hybrid, now with its source-shaped local LVCS feedback
pattern proved under the stated fixed-context and selector premises.
Soundness must replace the invalid selected-completion event bound before any
CMS arithmetic is credited. The report's stronger support-count obstruction
also rules out simply assigning the old 288-bit screen to that broad event.
Neither a new record of assumed probabilities nor the old published theorem
can fill that gap. No protocol redesign or parameter change is silently
authorized by these findings.
