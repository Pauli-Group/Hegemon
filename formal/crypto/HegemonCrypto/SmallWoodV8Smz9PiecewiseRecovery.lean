import HegemonCrypto.SmallWoodV8Smz9PiecewiseCoverage
import HegemonCrypto.SmallWoodV8Smz9RobustQueryMismatch
import HegemonCrypto.SmallWoodV8Smz9JointQuerySampling
import Mathlib.Data.List.FinRange

/-!
# A specified finite-list DECS recovery procedure

Scan a source-fixed finite list for the first candidate whose full polynomial
projection equals the matrix-dependent response. For a source covered by that list,
the deterministic patch theorem proves this scan succeeds on large agreement.
Failure to return a candidate consistent with the queried source is charged to
small agreement or the previously proved fixed-family affine mismatch event.

This procedure recovers only a DECS polynomial candidate. The list must actually
cover the source, is not constructed here from arbitrary committed data, and is
fixed before the matrix in the subsequent finite probability experiment. No PIOP
or transaction witness validity, quantum extraction, or runtime refinement follows.
-/

namespace HegemonCrypto.SmallWood.V8Smz9PiecewiseRecovery

open Polynomial
open scoped BigOperators
open V8Smz9RobustQueryMismatch

noncomputable section

set_option maxRecDepth 5000

/-- A finite scan in index order; the query subset is not an input. -/
def selectCandidate {count : ℕ} (candidates : Fin count → Candidate)
    (response : Response) (matrix : Matrix) : Option (Fin count) := by
  classical
  exact (List.finRange count).find? fun index =>
    decide (ResponseConsistent (candidates index) response matrix)

theorem selected_candidate_is_response_consistent {count : ℕ}
    (candidates : Fin count → Candidate) (response : Response) (matrix : Matrix)
    (index : Fin count) (selected : selectCandidate candidates response matrix = some index) :
    ResponseConsistent (candidates index) response matrix := by
  classical
  change (List.finRange count).find? (fun label =>
    decide (ResponseConsistent (candidates label) response matrix)) = some index at selected
  have hit := List.find?_some (p := fun label : Fin count =>
    decide (ResponseConsistent (candidates label) response matrix)) selected
  exact of_decide_eq_true hit

theorem selection_is_none_iff_no_projecting_candidate {count : ℕ}
    (candidates : Fin count → Candidate) (response : Response) (matrix : Matrix) :
    selectCandidate candidates response matrix = none ↔
      ∀ index, ¬ ResponseConsistent (candidates index) response matrix := by
  classical
  simp only [selectCandidate, List.find?_eq_none, List.mem_finRange, forall_true_left,
    decide_eq_true_eq]

def agreement (source : Source) (response : Response) (matrix : Matrix) : Finset Position :=
  V8Smz9PiecewiseCoverage.responseAgreement source.data source.masks matrix (response matrix)

theorem query_accepts_iff_subset_agreement (source : Source) (response : Response)
    (matrix : Matrix) (challenge : Challenge) :
    QueryAccepts source response matrix challenge ↔ challenge.val ⊆ agreement source response matrix := by
  classical
  constructor
  · intro accepts index member
    apply Finset.mem_filter.mpr
    exact ⟨Finset.mem_univ _, fun row => (accepts index member row).symm⟩
  · intro subset index member row
    exact ((Finset.mem_filter.mp (subset member)).2 row).symm

theorem large_agreement_selects_candidate {count : ℕ}
    (source : Source) (candidates : Fin count → Candidate)
    (exceptions : Finset Position) (degree : ℕ)
    (cover : ∀ position, position ∉ exceptions → ∃ index,
      position ∈ V8Smz9PiecewiseCoverage.sourcePatch source.data source.masks
        (candidates index).data (candidates index).masks)
    (dataBound : ∀ index column, ((candidates index).data column).natDegree ≤ degree)
    (maskBound : ∀ index row, ((candidates index).masks row).natDegree ≤ degree)
    (response : Response) (responseBound : ∀ matrix row, (response matrix row).natDegree ≤ degree)
    (matrix : Matrix)
    (large : exceptions.card + count * degree < (agreement source response matrix).card) :
    selectCandidate candidates response matrix ≠ none := by
  classical
  obtain ⟨index, consistent⟩ := V8Smz9PiecewiseCoverage.large_agreement_response_has_fixed_patch_lift
    source.data source.masks (fun index => (candidates index).data)
    (fun index => (candidates index).masks) exceptions degree cover dataBound maskBound
    matrix (response matrix) (responseBound matrix)
    (by rw [Fintype.card_fin]; exact large)
  intro absent
  exact (selection_is_none_iff_no_projecting_candidate candidates response matrix).mp absent index
    consistent

/-- Failure of this specified list scan to produce a query-consistent polynomial candidate. -/
def recoveryFailureEvent {count : ℕ} (source : Source) (candidates : Fin count → Candidate)
    (response : Response) (challenge : Challenge) : Finset Matrix := by
  classical
  exact Finset.univ.filter fun matrix => QueryAccepts source response matrix challenge ∧
    match selectCandidate candidates response matrix with
    | none => True
    | some index => ∃ position ∈ challenge.val, Mismatch source (candidates index) position

def smallAgreementEvent (source : Source) (response : Response) (cutoff : ℕ)
    (challenge : Challenge) : Finset Matrix := by
  classical
  exact Finset.univ.filter fun matrix =>
    (agreement source response matrix).card ≤ cutoff ∧ QueryAccepts source response matrix challenge

-- The naming-only linter unfolds the enormous finite matrix type; kernel checking is unchanged.
set_option linter.constructorNameAsVariable false in
/-- Concrete algorithm failure is covered by a small sampled agreement or a fixed-list mismatch. -/
theorem recovery_failure_subset_small_or_family {count : ℕ}
    (source : Source) (candidates : Fin count → Candidate)
    (exceptions : Finset Position) (degree : ℕ)
    (cover : ∀ position, position ∉ exceptions → ∃ index,
      position ∈ V8Smz9PiecewiseCoverage.sourcePatch source.data source.masks
        (candidates index).data (candidates index).masks)
    (dataBound : ∀ index column, ((candidates index).data column).natDegree ≤ degree)
    (maskBound : ∀ index row, ((candidates index).masks row).natDegree ≤ degree)
    (response : Response) (responseBound : ∀ matrix row, (response matrix row).natDegree ≤ degree)
    (challenge : Challenge) :
    recoveryFailureEvent source candidates response challenge ⊆
      smallAgreementEvent source response (exceptions.card + count * degree) challenge ∪
        familyMismatchEvent source candidates response challenge := by
  classical
  intro matrix member
  rw [recoveryFailureEvent, Finset.mem_filter] at member
  have info := member.2
  clear member
  rw [Finset.mem_union]
  apply (le_or_gt (agreement source response matrix).card (exceptions.card + count * degree)).elim
  · intro small
    apply Or.inl
    rw [smallAgreementEvent, Finset.mem_filter]
    simp only [Finset.mem_univ, true_and]
    exact ⟨small, info.1⟩
  · intro large
    have selected := large_agreement_selects_candidate source candidates exceptions degree
      cover dataBound maskBound response responseBound matrix large
    cases chosen : selectCandidate candidates response matrix with
    | none => exact False.elim (selected chosen)
    | some index =>
      have mismatch : ∃ position ∈ challenge.val, Mismatch source (candidates index) position := by
        simpa only [chosen] using info.2
      apply Or.inr
      rw [familyMismatchEvent, Finset.mem_biUnion]
      refine ⟨index, Finset.mem_univ _, ?_⟩
      rw [mem_robust_mismatch_event]
      exact ⟨selected_candidate_is_response_consistent candidates response matrix index chosen,
        info.1, mismatch⟩

section FiniteUnion

variable {Prefix Outcome : Type*} [Fintype Prefix] [Fintype Outcome] [DecidableEq Outcome]

/-- Finite accepted-pair counting permits a union bound without any event-independence premise. -/
theorem joint_probability_le_sum_of_subset_union
    (event left right : Prefix → Finset Outcome)
    (contained : ∀ context, event context ⊆ left context ∪ right context) :
    FiniteEvents.jointProbability event ≤
      FiniteEvents.jointProbability left + FiniteEvents.jointProbability right := by
  have pointwise (context : Prefix) : FiniteEvents.probability (event context) ≤
      FiniteEvents.probability (left context) + FiniteEvents.probability (right context) := by
    apply (FiniteEvents.probability_mono (contained context)).trans
    unfold FiniteEvents.probability
    rw [← add_div]
    apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
    exact_mod_cast Finset.card_union_le (left context) (right context)
  simp only [FiniteEvents.joint_probability_eq_average]
  rw [← add_div, ← Finset.sum_add_distrib]
  exact div_le_div_of_nonneg_right
    (Finset.sum_le_sum fun context _ => pointwise context) (Nat.cast_nonneg _)

end FiniteUnion

def recoveryFailureProbability {count : ℕ} (source : Source) (candidates : Fin count → Candidate)
    (response : Response) : Rat :=
  FiniteEvents.jointProbability (recoveryFailureEvent source candidates response)

set_option linter.constructorNameAsVariable false in
/-- Joint acceptance-and-recovery-failure bound for the specified list scan and a verified cover.
The list is fixed in the actual matrix/exact-twenty-subset product experiment. -/
theorem piecewise_recovery_failure_probability_le {count : ℕ}
    (source : Source) (candidates : Fin count → Candidate)
    (exceptions : Finset Position) (degree : ℕ)
    (cover : ∀ position, position ∉ exceptions → ∃ index,
      position ∈ V8Smz9PiecewiseCoverage.sourcePatch source.data source.masks
        (candidates index).data (candidates index).masks)
    (dataBound : ∀ index column, ((candidates index).data column).natDegree ≤ degree)
    (maskBound : ∀ index row, ((candidates index).masks row).natDegree ≤ degree)
    (response : Response) (responseBound : ∀ matrix row, (response matrix row).natDegree ≤ degree) :
    recoveryFailureProbability source candidates response ≤
      (Nat.choose (exceptions.card + count * degree) 20 : Rat) /
        Nat.choose V8Smz9LogicalOracle.decsDomainSize 20 +
      count * (((1 : Rat) / Fintype.card Goldilocks) ^ 5) := by
  classical
  have smallEventEq (cutoff : ℕ) : smallAgreementEvent source response cutoff =
      V8Smz9JointQuerySampling.smallAgreementPrefixEvent (agreement source response) cutoff := by
    funext challenge
    apply Finset.ext
    intro matrix
    rw [V8Smz9JointQuerySampling.mem_small_agreement_prefix_event]
    simp only [smallAgreementEvent, Finset.mem_filter, Finset.mem_univ, true_and,
      query_accepts_iff_subset_agreement]
  have smallBound := V8Smz9JointQuerySampling.query_outer_small_agreement_probability_le
    (agreement source response) (exceptions.card + count * degree)
  rw [← smallEventEq] at smallBound
  have familyBound := fixed_family_mismatch_probability_le source candidates response
  rw [Fintype.card_fin] at familyBound
  have unionBound := joint_probability_le_sum_of_subset_union
    (recoveryFailureEvent source candidates response)
    (smallAgreementEvent source response (exceptions.card + count * degree))
    (familyMismatchEvent source candidates response)
    (fun challenge => recovery_failure_subset_small_or_family source candidates exceptions degree
      cover dataBound maskBound response responseBound challenge)
  exact unionBound.trans (add_le_add smallBound familyBound)

end

end HegemonCrypto.SmallWood.V8Smz9PiecewiseRecovery
