import HegemonCrypto.SmallWoodV8Smz9AdmissibleRootProbability
import Mathlib.Algebra.Polynomial.BigOperators

/-!
# Constructive response coverage by a fixed piecewise polynomial source

On the actual SMZ9 evaluation domain, suppose a fixed list of common data/mask
polynomial tuples covers the committed source except at a specified set of positions.
Any degree-387 response with agreement larger than `387 * list size + exceptions`
must equal the matrix projection of a tuple in that same fixed list.

This is a deterministic coverage theorem, valid for every matrix and response.
It does not assert that an arbitrary source admits a small cover, that twenty opened
positions bind a unique tuple, that the tuple satisfies PIOP/transaction semantics,
or that Fiat--Shamir challenges follow an independent uniform law.
-/

namespace HegemonCrypto.SmallWood.V8Smz9PiecewiseCoverage

open Polynomial
open scoped BigOperators
open V8Smz9AdmissibleRootProbability V8Smz9AdaptiveFiniteAccounting

noncomputable section

set_option maxRecDepth 5000

abbrev Position := Fin V8Smz9DisjointCoset.domainSize
abbrev DataRow := Fin V8Smz9LogicalOracle.decsRowCount
abbrev MaskRow := Fin V8Smz9LogicalOracle.decsEta
abbrev Matrix := MaskRow → DataRow → Goldilocks
abbrev DataWords := DataRow → Position → Goldilocks
abbrev MaskWords := MaskRow → Position → Goldilocks
abbrev DataPolynomials := DataRow → Goldilocks[X]
abbrev MaskPolynomials := MaskRow → Goldilocks[X]

def projectedCandidate (matrix : Matrix) (data : DataPolynomials)
    (masks : MaskPolynomials) (row : MaskRow) : Goldilocks[X] :=
  (∑ column, C (matrix row column) * data column) + masks row

def sourcePatch (words : DataWords) (masks : MaskWords)
    (candidateData : DataPolynomials) (candidateMasks : MaskPolynomials) : Finset Position := by
  classical
  exact Finset.univ.filter fun index =>
    (∀ column, words column index =
      (candidateData column).eval (V8Smz9DisjointCoset.evaluationPoint index)) ∧
    (∀ row, masks row index =
      (candidateMasks row).eval (V8Smz9DisjointCoset.evaluationPoint index))

def responseAgreement (words : DataWords) (masks : MaskWords)
    (matrix : Matrix) (response : MaskPolynomials) : Finset Position := by
  classical
  exact Finset.univ.filter fun index => ∀ row,
    (response row).eval (V8Smz9DisjointCoset.evaluationPoint index) =
      (∑ column, matrix row column * words column index) + masks row index

theorem projected_candidate_degree_le (matrix : Matrix) (data : DataPolynomials)
    (masks : MaskPolynomials) (degree : ℕ)
    (dataBound : ∀ column, (data column).natDegree ≤ degree)
    (maskBound : ∀ row, (masks row).natDegree ≤ degree) (row : MaskRow) :
    (projectedCandidate matrix data masks row).natDegree ≤ degree := by
  apply (natDegree_add_le _ _).trans
  apply max_le
  · exact natDegree_sum_le_of_forall_le _ _ fun column _ =>
      (natDegree_C_mul_le _ _).trans (dataBound column)
  · exact maskBound row

theorem agreement_on_patch_matches_projected_candidate
    (words : DataWords) (masks : MaskWords) (matrix : Matrix)
    (response : MaskPolynomials) (candidateData : DataPolynomials)
    (candidateMasks : MaskPolynomials) (index : Position)
    (agrees : index ∈ responseAgreement words masks matrix response)
    (onPatch : index ∈ sourcePatch words masks candidateData candidateMasks) (row : MaskRow) :
    (response row).eval (V8Smz9DisjointCoset.evaluationPoint index) =
      (projectedCandidate matrix candidateData candidateMasks row).eval
        (V8Smz9DisjointCoset.evaluationPoint index) := by
  classical
  have hresponse := (Finset.mem_filter.mp agrees).2 row
  have hpatch := (Finset.mem_filter.mp onPatch).2
  simp_rw [hpatch.1, hpatch.2] at hresponse
  simpa only [projectedCandidate, eval_add, eval_finsetSum, eval_mul, eval_C] using hresponse

theorem disagreement_limits_patch_agreement
    (words : DataWords) (masks : MaskWords) (matrix : Matrix)
    (response : MaskPolynomials) (candidateData : DataPolynomials)
    (candidateMasks : MaskPolynomials) (degree : ℕ)
    (responseBound : ∀ row, (response row).natDegree ≤ degree)
    (dataBound : ∀ column, (candidateData column).natDegree ≤ degree)
    (maskBound : ∀ row, (candidateMasks row).natDegree ≤ degree)
    (different : ∃ row, response row ≠ projectedCandidate matrix candidateData candidateMasks row) :
    ((responseAgreement words masks matrix response) ∩
      sourcePatch words masks candidateData candidateMasks).card ≤ degree := by
  classical
  obtain ⟨row, different⟩ := different
  let discrepancy := response row - projectedCandidate matrix candidateData candidateMasks row
  have nonzero : discrepancy ≠ 0 := sub_ne_zero.mpr different
  have degreeBound : discrepancy.natDegree ≤ degree :=
    (natDegree_sub_le _ _).trans (max_le (responseBound row)
      (projected_candidate_degree_le matrix candidateData candidateMasks degree dataBound maskBound row))
  have subset : (responseAgreement words masks matrix response) ∩
      sourcePatch words masks candidateData candidateMasks ⊆ decsRootIndices discrepancy := by
    intro index member
    obtain ⟨agrees, onPatch⟩ := Finset.mem_inter.mp member
    apply Finset.mem_filter.mpr
    refine ⟨Finset.mem_univ _, ?_⟩
    change (response row - projectedCandidate matrix candidateData candidateMasks row).eval _ = 0
    rw [eval_sub, agreement_on_patch_matches_projected_candidate words masks matrix response
      candidateData candidateMasks index agrees onPatch row, sub_self]
  exact (Finset.card_le_card subset).trans ((decs_root_indices_card_le nonzero).trans degreeBound)

/-- A fixed source cover supplies actual response coverage; no post-matrix candidate list is chosen. -/
theorem large_agreement_response_has_fixed_patch_lift
    {Patch : Type*} [Fintype Patch]
    (words : DataWords) (masks : MaskWords)
    (candidateData : Patch → DataPolynomials) (candidateMasks : Patch → MaskPolynomials)
    (exceptions : Finset Position) (degree : ℕ)
    (cover : ∀ index, index ∉ exceptions → ∃ patch,
      index ∈ sourcePatch words masks (candidateData patch) (candidateMasks patch))
    (dataBound : ∀ patch column, (candidateData patch column).natDegree ≤ degree)
    (maskBound : ∀ patch row, (candidateMasks patch row).natDegree ≤ degree)
    (matrix : Matrix) (response : MaskPolynomials)
    (responseBound : ∀ row, (response row).natDegree ≤ degree)
    (large : exceptions.card + Fintype.card Patch * degree <
      (responseAgreement words masks matrix response).card) :
    ∃ patch, ∀ row, response row =
      projectedCandidate matrix (candidateData patch) (candidateMasks patch) row := by
  classical
  by_contra noPatch
  push Not at noPatch
  let matched : Patch → Finset Position := fun patch =>
    (responseAgreement words masks matrix response) ∩
      sourcePatch words masks (candidateData patch) (candidateMasks patch)
  have patchBound (patch : Patch) : (matched patch).card ≤ degree :=
    disagreement_limits_patch_agreement words masks matrix response
      (candidateData patch) (candidateMasks patch) degree responseBound
      (dataBound patch) (maskBound patch) (noPatch patch)
  have subset : responseAgreement words masks matrix response ⊆
      exceptions ∪ (Finset.univ : Finset Patch).biUnion matched := by
    intro index member
    by_cases exceptional : index ∈ exceptions
    · exact Finset.mem_union_left _ exceptional
    · obtain ⟨patch, onPatch⟩ := cover index exceptional
      apply Finset.mem_union_right
      exact Finset.mem_biUnion.mpr ⟨patch, Finset.mem_univ _, Finset.mem_inter.mpr ⟨member, onPatch⟩⟩
  have bound : (responseAgreement words masks matrix response).card ≤
      exceptions.card + Fintype.card Patch * degree := by
    calc
      (responseAgreement words masks matrix response).card ≤
          (exceptions ∪ (Finset.univ : Finset Patch).biUnion matched).card := Finset.card_le_card subset
      _ ≤ exceptions.card + ((Finset.univ : Finset Patch).biUnion matched).card := Finset.card_union_le _ _
      _ ≤ exceptions.card + ∑ patch : Patch, (matched patch).card :=
        Nat.add_le_add_left Finset.card_biUnion_le _
      _ ≤ exceptions.card + ∑ _patch : Patch, degree :=
        Nat.add_le_add_left (Finset.sum_le_sum fun patch _ => patchBound patch) _
      _ = exceptions.card + Fintype.card Patch * degree := by simp
  exact (not_lt_of_ge bound) large

end

end HegemonCrypto.SmallWood.V8Smz9PiecewiseCoverage
