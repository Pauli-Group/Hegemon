import HegemonCrypto.NativePrivateSpendQ58Compff01OpeningContinuation
import HegemonCrypto.NativePrivateSpendQ58Compff01ClosedLinearRecovery

/-! One current public factorization boundary. The only relation premise is
actual packed CSR/multiplication validity. The existing closed Fin26210 linear
recovery theorem supplies the mask reconstruction, so no point-wrapper or
symbolic-reduction shard chain is needed. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening
open Polynomial
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9RuntimeFieldLayout V8Smz9EagerPrivacy V8Smz9PiopOpeningRecovery
open V8Smz9ZeroKnowledge V8Smz9EagerSimulator
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- Shared polynomial wrappers are defined before the concrete row type.
Their field and row instances remain parameters of the retained algebra. -/
private def genericLinearTranscript {F : Type*} [Field F] {R : Type*} [Fintype R]
    (packing : Fin 64 → F) (rowWeights : R → Fin 64 → F)
    (witnessPolynomials : R → F[X]) (coins : Fin 132 → F) : F[X] :=
  sourceLinearUnmasked rowWeights (sourcePackingLagrange packing) witnessPolynomials +
    sourceLinearMask packing coins

private def genericLinearResponse {F : Type*} [Field F] {R : Type*} [Fintype R]
    (packing : Fin 64 → F) (rowWeights : R → Fin 64 → F)
    (witnessPolynomials : R → F[X]) (coins : Fin 132 → F) : Fin 132 → F :=
  fun index =>
    (genericLinearTranscript packing rowWeights witnessPolynomials coins).coeff (index.val + 1)

private def genericPublicLinearMask {F : Type*} [Field F] {R : Type*} [Fintype R]
    (packing : Fin 64 → F) (rowWeights : R → Fin 64 → F) (target : F)
    (response : Fin 132 → F) (opened : R → F) (point : F) : F :=
  recoverLinearMaskOpening packing target response rowWeights
    (sourcePackingLagrange packing) opened point

/-- All three shared wrappers are definitionally the original formulas.
This equality is checked abstractly; no concrete finite universe is introduced. -/
private theorem generic_wrapper_definitions_eq {F : Type*} [Field F]
    {R : Type*} [Fintype R]
    (packing : Fin 64 → F) (rowWeights : R → Fin 64 → F)
    (witnessPolynomials : R → F[X]) (coins : Fin 132 → F) (target : F)
    (response : Fin 132 → F) (opened : R → F) (point : F) :
    genericLinearTranscript packing rowWeights witnessPolynomials coins =
      sourceLinearUnmasked rowWeights (sourcePackingLagrange packing) witnessPolynomials +
        sourceLinearMask packing coins ∧
    genericLinearResponse packing rowWeights witnessPolynomials coins =
      (fun index =>
        (sourceLinearUnmasked rowWeights (sourcePackingLagrange packing) witnessPolynomials +
          sourceLinearMask packing coins).coeff (index.val + 1)) ∧
    genericPublicLinearMask packing rowWeights target response opened point =
      recoverLinearMaskOpening packing target response rowWeights
        (sourcePackingLagrange packing) opened point := by
  exact ⟨rfl, rfl, rfl⟩

/-- The recovery identity uses the same shared wrapper heads that the current
public aliases use. Only the true packing-sum, degree and packing premises enter. -/
private theorem generic_public_linear_mask_openings_match {F : Type*} [Field F]
    {R : Type*} [Fintype R]
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (packingCardNonzero : (64 : F) ≠ 0)
    (rowWeights : R → Fin 64 → F) (witnessPolynomials : R → F[X])
    (witnessDegree : ∀ row, (witnessPolynomials row).natDegree ≤ 69)
    (coins : Fin 132 → F) (target : F)
    (valid : (∑ row, ∑ lane : Fin 64,
      rowWeights row lane * (witnessPolynomials row).eval (packing lane)) = target)
    (point : F) :
    genericPublicLinearMask packing rowWeights target
      (genericLinearResponse packing rowWeights witnessPolynomials coins)
      (fun row => (witnessPolynomials row).eval point) point =
      (sourceLinearMask packing coins).eval point := by
  unfold genericPublicLinearMask genericLinearResponse genericLinearTranscript
  exact @V8Smz9PiopOpeningRecovery.source_linear_coins_recovered_from_opened_rows
    F (inferInstance : Field F) R (inferInstance : Fintype R)
    packing injective packingCardNonzero rowWeights witnessPolynomials
    witnessDegree coins target valid point

abbrev Row := Fin 26210
abbrev Lane := Fin 64
abbrev Check := Fin 1344594
abbrev Batch := Fin 5210
abbrev Values := Row → Lane → Goldilocks
abbrev Witness := Row → Goldilocks[X]
abbrev Gamma := Check → Goldilocks
abbrev Term := (Row × Lane) × Goldilocks

def packing : Lane → Goldilocks := fun lane => (lane.val : Goldilocks)

theorem packing_injective : Function.Injective packing := by
  intro left right same
  have equal : (⟨left.val, by omega⟩ : Fin 13173) = ⟨right.val, by omega⟩ :=
    NativePrivateSpendQ58Compff01OpeningContinuation.current_nodes_distinct same
  exact Fin.ext (congrArg (@Fin.val 13173) equal)

theorem packing_card_nonzero : (64 : Goldilocks) ≠ 0 := by
  change (64 : ZMod goldilocksModulus) ≠ 0
  exact (CharP.cast_eq_zero_iff (ZMod goldilocksModulus) goldilocksModulus 64).not.mpr
    (by norm_num [goldilocksModulus])

/-- The sparse algebra is proved before specializing either finite universe.
This keeps proof elaboration independent of the 26210-by-64 concrete cardinality. -/
private def genericCsrValue {R L : Type} :
    List ((R × L) × Goldilocks) → (R → L → Goldilocks) → Goldilocks
  | [], _ => 0
  | term :: rest, values =>
      term.2 * values term.1.1 term.1.2 + genericCsrValue rest values

private def genericCsrWeights {R L : Type} [DecidableEq R] [DecidableEq L] :
    List ((R × L) × Goldilocks) → R → L → Goldilocks
  | [], _, _ => 0
  | term :: rest, row, lane =>
      (if term.1 = (row, lane) then term.2 else 0) + genericCsrWeights rest row lane

private theorem generic_csr_dense_matches {R L : Type}
    [Fintype R] [Fintype L] [DecidableEq R] [DecidableEq L]
    (terms : List ((R × L) × Goldilocks)) (values : R → L → Goldilocks) :
    (∑ row, ∑ lane, genericCsrWeights terms row lane * values row lane) =
      genericCsrValue terms values := by
  induction terms with
  | nil => simp [genericCsrWeights, genericCsrValue]
  | cons term rest ih =>
      rcases term with ⟨⟨selectedRow, selectedLane⟩, coefficient⟩
      simp only [genericCsrWeights, genericCsrValue, add_mul, Finset.sum_add_distrib]
      rw [ih]
      simp [Prod.mk.injEq, ite_and, ite_mul]

/-- Literal sparse CSR accumulation, with duplicate terms preserved. -/
def csrValue : List Term → Values → Goldilocks := genericCsrValue

def csrWeights : List Term → Row → Lane → Goldilocks := genericCsrWeights

/-- Derive dense notation from the source list; do not assume a CSR target in
some independently normalized relation. -/
theorem csr_dense_matches (terms : List Term) (values : Values) :
    (∑ row, ∑ lane, csrWeights terms row lane * values row lane) = csrValue terms values := by
  exact generic_csr_dense_matches terms values

structure Relation where
  batch : Batch → Fin 3 → Row
  csr : Check → List Term
  target : Check → Goldilocks

/-- The packed linear and multiplication checks of the current relation. -/
structure Satisfies (relation : Relation) (values : Values) : Prop where
  linear : ∀ check, csrValue (relation.csr check) values = relation.target check
  multiply : ∀ batch lane, values (relation.batch batch 0) lane =
    values (relation.batch batch 1) lane * values (relation.batch batch 2) lane

/-- These are polynomial construction facts, not privacy hypotheses. Source
poly_restore at K64/open6 supplies them; its Rust refinement remains explicit. -/
structure PackedPolynomials (relation : Relation) where
  values : Values
  polynomial : Witness
  atPacking : ∀ row lane, (polynomial row).eval (packing lane) = values row lane
  degree : ∀ row, (polynomial row).natDegree ≤ 69
  valid : Satisfies relation values

def weights (relation : Relation) (gamma : Gamma) : Row → Lane → Goldilocks :=
  batchedLinearWeights gamma (fun check => csrWeights (relation.csr check))

def publicTarget (relation : Relation) (gamma : Gamma) : Goldilocks :=
  ∑ check, gamma check * relation.target check

theorem csr_checks_supply_target (relation : Relation) (source : PackedPolynomials relation)
    (gamma : Gamma) :
    (∑ row, ∑ lane, weights relation gamma row lane *
      (source.polynomial row).eval (packing lane)) = publicTarget relation gamma := by
  simp_rw [source.atPacking]
  apply valid_linear_constraints_supply_batched_target gamma
    (fun check => csrWeights (relation.csr check)) source.values relation.target
  intro check
  rw [csr_dense_matches]
  exact source.valid.linear check

def linearTranscript (relation : Relation) (gamma : Gamma) (witness : Witness)
    (coins : Fin 132 → Goldilocks) : Goldilocks[X] :=
  genericLinearTranscript packing (weights relation gamma) witness coins

def linearResponse (relation : Relation) (gamma : Gamma) (witness : Witness)
    (coins : Fin 132 → Goldilocks) : Fin 132 → Goldilocks :=
  genericLinearResponse packing (weights relation gamma) witness coins

def publicLinearMask (relation : Relation) (gamma : Gamma) (response : Fin 132 → Goldilocks)
    (opened : Row → Goldilocks) (point : Goldilocks) : Goldilocks :=
  genericPublicLinearMask packing (weights relation gamma) (publicTarget relation gamma)
    response opened point

/-- The current wrapper has plain polynomial addition and invokes exactly the
already checked current row helper. We do not assume the desired mask equality. -/
theorem public_linear_mask_openings_match (relation : Relation)
    (source : PackedPolynomials relation) (gamma : Gamma) (coins : Fin 132 → Goldilocks)
    (point : Goldilocks) :
    publicLinearMask relation gamma (linearResponse relation gamma source.polynomial coins)
      (fun row => (source.polynomial row).eval point) point =
      (sourceLinearMask packing coins).eval point := by
  unfold publicLinearMask linearResponse
  exact generic_public_linear_mask_openings_match
    packing packing_injective packing_card_nonzero
    (weights relation gamma) source.polynomial source.degree coins
    (publicTarget relation gamma) (csr_checks_supply_target relation source gamma) point

/-- Scalar response coefficient algebra is checked before concrete row specialization.
The packing and coins are the original source parameters, without a new premise. -/
private theorem generic_linear_response_coefficient {F : Type*} [Field F]
    {R : Type*} [Fintype R]
    (packing : Fin 64 → F) (rowWeights : R → Fin 64 → F)
    (witnessPolynomials : R → F[X]) (coins : Fin 132 → F) (index : Fin 132) :
    genericLinearResponse packing rowWeights witnessPolynomials coins index =
      (sourceLinearUnmasked rowWeights (sourcePackingLagrange packing)
        witnessPolynomials).coeff (index.val + 1) + coins index := by
  unfold genericLinearResponse genericLinearTranscript
  rw [Polynomial.coeff_add,
    V8Smz9EagerSimulator.source_linear_mask_nonconstant_coefficient packing coins index]

/-- Public coefficient interface for the unchanged current linear response. -/
theorem linear_response_coefficient (relation : Relation) (gamma : Gamma)
    (witness : Witness) (coins : Fin 132 → Goldilocks) (index : Fin 132) :
    linearResponse relation gamma witness coins index =
      (sourceLinearUnmasked (weights relation gamma) (sourcePackingLagrange packing)
        witness).coeff (index.val + 1) + coins index := by
  exact generic_linear_response_coefficient packing (weights relation gamma)
    witness coins index

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening
