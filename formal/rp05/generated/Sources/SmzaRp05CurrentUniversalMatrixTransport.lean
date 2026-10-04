import Mca38UniversalBadLineCount
import SmzaRp05CurrentCoset406

/-!
# Current-profile universal MCA matrix transport

The current 406-point evaluation map is not the historical 388-point map.
It is, however, a nonzero scalar rescaling of it.  Degree-bounded polynomial
responses and code predicates are invariant under that rescaling, so the
response-universal historical line count transports without an independence
assumption on the later response.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentUniversalMatrixTransport

open Polynomial
open HegemonCrypto.SmallWood.V8Smz9McaRecovery
open HegemonCrypto.SmallWood.Mca38UniversalMatrixEvent
open HegemonCrypto.SmallWood.Mca38UniversalBadLineCount
open HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

variable {F Position Row : Type*} [Field F]

def rescalePolynomial (c : F) (p : F[X]) : F[X] :=
  p.comp (C c * X)

theorem rescalePolynomial_degree_le (c : F) (hc : c ≠ 0)
    (p : F[X]) (degree : Nat) (bound : p.natDegree ≤ degree) :
    (rescalePolynomial c p).natDegree ≤ degree := by
  unfold rescalePolynomial
  calc
    (p.comp (C c * X)).natDegree ≤ p.natDegree * (C c * X).natDegree :=
      Polynomial.natDegree_comp_le
    _ = p.natDegree := by rw [Polynomial.natDegree_C_mul_X c hc, Nat.mul_one]
    _ ≤ degree := bound

theorem eval_rescalePolynomial (c : F) (p : F[X]) (x : F) :
    (rescalePolynomial c p).eval x = p.eval (c * x) := by
  simp [rescalePolynomial, Polynomial.eval_comp]

theorem codeOn_scale_iff (c : F) (hc : c ≠ 0)
    (point : Position → F) (degree : Nat) (word : Position → F)
    (support : Finset Position) :
    CodeOn (fun i => c * point i) degree word support ↔
      CodeOn point degree word support := by
  constructor
  · rintro ⟨p, bound, agrees⟩
    refine ⟨rescalePolynomial c p, rescalePolynomial_degree_le c hc p degree bound, ?_⟩
    intro index member
    rw [eval_rescalePolynomial]
    exact agrees index member
  · rintro ⟨p, bound, agrees⟩
    have hcInv : c⁻¹ ≠ 0 := inv_ne_zero hc
    refine ⟨rescalePolynomial c⁻¹ p,
      rescalePolynomial_degree_le c⁻¹ hcInv p degree bound, ?_⟩
    intro index member
    rw [eval_rescalePolynomial]
    have pointEq : c⁻¹ * (c * point index) = point index := by
      rw [← mul_assoc, inv_mul_cancel₀ hc, one_mul]
    simpa [pointEq] using agrees index member

theorem lineGood_scale_iff (c : F) (hc : c ≠ 0)
    [Fintype Position]
    (point : Position → F) (degree threshold : Nat)
    (prior : Row → Position → F) (direction : Position → F)
    (coefficient : Row → F) :
    LineGood (fun i => c * point i) degree threshold prior direction coefficient ↔
      LineGood point degree threshold prior direction coefficient := by
  constructor
  · intro currentGood response responseBound large
    let currentResponse : Row → F[X] := fun row =>
      rescalePolynomial c⁻¹ (response row)
    have hcInv : c⁻¹ ≠ 0 := inv_ne_zero hc
    have currentBound : ∀ row, (currentResponse row).natDegree ≤ degree := by
      intro row
      exact rescalePolynomial_degree_le c⁻¹ hcInv (response row) degree
        (responseBound row)
    have agreementEq :
        agreement (fun i => c * point i) (lineWord prior direction coefficient)
            currentResponse =
          agreement point (lineWord prior direction coefficient) response := by
      ext index
      simp only [agreement, Finset.mem_filter, Finset.mem_univ, true_and]
      constructor
      · intro h row
        have evalEq : (currentResponse row).eval (c * point index) =
            (response row).eval (point index) := by
          rw [eval_rescalePolynomial]
          congr 1
          rw [← mul_assoc, inv_mul_cancel₀ hc, one_mul]
        simpa only [evalEq] using h row
      · intro h row
        have evalEq : (currentResponse row).eval (c * point index) =
            (response row).eval (point index) := by
          rw [eval_rescalePolynomial]
          congr 1
          rw [← mul_assoc, inv_mul_cancel₀ hc, one_mul]
        simpa only [← evalEq] using h row
    have currentLarge : threshold ≤
        (agreement (fun i => c * point i)
          (lineWord prior direction coefficient) currentResponse).card := by
      rw [agreementEq]
      exact large
    have codedCurrent := currentGood currentResponse currentBound currentLarge
    have codedHistorical := (codeOn_scale_iff c hc point degree direction
      (agreement (fun i => c * point i)
        (lineWord prior direction coefficient) currentResponse)).mp codedCurrent
    rw [agreementEq] at codedHistorical
    exact codedHistorical
  · intro historicalGood response responseBound large
    let historicalResponse : Row → F[X] := fun row =>
      rescalePolynomial c (response row)
    have historicalBound : ∀ row, (historicalResponse row).natDegree ≤ degree := by
      intro row
      exact rescalePolynomial_degree_le c hc (response row) degree (responseBound row)
    have agreementEq :
        agreement point (lineWord prior direction coefficient) historicalResponse =
          agreement (fun i => c * point i)
            (lineWord prior direction coefficient) response := by
      ext index
      simp only [agreement, Finset.mem_filter, Finset.mem_univ, true_and]
      constructor
      · intro h row
        have evalEq : (historicalResponse row).eval (point index) =
            (response row).eval (c * point index) := by
          rw [eval_rescalePolynomial]
        simpa only [evalEq] using h row
      · intro h row
        have evalEq : (historicalResponse row).eval (point index) =
            (response row).eval (c * point index) := by
          rw [eval_rescalePolynomial]
        simpa only [← evalEq] using h row
    have historicalLarge : threshold ≤
        (agreement point (lineWord prior direction coefficient) historicalResponse).card := by
      rw [agreementEq]
      exact large
    have codedHistorical := historicalGood historicalResponse historicalBound historicalLarge
    have codedCurrent := (codeOn_scale_iff c hc point degree direction
      (agreement point (lineWord prior direction coefficient) historicalResponse)).mpr
      codedHistorical
    rw [agreementEq] at codedCurrent
    exact codedCurrent

theorem badLineLabels_scale (c : F) (hc : c ≠ 0)
    [Fintype Position] [Fintype F] [Fintype Row]
    (point : Position → F) (degree threshold : Nat)
    (prior : Row → Position → F) (direction : Position → F) :
    badLineLabels (fun i => c * point i) degree threshold prior direction =
      badLineLabels point degree threshold prior direction := by
  classical
  ext coefficient
  simp only [badLineLabels, Finset.mem_filter, Finset.mem_univ, true_and]
  exact not_congr (lineGood_scale_iff c hc point degree threshold prior direction coefficient)

local notation "Position38" => Fin domainSize

def currentToHistoricalScale : Goldilocks := (406 : Goldilocks) / 388

theorem currentToHistoricalScale_ne_zero : currentToHistoricalScale ≠ 0 := by
  change (406 : ZMod goldilocksModulus) / 388 ≠ 0
  apply div_ne_zero
  · exact (CharP.cast_eq_zero_iff (ZMod goldilocksModulus)
      goldilocksModulus 406).not.mpr (by norm_num [goldilocksModulus])
  · exact (CharP.cast_eq_zero_iff (ZMod goldilocksModulus)
      goldilocksModulus 388).not.mpr (by norm_num [goldilocksModulus])

theorem current_point_is_scaled_historical (index : Position38) :
    evaluationPoint index = currentToHistoricalScale *
      V8Smz9DisjointCoset.evaluationPoint ⟨index.val, index.isLt⟩ := by
  have scaledShift : currentToHistoricalScale * (388 : Goldilocks) = 406 := by
    have h388 : (388 : Goldilocks) ≠ 0 := by
      change (388 : ZMod goldilocksModulus) ≠ 0
      exact (CharP.cast_eq_zero_iff (ZMod goldilocksModulus)
        goldilocksModulus 388).not.mpr (by norm_num [goldilocksModulus])
    unfold currentToHistoricalScale
    exact div_mul_cancel₀ (406 : Goldilocks) h388
  change (406 : Goldilocks) *
      V8Smz9DisjointCoset.radix2Root ^ index.val =
    currentToHistoricalScale *
      ((388 : Goldilocks) * V8Smz9DisjointCoset.radix2Root ^ index.val)
  calc
    (406 : Goldilocks) * V8Smz9DisjointCoset.radix2Root ^ index.val =
        (currentToHistoricalScale * 388) *
          V8Smz9DisjointCoset.radix2Root ^ index.val := by rw [scaledShift]
    _ = currentToHistoricalScale *
        ((388 : Goldilocks) * V8Smz9DisjointCoset.radix2Root ^ index.val) := by
      rw [mul_assoc]

theorem current_universal_badLineLabels_65536
    (prior : Fin 5 → Position38 → Goldilocks)
    (direction : Position38 → Goldilocks) :
    (badLineLabels evaluationPoint 405 65536 prior direction).card ≤
      12310499043179 := by
  have pointEq : evaluationPoint = fun index : Position38 =>
      currentToHistoricalScale *
        V8Smz9DisjointCoset.evaluationPoint ⟨index.val, index.isLt⟩ := by
    funext index
    exact current_point_is_scaled_historical index
  rw [pointEq]
  rw [badLineLabels_scale currentToHistoricalScale currentToHistoricalScale_ne_zero
    (fun index : Position38 =>
      V8Smz9DisjointCoset.evaluationPoint ⟨index.val, index.isLt⟩)
    405 65536 prior direction]
  have oldPointEq :
      (fun index : Position38 =>
        V8Smz9DisjointCoset.evaluationPoint ⟨index.val, index.isLt⟩) =
        V8Smz9DisjointCoset.evaluationPoint := by
    funext index
    rfl
  rw [oldPointEq]
  exact universal_badLineLabels_65536 prior direction

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentUniversalMatrixTransport
