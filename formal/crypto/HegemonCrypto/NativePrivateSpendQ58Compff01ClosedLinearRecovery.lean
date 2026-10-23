import HegemonCrypto.SmallWoodV8Smz9PiopOpeningRecovery

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58Compff01ClosedLinearRecovery
open Polynomial
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9PiopOpeningRecovery
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- Closed current-row specialization of the retained linear reconstruction theorem.
The sole validity input is the genuine packing-sum constraint, not a mask/output equality.
Weights and target are abstract public coefficients, so no current CSR/gamma definition is unfolded. -/
theorem closed_linear_coins_recovered_from_opened_rows
    (packing : Fin 64 → Goldilocks) (injective : Function.Injective packing)
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (weights : Fin 26210 → Fin 64 → Goldilocks)
    (witnessPolynomials : Fin 26210 → Goldilocks[X])
    (witnessDegree : ∀ row, (witnessPolynomials row).natDegree ≤ 69)
    (coins : Fin 132 → Goldilocks) (target : Goldilocks)
    (valid : (∑ row, ∑ lane : Fin 64,
      weights row lane * (witnessPolynomials row).eval (packing lane)) = target)
    (point : Goldilocks) :
    let mask := sourceLinearMask packing coins
    let transcript := sourceLinearUnmasked weights (sourcePackingLagrange packing)
      witnessPolynomials + mask
    recoverLinearMaskOpening packing target
      (fun index => transcript.coeff (index.val + 1)) weights (sourcePackingLagrange packing)
      (fun row => (witnessPolynomials row).eval point) point = mask.eval point := by
  exact @source_linear_coins_recovered_from_opened_rows Goldilocks
    (@ZMod.instField goldilocksModulus HegemonCrypto.SmallWood.goldilocksPrimeFact)
    (Fin 26210) (Fin.fintype 26210) packing injective packingCardNonzero
    weights witnessPolynomials witnessDegree coins target valid point

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58Compff01ClosedLinearRecovery
