import HegemonCrypto.SmallWoodLinearPiopExact

/-! Construct the current SIX-opening linear recomputation over a field.
The seventh interpolation node is zero with prescribed value zero. Decoded
high coefficients are shifted by X^7, exactly the seven-value poly_restore
shape. No desired corrected equation or claimed target is assumed.
This is a field model, not Rust word/poly refinement or adapter semantics;
canonical decoding, native acceptance and all production gates remain open. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchPiopLinearRecompute
open Polynomial
open SmallWood.LinearPiopExact
open scoped BigOperators
noncomputable section
variable {F I : Type*} [Field F]

def prescribed (values : Fin 6 → F) : Option (Fin 6) → F
  | none => 0
  | some index => values index

def shiftedHigh (high : F[X]) : F[X] := high * X^7

def restored (openings values : Fin 6 → F) (high : F[X]) : F[X] :=
  shiftedHigh high + Lagrange.interpolate Finset.univ (augmentedPoint openings)
    (fun index => prescribed values index - (shiftedHigh high).eval (augmentedPoint openings index))

def packingSum (packing : Finset I) (point : I → F) (polynomial : F[X]) : F :=
  ∑ index ∈ packing, polynomial.eval (point index)

def corrected (packing : Finset I) (point : I → F) (openings values : Fin 6 → F)
    (high : F[X]) (publicTarget : F) : F[X] :=
  restored openings values high +
    C ((publicTarget - packingSum packing point (restored openings values high)) /
      correctionFactor packing point openings) * normalizedRootPolynomial openings

theorem restored_at_seven_nodes (openings values : Fin 6 → F) (high : F[X])
    (distinct : Function.Injective openings) (nonzero : ∀ i, openings i ≠ 0)
    (index : Option (Fin 6)) :
    (restored openings values high).eval (augmentedPoint openings index) = prescribed values index := by
  have interp := Lagrange.eval_interpolate_at_node
    (r := fun i => prescribed values i - (shiftedHigh high).eval (augmentedPoint openings i))
    (augmentedPoint_injective distinct nonzero).injOn (Finset.mem_univ index)
  rw [restored, eval_add, interp]
  ring

theorem corrected_at_six_openings (packing : Finset I) (point : I → F)
    (openings values : Fin 6 → F) (high : F[X]) (publicTarget : F)
    (distinct : Function.Injective openings) (nonzero : ∀ i, openings i ≠ 0) (index : Fin 6) :
    (corrected packing point openings values high publicTarget).eval (openings index) = values index := by
  have base := restored_at_seven_nodes openings values high distinct nonzero (some index)
  simpa only [corrected, eval_add, eval_mul, normalizedRootPolynomial_eval_opening,
    mul_zero, add_zero, augmentedPoint, prescribed] using base

theorem corrected_packing_sum (packing : Finset I) (point : I → F)
    (openings values : Fin 6 → F) (high : F[X]) (publicTarget : F)
    (guard : correctionFactor packing point openings ≠ 0) :
    packingSum packing point (corrected packing point openings values high publicTarget) = publicTarget := by
  simp only [packingSum, corrected, eval_add, eval_mul, eval_C, Finset.sum_add_distrib]
  rw [← Finset.mul_sum]
  change packingSum packing point (restored openings values high) +
    ((publicTarget - packingSum packing point (restored openings values high)) /
      correctionFactor packing point openings) * correctionFactor packing point openings = publicTarget
  rw [div_mul_cancel₀ _ guard]
  ring

/-- Actual batched linear rows, masks, public targets and gamma are inputs.
The resulting polynomial is constructed, not supplied with a desired equation. -/
def recompute {count : Nat} (packing : Finset I) (point : I → F) (openings : Fin 6 → F)
    (linear : Fin 6 → Fin count → F) (mask : Fin 6 → F) (gamma targets : Fin count → F)
    (high : F[X]) : F[X] :=
  corrected packing point openings (fun j => (∑ c, linear j c * gamma c) + mask j) high
    (∑ c, targets c * gamma c)

theorem recompute_equations {count : Nat} (packing : Finset I) (point : I → F) (openings : Fin 6 → F)
    (linear : Fin 6 → Fin count → F) (mask : Fin 6 → F) (gamma targets : Fin count → F)
    (high : F[X]) (distinct : Function.Injective openings) (nonzero : ∀ i, openings i ≠ 0)
    (guard : correctionFactor packing point openings ≠ 0) :
    (∀ j, (recompute packing point openings linear mask gamma targets high).eval (openings j) =
      (∑ c, linear j c * gamma c) + mask j) ∧
    packingSum packing point (recompute packing point openings linear mask gamma targets high) =
      ∑ c, targets c * gamma c := by
  exact ⟨fun j => corrected_at_six_openings packing point openings _ high _ distinct nonzero j,
    corrected_packing_sum packing point openings _ high _ guard⟩

end
end HegemonCrypto.NativeLaunchPiopLinearRecompute
