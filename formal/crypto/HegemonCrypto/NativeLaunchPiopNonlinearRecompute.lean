import Mathlib.LinearAlgebra.Lagrange

/-! Current SIX-opening nonlinear PIOP field construction. Actual batched
constraint evaluations are divided by the packing vanishing polynomial, then
masked and restored using high*X^6 plus six-node Lagrange interpolation.
No desired reconstructed equation or relation-satisfaction premise is used.
Canonical decoding, Rust word/poly refinement, constraint-adapter semantics,
native acceptance and all production gates remain separate. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchPiopNonlinearRecompute
open Polynomial
open scoped BigOperators
noncomputable section
variable {F I : Type*} [Field F]

def packingVanishing (packing : Finset I) (point : I → F) : F[X] :=
  ∏ index ∈ packing, (X - C (point index))

def shiftedHigh (high : F[X]) : F[X] := high * X^6

def restored (openings values : Fin 6 → F) (high : F[X]) : F[X] :=
  shiftedHigh high + Lagrange.interpolate Finset.univ openings
    (fun index => values index - (shiftedHigh high).eval (openings index))

def batched {count : Nat} (constraints : Fin 6 → Fin count → F) (gamma : Fin count → F)
    (index : Fin 6) : F := ∑ row, constraints index row * gamma row

def quotientValues {count : Nat} (packing : Finset I) (point : I → F) (openings : Fin 6 → F)
    (constraints : Fin 6 → Fin count → F) (gamma : Fin count → F) (mask : Fin 6 → F) : Fin 6 → F :=
  fun index => batched constraints gamma index / (packingVanishing packing point).eval (openings index) + mask index

def recompute {count : Nat} (packing : Finset I) (point : I → F) (openings : Fin 6 → F)
    (constraints : Fin 6 → Fin count → F) (gamma : Fin count → F) (mask : Fin 6 → F)
    (high : F[X]) : F[X] :=
  restored openings (quotientValues packing point openings constraints gamma mask) high

theorem vanishing_nonzero (packing : Finset I) (point : I → F) (x : F)
    (offPacking : ∀ index ∈ packing, x ≠ point index) :
    (packingVanishing packing point).eval x ≠ 0 := by
  simp only [packingVanishing, eval_prod, eval_sub, eval_X, eval_C]
  apply Finset.prod_ne_zero_iff.mpr
  intro index member
  exact sub_ne_zero.mpr (offPacking index member)

theorem restored_at_six_nodes (openings values : Fin 6 → F) (high : F[X])
    (distinct : Function.Injective openings) (index : Fin 6) :
    (restored openings values high).eval (openings index) = values index := by
  have interp := Lagrange.eval_interpolate_at_node
    (r := fun i => values i - (shiftedHigh high).eval (openings i))
    distinct.injOn (Finset.mem_univ index)
  rw [restored, eval_add, interp]
  ring

theorem recompute_openings {count : Nat} (packing : Finset I) (point : I → F) (openings : Fin 6 → F)
    (constraints : Fin 6 → Fin count → F) (gamma : Fin count → F) (mask : Fin 6 → F)
    (high : F[X]) (distinct : Function.Injective openings) (index : Fin 6) :
    (recompute packing point openings constraints gamma mask high).eval (openings index) =
      (∑ row, constraints index row * gamma row) /
        (∏ p ∈ packing, (openings index - point p)) + mask index := by
  have values := restored_at_six_nodes openings
    (quotientValues packing point openings constraints gamma mask) high distinct index
  simpa only [recompute, quotientValues, batched, packingVanishing, eval_prod,
    eval_sub, eval_X, eval_C] using values

theorem recompute_cleared_denominators {count : Nat} (packing : Finset I) (point : I → F)
    (openings : Fin 6 → F) (constraints : Fin 6 → Fin count → F) (gamma : Fin count → F)
    (mask : Fin 6 → F) (high : F[X]) (distinct : Function.Injective openings)
    (offPacking : ∀ j p, p ∈ packing → openings j ≠ point p) (index : Fin 6) :
    ((recompute packing point openings constraints gamma mask high).eval (openings index) - mask index) *
      (packingVanishing packing point).eval (openings index) = ∑ row, constraints index row * gamma row := by
  have values := restored_at_six_nodes openings
    (quotientValues packing point openings constraints gamma mask) high distinct index
  change ((restored openings (quotientValues packing point openings constraints gamma mask) high).eval (openings index) - mask index) *
    (packingVanishing packing point).eval (openings index) = _
  rw [values]
  simp only [quotientValues, add_sub_cancel_right]
  exact div_mul_cancel₀ _ (vanishing_nonzero packing point (openings index) (offPacking index))

end
end HegemonCrypto.NativeLaunchPiopNonlinearRecompute
