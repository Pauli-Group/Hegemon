import Mathlib.Algebra.Polynomial.Taylor
import Mathlib.Algebra.Polynomial.Div
import Mathlib.Tactic.Ring

/-!
Finite, explicit Hensel/Newton lifting. No Henselian axiom, completion, count
hypothesis, or factor theorem is assumed. This is an intermediate ingredient
for the separable factor part of BCHKS, not the bounded-label theorem.
Prepared source, not yet compiler checked.
-/

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false

variable {R : Type*} [CommRing R]

/-- a approximates a root, b approximates the inverse of its derivative. -/
def NewtonValid (f : Polynomial R) (π : R) (m : ℕ) (s : R × R) : Prop :=
  π ^ m ∣ f.eval s.1 ∧ π ^ m ∣ f.derivative.eval s.1 * s.2 - 1

/-- A completely explicit simultaneous root/inverse Newton update. -/
noncomputable def newtonStep (f : Polynomial R) (s : R × R) : R × R :=
  let a' := s.1 - s.2 * f.eval s.1
  (a', s.2 * (2 - f.derivative.eval a' * s.2))

theorem newtonStep_valid (f : Polynomial R) (π : R) (m : ℕ)
    (s : R × R) (hs : NewtonValid f π m s) :
    NewtonValid f π (m + m) (newtonStep f s) := by
  rcases hs with ⟨⟨u, hu⟩, ⟨v, hv⟩⟩
  let a' := s.1 - s.2 * f.eval s.1
  obtain ⟨c, hc⟩ := f.exists_mul_sq_add_linear_part_eq_eval_add
    s.1 (-(s.2 * f.eval s.1))
  have ha' : f.eval a' =
      π ^ (m + m) * (c * s.2 ^ 2 * u ^ 2 - u * v) := by
    calc
      f.eval a' = c * (-(s.2 * f.eval s.1)) ^ 2 +
          f.derivative.eval s.1 * (-(s.2 * f.eval s.1)) + f.eval s.1 := by
        simpa only [a', sub_eq_add_neg] using hc.symm
      _ = c * s.2 ^ 2 * (f.eval s.1) ^ 2 -
          f.eval s.1 * (f.derivative.eval s.1 * s.2 - 1) := by ring
      _ = _ := by rw [hu, hv, pow_add]; ring
  obtain ⟨w, hw⟩ := Polynomial.sub_dvd_eval_sub a' s.1 f.derivative
  have he : f.derivative.eval a' * s.2 - 1 =
      π ^ m * (v - s.2 ^ 2 * u * w) := by
    calc
      f.derivative.eval a' * s.2 - 1 =
          (f.derivative.eval a' - f.derivative.eval s.1) * s.2 +
          (f.derivative.eval s.1 * s.2 - 1) := by ring
      _ = _ := by rw [hw, hv]; dsimp [a']; rw [hu]; ring
  have hb' : f.derivative.eval a' *
      (s.2 * (2 - f.derivative.eval a' * s.2)) - 1 =
      π ^ (m + m) * (-(v - s.2 ^ 2 * u * w) ^ 2) := by
    calc
      f.derivative.eval a' *
          (s.2 * (2 - f.derivative.eval a' * s.2)) - 1 =
          -(f.derivative.eval a' * s.2 - 1) ^ 2 := by ring
      _ = _ := by rw [he, pow_add]; ring
  exact ⟨⟨c * s.2 ^ 2 * u ^ 2 - u * v, ha'⟩,
    ⟨-(v - s.2 ^ 2 * u * w) ^ 2, hb'⟩⟩

theorem newtonStep_preserves_root_mod (f : Polynomial R) (π : R) (m : ℕ)
    (s : R × R) (hs : NewtonValid f π m s) :
    π ^ m ∣ (newtonStep f s).1 - s.1 := by
  obtain ⟨u, hu⟩ := hs.1
  refine ⟨-s.2 * u, ?_⟩
  dsimp [newtonStep]
  rw [hu]
  ring

noncomputable def newtonIterate (f : Polynomial R) (s : R × R) : ℕ → R × R
  | 0 => s
  | t + 1 => newtonStep f (newtonIterate f s t)

/-- Every iteration doubles the certified modulus. This constructs finite
approximants over E[X], taking π=X; no infinite-series existence assumption
is needed. The missing application is a bound on Z degrees/denominators. -/
theorem newtonIterate_valid (f : Polynomial R) (π : R) (s : R × R)
    (hs : NewtonValid f π 1 s) (t : ℕ) :
    NewtonValid f π (2 ^ t) (newtonIterate f s t) := by
  induction t with
  | zero => simpa only [pow_zero, newtonIterate] using hs
  | succ t ih =>
      have h := newtonStep_valid f π (2 ^ t) (newtonIterate f s t) ih
      simpa only [newtonIterate, pow_succ, mul_two] using h

end HegemonCrypto.SmallWood.Mca38Published


