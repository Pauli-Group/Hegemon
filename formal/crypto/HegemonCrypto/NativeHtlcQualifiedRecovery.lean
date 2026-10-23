import HegemonCrypto.NativeHtlcGlobalCount
import HegemonCrypto.NativeHtlcLedger
import HegemonCrypto.CmsClassicalDatabase
import Mathlib.Data.Nat.Choose.Basic

/-!
# Native HTLC recovery with the counting premise discharged

The finite matrix and sample densities below are proved for fixed source
words and arbitrary later response selectors. The accepted-wire endpoint keeps
the exact whole-view and accepted-query bindings explicit. Its ledger component
is a rational inequality, not an unproved quantum execution transport.
Connecting the matrix density to an actual draw additionally requires proving
that these source words were fixed before that draw; this file does not infer
that chronology from a view fixed only before the final query.
-/
namespace HegemonCrypto.SmallWood.NativeHtlcQualifiedRecovery

open NativeHtlcRecovery NativeHtlcUniversalMatrix NativeHtlcLedger
open V8Smz9McaRecovery V8Smz9McaDecoder
open HegemonCrypto.CmsClassicalDatabase
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 200000
set_option maxHeartbeats 4000000
set_option exponentiation.threshold 1024

abbrev Matrix := Coefficients Goldilocks

theorem output_density_of_card_bound {A B : Type*} [Fintype A] [Fintype B]
    [Nonempty A] [Nonempty B] (event : Finset A) (budget : Nat)
    (bound : event.card * Fintype.card B ≤
      Fintype.card A * budget) :
    (event.card : Rat) / Fintype.card A ≤ (budget : Rat) / Fintype.card B := by
  classical
  have aPositive : (0 : Rat) < Fintype.card A := by exact_mod_cast Fintype.card_pos
  have bPositive : (0 : Rat) < Fintype.card B := by exact_mod_cast Fintype.card_pos
  apply (div_le_div_iff₀ aPositive bPositive).2
  exact_mod_cast (by simpa only [Nat.mul_comm] using bound :
    event.card * Fintype.card B ≤ budget * Fintype.card A)

/-- The response-universal matrix density, with no line-count premise. -/
theorem matrix_bad_output_density
    (point : Position → Goldilocks) (injective : Function.Injective point)
    (data : Nat → Position → Goldilocks) (masks : MaskRow → Position → Goldilocks) :
    ((badMatrices point 9933 327680 data masks 140).card : Rat) /
      Fintype.card Matrix ≤
      matrixLoss := by
  classical
  have bound := NativeHtlcGlobalCount.matrix_card_bound point injective data masks
  have gammaCard : Fintype.card (MaskRow → Goldilocks) = goldilocksModulus^5 := by
    rw [Fintype.card_fun, Fintype.card_fin, goldilocks_card]
  have aPositive : (0 : Rat) < Fintype.card Matrix := by
    exact_mod_cast Fintype.card_pos (α := Matrix)
  have bPositive : (0 : Rat) < Fintype.card (MaskRow → Goldilocks) := by
    exact_mod_cast Fintype.card_pos (α := MaskRow → Goldilocks)
  have density : ((badMatrices point 9933 327680 data masks 140).card : Rat) /
      Fintype.card Matrix ≤ (140 * 12548540024940 : Rat) /
        Fintype.card (MaskRow → Goldilocks) := by
    apply (div_le_div_iff₀ aPositive bPositive).2
    have castBound := (Nat.cast_le (α := Rat)).2 bound
    simpa only [Nat.cast_mul, Nat.cast_ofNat, mul_comm] using castBound
  rw [gammaCard] at density
  simpa only [matrixLoss, modulus, Nat.cast_pow, goldilocksModulus,
    Nat.cast_ofNat] using density

/-- Exact falling-factorial conversion avoids computing a huge binomial
recurrence. All arithmetic is checked by the kernel. -/
theorem falling_nat_eq_descFactorial (n q : Nat) (within : q ≤ n) :
    falling (n : Rat) q = (n.descFactorial q : Rat) := by
  induction q with
  | zero => simp [falling]
  | succ q ih =>
    have smaller : q ≤ n := Nat.le_trans (Nat.le_succ q) within
    rw [falling, Nat.descFactorial_succ, Nat.cast_mul, Nat.cast_sub smaller,
      ih smaller]
    ring

theorem choose_ratio_eq_falling (n m q : Nat) (qn : q ≤ n) (qm : q ≤ m) :
    (n.choose q : Rat) / m.choose q = falling (n : Rat) q / falling (m : Rat) q := by
  rw [falling_nat_eq_descFactorial n q qn, falling_nat_eq_descFactorial m q qm,
    Nat.descFactorial_eq_factorial_mul_choose,
    Nat.descFactorial_eq_factorial_mul_choose, Nat.cast_mul, Nat.cast_mul]
  symm
  exact mul_div_mul_left _ _ (by exact_mod_cast Nat.factorial_ne_zero q)

/-- Fresh uniform q58 sampling outside the universal matrix event. The
response is allowed to depend arbitrarily on the matrix. -/
theorem nonexceptional_sample_output_density
    (point : Position → Goldilocks) (injective : Function.Injective point)
    (view : SourceResponseView Goldilocks)
    (notBad : ¬ BadMatrix point 9933 327680 view.data view.masks view.coefficients) :
    ((decoderFailureEvent point 9933 58 view.data view.masks
      view.response view.coefficients).card : Rat) /
        Fintype.card (QuerySample Position 58) ≤ sampleLoss := by
  classical
  have cardBound := nonexceptional_q58_failure_card point injective view notBad
  rw [query_sample_card, Fintype.card_fin]
  calc
    _ ≤ (Nat.choose 327679 58 : Rat) / Nat.choose 8388608 58 :=
      div_le_div_of_nonneg_right (by exact_mod_cast cardBound)
        (Nat.cast_nonneg (Nat.choose 8388608 58))
    _ = sampleLoss := by
      rw [choose_ratio_eq_falling 327679 8388608 58 (by norm_num) (by norm_num)]
      rfl

/-- One uniform density bound for every public prefix. This quantification
does not itself transport an adaptive quantum execution. -/
theorem matrix_density_uniform_over_prefixes
    {Prefix : Type*}
    (point : Position → Goldilocks) (injective : Function.Injective point)
    (data : Prefix → Nat → Position → Goldilocks)
    (masks : Prefix → MaskRow → Position → Goldilocks) :
    ∀ history, ((badMatrices point 9933 327680 (data history) (masks history) 140).card : Rat) /
      Fintype.card Matrix ≤
        matrixLoss := by
  intro history
  exact matrix_bad_output_density point injective (data history) (masks history)

/-- An explicit finite recovery certificate. It contains no unproved
line-count premise and no asserted oracle-to-execution reduction. -/
structure QualifiedView (point : Position → Goldilocks)
    (view : SourceResponseView Goldilocks) : Prop where
  matrixDensity : ((badMatrices point 9933 327680 view.data view.masks 140).card : Rat) /
    Fintype.card Matrix ≤ matrixLoss
  sampleDensity : ¬ BadMatrix point 9933 327680 view.data view.masks view.coefficients →
    ((decoderFailureEvent point 9933 58 view.data view.masks
      view.response view.coefficients).card : Rat) /
        Fintype.card (QuerySample Position 58) ≤ sampleLoss
  localLedger : localLoss < 1 / (2 : Rat)^269
  freshLedger : ∀ queries, queries ≤ 3 * 2^64 →
    freshLoss queries < 1 / (2 : Rat)^134

theorem qualified_view
    (point : Position → Goldilocks) (injective : Function.Injective point)
    (view : SourceResponseView Goldilocks) : QualifiedView point view :=
  ⟨matrix_bad_output_density point injective view.data view.masks,
    nonexceptional_sample_output_density point injective view,
    exact_local_below_269_bits, fresh_below_134_bits⟩

/-- The composed accepted-wire endpoint. The source/response view is fixed
before the final query, and accepted continuations must be bound to that exact
view. Those concrete execution assumptions remain visible; all finite counting
and rational ledger conclusions are constructed here. -/
theorem accepted_execution_qualified_endpoint
    {Wire : Type*} (accepted : Wire → Prop)
    (observed : Wire → SourceResponseView Goldilocks)
    (view : SourceResponseView Goldilocks)
    (query : Wire → QuerySample Position 58)
    (point : Position → Goldilocks) (injective : Function.Injective point)
    (sourceResponseWholeViewBinding :
      ∀ wire, accepted wire → observed wire = view)
    (acceptedQueryBinding : ∀ wire, accepted wire →
      (query wire).val ⊆ support point (observed wire))
    (wire : Wire) (accepts : accepted wire) :
    QualifiedView point view ∧
      (WholeResponseRecovered point view ∨
        BadMatrix point 9933 327680 view.data view.masks view.coefficients ∨
        ((support point view).card < 327680 ∧
          (query wire).val ⊆ support point view)) := by
  exact ⟨qualified_view point injective view,
    accepted_execution_decoder_endpoint accepted observed view query point injective
      sourceResponseWholeViewBinding acceptedQueryBinding wire accepts⟩

end
end HegemonCrypto.SmallWood.NativeHtlcQualifiedRecovery
