import HegemonCrypto.SmallWoodV8Smz9RandomDirectionRecovery

/-!
Successor-only q38/d405 specialization of the computed decoder event.
The source and the whole matrix-dependent response are arbitrary. The decoder
receives the response before, and does not receive, the final 38-subset.
No SMZ9/profile6 accepted-byte or quantum-reduction assertion is made here.
-/

namespace HegemonCrypto.SmallWood.Q38DecoderEvent

open V8Smz9McaRecovery V8Smz9McaDecoder V8Smz9RandomDirectionRecovery
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9RobustQueryMismatch

noncomputable section

abbrev Position38 := Fin V8Smz9DisjointCoset.domainSize
abbrev Coefficients38 := Fin 140 → Fin 5 → Goldilocks
abbrev Response38 := Coefficients38 → BoundedResponse Goldilocks (Fin 5) 405

def lineBudget38 : Nat := universalLineBudget (Row := Fin 5)
  V8Smz9DisjointCoset.evaluationPoint 405 416 38

def epsilon38 : Rat :=
  (Nat.choose 415 38 : Rat) / Nat.choose (2 ^ 23) 38 +
    (goldilocksModulus : Rat) * lineBudget38 /
      (((goldilocksModulus - 1 : Nat) : Rat) * (goldilocksModulus : Rat)^5 *
        Nat.choose (2 ^ 23) 38)

def failure38 (data : Nat → Position38 → Goldilocks)
    (masks : Fin 5 → Position38 → Goldilocks) (response : Response38) :=
  decoderFailureEvent V8Smz9DisjointCoset.evaluationPoint 405 38 data masks response

/-- An actual finite accepted-query/computed-decoder-failure probability,
universally bounded by the exact unrestricted source supremum. -/
theorem decoder_failure38_le
    (data : Nat → Position38 → Goldilocks)
    (masks : Fin 5 → Position38 → Goldilocks) (response : Response38) :
    FiniteEvents.jointProbability (failure38 data masks response) ≤ epsilon38 := by
  have coefficientCard : Fintype.card (Fin 5 → Goldilocks) = goldilocksModulus ^ 5 := by
    rw [Fintype.card_fun, Fintype.card_fin, goldilocks_card]
  have sampleFits : 38 ≤ Fintype.card Position38 := by
    rw [Fintype.card_fin]
    decide
  have bound := factor_free_source_recovery_probability_le
    V8Smz9DisjointCoset.evaluationPoint 405 416 38 (by decide) sampleFits data masks response
  have same : failure38 data masks response =
      unrecoveredQueryEvent V8Smz9DisjointCoset.evaluationPoint 405 38 data masks response := by
    funext coefficients
    exact decoder_failure_event_eq_unrecovered_event
      V8Smz9DisjointCoset.evaluationPoint V8Smz9DisjointCoset.evaluation_point_injective
      405 38 data masks response coefficients
  rw [same]
  rw [coefficientCard, goldilocks_card, Fintype.card_fin, Nat.cast_pow] at bound
  exact bound

/-- Arbitrary prior histories can select both the source and the entire
response strategy; the final query subset remains subsequent and fresh.
This is the finite chronological interface needed by a future round-by-round
quantum knowledge proof, not that quantum proof. -/
theorem every_prior_decoder_failure38_le {Prior : Type*}
    (data : Prior → Nat → Position38 → Goldilocks)
    (masks : Prior → Fin 5 → Position38 → Goldilocks)
    (response : Prior → Response38) :
    ∀ prior, FiniteEvents.jointProbability
      (failure38 (data prior) (masks prior) (response prior)) ≤ epsilon38 := by
  intro prior
  exact decoder_failure38_le (data prior) (masks prior) (response prior)

def sampleDenominator38 : Rat := Nat.choose (2 ^ 23) 38
def w38 (g : Nat) : Rat := (Nat.choose g 38 : Rat) / sampleDenominator38

def publishedPartition38 : Rat :=
  (goldilocksModulus : Rat)^5 * w38 58287 +
    19191588994328775603293919496651850544 * w38 524287 +
    (((2 ^ 23 : Nat)^2 + 3 * 2 ^ 23 : Nat) : Rat) / 1643

/-- This precise external mathematical proof obligation is deliberately a
definition with no constructor/theorem asserting it. Proving it requires the
arbitrary-support BCHKS count and cubic-incidence bound for degree 405. -/
def UnrestrictedMca38 : Prop :=
  (lineBudget38 : Rat) / sampleDenominator38 ≤ publishedPartition38

def partitionEpsilon38 : Rat := w38 415 +
  (goldilocksModulus : Rat) * publishedPartition38 /
    (((goldilocksModulus - 1 : Nat) : Rat) * (goldilocksModulus : Rat)^5)

/-- Conditional source-event bridge. Its one mathematical premise refers to
the actual universalLineBudget, not a caller-selected recovery event. -/
theorem decoder_failure38_le_partition
    (mca : UnrestrictedMca38)
    (data : Nat → Position38 → Goldilocks)
    (masks : Fin 5 → Position38 → Goldilocks) (response : Response38) :
    FiniteEvents.jointProbability (failure38 data masks response) ≤ partitionEpsilon38 := by
  apply (decoder_failure38_le data masks response).trans
  have positive : (0 : Rat) <
      (((goldilocksModulus - 1 : Nat) : Rat) * (goldilocksModulus : Rat)^5) := by
    norm_num [goldilocksModulus]
  have scaled := div_le_div_of_nonneg_right
    (mul_le_mul_of_nonneg_left mca (Nat.cast_nonneg goldilocksModulus)) (le_of_lt positive)
  have identity :
      (goldilocksModulus : Rat) * ((lineBudget38 : Rat) / sampleDenominator38) /
        (((goldilocksModulus - 1 : Nat) : Rat) * (goldilocksModulus : Rat)^5) =
      (goldilocksModulus : Rat) * lineBudget38 /
        ((((goldilocksModulus - 1 : Nat) : Rat) * (goldilocksModulus : Rat)^5) *
          sampleDenominator38) := by ring
  rw [identity] at scaled
  exact add_le_add (le_refl (w38 415)) scaled

end
end HegemonCrypto.SmallWood.Q38DecoderEvent
