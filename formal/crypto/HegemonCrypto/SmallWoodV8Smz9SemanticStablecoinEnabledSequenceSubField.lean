import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoinEnabledCore
import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoinEnabledArithmetic

/-! Raw exact-CSR extraction for the enabled stablecoin sequence equation. -/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled

open Hegemon.Transaction.Poseidon2V8RelationProgram
    (CsrExecutableAttempt evalCsrTerms fieldSub)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

theorem stable_enabled_sequence_sub_field
    {publicWords packed values : List Nat}
    (equations : CsrTraceEquations publicWords values)
    (attempts : ∀ entry, entry ∈ exactCsrAttempts → entry.Accepts values packed)
    (node431 : values[431]? =
      some (fieldSub 0 (fieldSub (publicWords.getD 112 0) 1))) :
    (packedWord packed 41501 : F) = (publicWords.getD 112 0 : F) - 1 := by
  have negative : (values.getD 158 0 : F) = -1 := by
    simpa using (dense_negative_coefficient_values equations).1 0 (by decide)
  have acceptedAttempt := attempts _ (exact_stable_epoch_cap_attempts
    (attempt 20330 67 6 1 [(41501, 158)] 431) (by decide))
  obtain ⟨left, target, evaluated, targetFound, equal⟩ := acceptedAttempt
  change values[431]? = some target at targetFound
  have targetEqual : target = fieldSub 0 (fieldSub (publicWords.getD 112 0) 1) :=
    Option.some.inj (targetFound.symm.trans node431)
  subst target
  subst left
  have evaluatedField := eval_csr_terms_field_sum evaluated
  have fieldEquation : csrFieldSum values packed [(41501, 158)] =
      ((fieldSub 0 (fieldSub (publicWords.getD 112 0) 1) : Nat) : F) := by
    simpa only [attempt] using evaluatedField.symm
  have equation : csrFieldSum values packed [(41501, 158)] =
      -((publicWords.getD 112 0 : F) - 1) :=
    fieldEquation.trans (field_sub_zero_sub_one_cast (publicWords.getD 112 0))
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    negative, neg_one_mul, add_zero] at equation
  simpa only [packedWord] using neg_inj.mp equation

end HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
