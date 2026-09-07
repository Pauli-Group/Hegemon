import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoinEnabledCore
import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoinEnabledSequenceNode431
import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoinEnabledSequenceSubField

/-!
Sequence and typed-source consequences for enabled stablecoin arithmetic.
The unrestricted enabled transition is not asserted by these intermediate endpoints.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex)
open Hegemon.Transaction.Poseidon2V8RelationProgram
    (CsrExecutableAttempt FieldExpression evalFieldExpression fieldNormalize
     fieldSub fieldMul packingFactor)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

private theorem stable_enabled_sequence_node430_value {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values)
    (canonical : Hegemon.Transaction.Poseidon2V8RelationProgram.CanonicalPublicWords publicWords)
    (direction : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2) :
    values[430]? = some (fieldSub (publicWords.getD 112 0) 1) := by
  have enabled := stable_enabled_gate_value equations canonical direction
  have afterValue := stable_csr_public_value equations canonical
    (index := 112) (by decide) (by decide)
  simpa [evalFieldExpression, afterValue, enabled] using
    equations 430 (.sub 116 306) (by decide)

private theorem accepted_stable_enabled_sequence_field {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2) :
    (publicWords.getD 112 0 : F) = ((packedWord packed 41501 + 1 : Nat) : F) := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have node430 := stable_enabled_sequence_node430_value equations accepted.1 direction
  have node431 := stable_enabled_sequence_node431_value equations node430
  have subEquation := stable_enabled_sequence_sub_field equations attempts node431
  rw [Nat.cast_add, Nat.cast_one]
  exact (eq_sub_iff_add_eq.mp subEquation).symm

private theorem accepted_stable_enabled_sequence_sum_bound {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    packedWord packed 41501 + 1 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  have beforeBound := (accepted_stable_sequence_epoch_bounds accepted).1
  norm_num at beforeBound
  change _ < 18446744069414584321
  omega

/-- The enabled sequence increments as a Nat; canonical field wrap is excluded. -/
theorem accepted_stable_enabled_sequence {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2) :
    publicWords.getD 112 0 = packedWord packed 41501 + 1 := by
  exact canonical_nat_cast_injective
    (canonical_public_coordinate accepted.1 (index := 112) (by decide)).2
    (accepted_stable_enabled_sequence_sum_bound accepted)
    (accepted_stable_enabled_sequence_field accepted direction)

/-- Bind each typed configuration word to its actual accepted source coordinate. -/
theorem admitted_stable_config_word_source {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {word : Nat} (bound : word < 55) :
    stableWitnessWord (projectTypedWitness statement packed).stablecoin word =
      packedWord packed (41408 + word) := by
  have projection : stableWitnessWord (projectTypedWitness statement packed).stablecoin word =
      packedWord packed (hashInitialIndex (106 + word / 14) (word % 14)) := by
    change (projectStablecoinWords statement packed).getD word 0 = _
    simp only [projectStablecoinWords, List.append_assoc, List.getD_eq_getElem?_getD]
    rw [List.getElem?_append_left (by simpa using bound)]
    simp only [List.getElem?_map, List.getElem?_range bound,
      Option.map_some, Option.getD_some]
  rw [projection]
  simpa only [stableCopyDestination, stableCopySource, if_pos bound, stableSourceIndex] using
    accepted_stable_copy_equality domain.2.2 (word := word) (by omega)

/-- Bind the typed before epoch/minted/debt/sequence tuple to source slots 90–93. -/
theorem admitted_stable_before_word_source {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {counter : Nat} (bound : counter < 4) :
    stableWitnessWord (projectTypedWitness statement packed).stablecoin (55 + counter) =
      packedWord packed (41498 + counter) := by
  have projection : stableWitnessWord (projectTypedWitness statement packed).stablecoin (55 + counter) =
      packedWord packed (hashInitialIndex 113 (7 + counter)) := by
    change (projectStablecoinWords statement packed).getD (55 + counter) 0 = _
    simp only [projectStablecoinWords, List.append_assoc, List.getD_eq_getElem?_getD]
    rw [List.getElem?_append_right (by simp)]
    simp only [List.length_map, List.length_range, Nat.add_sub_cancel_left]
    rw [List.getElem?_append_left (by simpa using bound)]
    simp only [List.getElem?_map, List.getElem?_range bound,
      Option.map_some, Option.getD_some]
  rw [projection]
  have sourceAddress : 41408 + (90 + counter) = 41498 + counter := by omega
  simpa [stableCopyDestination, stableCopySource, stableSourceIndex,
    show ¬55 + counter < 55 by omega, show 55 + counter < 59 by omega,
    Nat.add_assoc, sourceAddress] using
    accepted_stable_copy_equality domain.2.2 (word := 55 + counter) (by omega)

#print axioms accepted_stable_boolean
#print axioms accepted_stable_odd_range
#print axioms accepted_stable_sequence_epoch_bounds
#print axioms accepted_stable_epoch_gap_and_caps
#print axioms accepted_stable_epoch_and_cap_inequalities
#print axioms accepted_stable_enabled_sequence
#print axioms accepted_stable_config_flag_boolean
#print axioms admitted_stable_config_word_source
#print axioms admitted_stable_before_word_source

end HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
