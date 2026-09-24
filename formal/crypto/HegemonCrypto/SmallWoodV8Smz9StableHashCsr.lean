import HegemonCrypto.SmallWoodV8Smz9SemanticCanonicalWitness

namespace HegemonCrypto.SmallWood.V8Smz9StableHashCsr

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem accepted_constant_coordinate {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (global family localIndex boundary coordinate target value : Nat)
    (member : attempt global family localIndex boundary [(coordinate, 1)] target ∈ exactCsrAttempts)
    (found : exactCsrExpressions[target]? = some (.constant value))
    (canonical : value < fieldModulus) :
    packedWord packed coordinate = value := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have one := equations 1 (.constant 1) (by decide)
  have valueEq := equations target (.constant value) found
  have eq := accepted_csr_attempt_field_equality (attempts _ member)
  simp only [expressionField, Nat.cast_one] at one valueEq
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, one, one_mul, add_zero, valueEq] at eq
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) canonical eq

theorem accepted_public_coordinate {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (global family localIndex boundary coordinate target index : Nat)
    (member : attempt global family localIndex boundary [(coordinate, 1)] target ∈ exactCsrAttempts)
    (found : exactCsrExpressions[target]? = some (.publicWord index))
    (bound : index < publicStatementWordCount) :
    packedWord packed coordinate = publicWords.getD index 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have one := equations 1 (.constant 1) (by decide)
  have valueEq := equations target (.publicWord index) found
  have eq := accepted_csr_attempt_field_equality (attempts _ member)
  simp only [expressionField, Nat.cast_one] at one valueEq
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, one, one_mul, add_zero, valueEq] at eq
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (canonical_public_coordinate accepted.1 bound).2 eq

theorem accepted_copied_coordinate {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (global family localIndex boundary destination source : Nat)
    (member : attempt global family localIndex boundary [(destination, 1), (source, 158)] 0 ∈
      exactCsrAttempts) :
    packedWord packed destination = packedWord packed source := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have one := equations 1 (.constant 1) (by decide)
  have zero := equations 0 (.constant 0) (by decide)
  have negative := equations 158 (.sub 0 1) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one] at one zero negative
  rw [zero, one, zero_sub] at negative
  have eq := accepted_csr_attempt_field_equality (attempts _ member)
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, one, zero, negative, one_mul, neg_one_mul, add_zero] at eq
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) (add_neg_eq_zero.mp eq)


end HegemonCrypto.SmallWood.V8Smz9StableHashCsr
