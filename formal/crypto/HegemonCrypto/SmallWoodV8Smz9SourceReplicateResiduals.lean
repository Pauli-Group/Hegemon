import HegemonCrypto.SmallWoodV8Smz9SourceReplicateCertificates
import HegemonCrypto.SmallWoodV8Smz9SourceReplicateReadback

namespace HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
set_option Elab.async false
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

noncomputable section

theorem actual_replicate_negative_one (pub : Nat → F) : actualCsrCoefficients pub 3 = -1 := by
  have expression := actual_csr_node_field_equation pub exact_replicate_negative_one_node
  have literal : actualCsrCoefficients pub 3 = ((18446744069414584320 : Nat) : F) := by
    simpa only [expressionField] using expression
  rw [literal]
  change (((18446744069414584321-1 : Nat) : ZMod 18446744069414584321)) = -1
  rw [Nat.cast_sub (by decide : 1 ≤ 18446744069414584321)]
  simp only [ZMod.natCast_self, Nat.cast_one, zero_sub]

theorem actual_replicate_expected_residual (pub : Nat → F) (words : List Nat) (index : Nat) :
    actualCsrResidual pub words (expectedReplicateAttempt index) =
      (words.getD ((index/63)*64+(index%63+1)) 0 : F) -
        (words.getD ((index/63)*64) 0 : F) := by
  simp only [actualCsrResidual, expectedReplicateAttempt, attempt, actualCsrTerms,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    (actual_csr_zero_one pub).1, (actual_csr_zero_one pub).2,
    actual_replicate_negative_one, one_mul, neg_one_mul, add_zero, sub_eq_add_neg, neg_zero]

/-- Constructor-supplied lane equality, not an EqualLanes assumption. The
public coefficient input and the complete caller tail remain arbitrary. -/
theorem constructed_replicate_expected_zero (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (pub : Nat → F)
    (index : Nat) (bound : index < 15561) :
    actualCsrResidual pub (constructedAssignment statement witness live tail)
      (expectedReplicateAttempt index) = 0 := by
  rw [actual_replicate_expected_residual]
  have rowBound : index/63 < 247 := by omega
  have laneBound : index%63+1 < 64 := by omega
  have same := constructed_raw_lanes_equal statement witness live tail
    ⟨index/63, rowBound⟩ ⟨index%63+1, laneBound⟩ ⟨0, by decide⟩
  simp only [Nat.add_zero] at same
  rw [same, sub_self]

/-- All 15,561 distinct actual table entries, including their full metadata
and actual coefficient-expression interpretation. No typed-validity premise. -/
theorem constructed_all_15561_actual_replicate_csr_zero
    (statement : V8PublicStatement) (witness : V8Witness) (live : LiveInitialStates)
    (tail : List Nat) (pub : Nat → F) (index : Nat) (bound : index < 15561) :
    (exactCsrAttempts[index]?).map
        (actualCsrResidual pub (constructedAssignment statement witness live tail)) = some 0 := by
  rw [exact_replicate_attempt index bound]
  simp only [Option.map_some, constructed_replicate_expected_zero statement witness live tail pub index bound]

theorem typed_all_15561_actual_replicate_csr_zero
    (statement : V8PublicStatement) (witness : V8Witness) (tail : List Nat)
    (pub : Nat → F) (index : Nat) (bound : index < 15561) :
    (exactCsrAttempts[index]?).map
        (actualCsrResidual pub (typedAssignment statement witness tail)) = some 0 :=
  constructed_all_15561_actual_replicate_csr_zero statement witness _ tail pub index bound

end
end HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
