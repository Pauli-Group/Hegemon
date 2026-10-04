import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceBaseMultiplication

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits
open HegemonCrypto.SmallWood.V8Smz9SourceBaseMultiplication
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem full_candidate_boolean_at (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) :
    (fullTypedSourceCandidate statement witness).getD (42112 + lane.val) 0 =
      (sourceBooleanValues statement.stablecoin witness.stablecoin
        (sourceAux statement.stablecoin witness.stablecoin)).getD lane.val 0 := by
  exact full_candidate_tail_flat_nat_readback statement witness .booleans 0 (by decide) lane

theorem full_candidate_multiplication_a (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) :
    (fullTypedSourceCandidate statement witness).getD (42240 + lane.val) 0 =
      (sourceMultiplication statement witness
        (sourceAux statement.stablecoin witness.stablecoin) lane.val).a := by
  exact full_candidate_tail_flat_nat_readback statement witness .multiplication 0 (by decide) lane

theorem full_candidate_multiplication_b (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) :
    (fullTypedSourceCandidate statement witness).getD (42304 + lane.val) 0 =
      (sourceMultiplication statement witness
        (sourceAux statement.stablecoin witness.stablecoin) lane.val).b := by
  exact full_candidate_tail_flat_nat_readback statement witness .multiplication 1 (by decide) lane

theorem full_candidate_multiplication_c (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) :
    (fullTypedSourceCandidate statement witness).getD (42368 + lane.val) 0 =
      (sourceMultiplication statement witness
        (sourceAux statement.stablecoin witness.stablecoin) lane.val).c := by
  exact full_candidate_tail_flat_nat_readback statement witness .multiplication 2 (by decide) lane

theorem actual_source_same_epoch_boolean (statement : V8PublicStatement) (witness : V8Witness) :
    (sourceAux statement.stablecoin witness.stablecoin).sameEpoch = 0 ∨
      (sourceAux statement.stablecoin witness.stablecoin).sameEpoch = 1 := by
  unfold sourceAux
  split_ifs <;> simp [disabledSourceAux]
  tauto

theorem full_candidate_boolean_absolute (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (lower : 42112 ≤ index) (upper : index < 42176) :
    (fullTypedSourceCandidate statement witness).getD index 0 =
      (sourceBooleanValues statement.stablecoin witness.stablecoin
        (sourceAux statement.stablecoin witness.stablecoin)).getD (index - 42112) 0 := by
  have readback := full_candidate_boolean_at statement witness ⟨index - 42112,by omega⟩
  have address : 42112 + (index - 42112) = index := by omega
  rw [address] at readback
  exact readback

theorem full_candidate_multiplication_a_absolute (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (lower : 42240 ≤ index) (upper : index < 42304) :
    (fullTypedSourceCandidate statement witness).getD index 0 =
      (sourceMultiplication statement witness
        (sourceAux statement.stablecoin witness.stablecoin) (index - 42240)).a := by
  have readback := full_candidate_multiplication_a statement witness ⟨index - 42240,by omega⟩
  have address : 42240 + (index - 42240) = index := by omega
  rw [address] at readback
  exact readback

theorem full_candidate_multiplication_b_absolute (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (lower : 42304 ≤ index) (upper : index < 42368) :
    (fullTypedSourceCandidate statement witness).getD index 0 =
      (sourceMultiplication statement witness
        (sourceAux statement.stablecoin witness.stablecoin) (index - 42304)).b := by
  have readback := full_candidate_multiplication_b statement witness ⟨index - 42304,by omega⟩
  have address : 42304 + (index - 42304) = index := by omega
  rw [address] at readback
  exact readback

theorem full_candidate_multiplication_c_absolute (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (lower : 42368 ≤ index) (upper : index < 42432) :
    (fullTypedSourceCandidate statement witness).getD index 0 =
      (sourceMultiplication statement witness
        (sourceAux statement.stablecoin witness.stablecoin) (index - 42368)).c := by
  have readback := full_candidate_multiplication_c statement witness ⟨index - 42368,by omega⟩
  have address : 42368 + (index - 42368) = index := by omega
  rw [address] at readback
  exact readback

end HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
