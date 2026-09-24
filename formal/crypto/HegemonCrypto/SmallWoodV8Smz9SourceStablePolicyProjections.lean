import HegemonCrypto.SmallWoodV8Smz9SourceParentMultiplication

namespace HegemonCrypto.SmallWood.V8Smz9SourceStablePolicyProjections
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem source_retirement_gate_a (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (lane : Nat) (lower : 25 ≤ lane) (upper : lane < 29) :
    (sourceMultiplication statement witness aux lane).a =
      (if statement.stablecoin.direction = .mint then 1 else 0) * stableSourceWord statement witness 4 := by
  simp only [sourceMultiplication,if_neg (show ¬lane < 18 by omega),
    if_neg (show ¬lane < 24 by omega),if_neg (show ¬lane = 24 by omega),if_pos upper]

theorem source_policy_output_c (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (lane : Nat) (lower : 24 ≤ lane) (upper : lane < 33) :
    (sourceMultiplication statement witness aux lane).c = 0 := by
  simp only [sourceMultiplication,if_neg (show ¬lane < 18 by omega),
    if_neg (show ¬lane < 24 by omega)]
  split_ifs <;> rfl

theorem source_retired_present_a (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) :
    (sourceMultiplication statement witness aux 24).a = 1 - stableSourceWord statement witness 4 := by
  rfl

theorem source_retired_present_b (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) :
    (sourceMultiplication statement witness aux 24).b = stableSourceWord statement witness 5 := by
  rfl

theorem source_retirement_inactive_a (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (lane : Nat) (lower : 29 ≤ lane) (upper : lane < 33) :
    (sourceMultiplication statement witness aux lane).a =
      1 - ((if statement.stablecoin.direction = .mint then 1 else 0) * stableSourceWord statement witness 4) := by
  simp only [sourceMultiplication,if_neg (show ¬lane < 18 by omega),
    if_neg (show ¬lane < 24 by omega),if_neg (show ¬lane = 24 by omega),
    if_neg (show ¬lane < 29 by omega),if_pos upper]

theorem source_retirement_inactive_b (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (lane : Nat) (lower : 29 ≤ lane) (upper : lane < 33) :
    (sourceMultiplication statement witness aux lane).b =
      [(sourceNumericValues aux).getD 2 0,(sourceNumericValues aux).getD 3 0,
       (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 27 0,
       (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 28 0].getD (lane - 29) 0 := by
  simp only [sourceMultiplication,if_neg (show ¬lane < 18 by omega),
    if_neg (show ¬lane < 24 by omega),if_neg (show ¬lane = 24 by omega),
    if_neg (show ¬lane < 29 by omega),if_pos upper]

end HegemonCrypto.SmallWood.V8Smz9SourceStablePolicyProjections
