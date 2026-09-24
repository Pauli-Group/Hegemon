import HegemonCrypto.SmallWoodV8Smz9SourceTailNumericInputs

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableAuxRangeBounds
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

structure SourceStableAuxRangeBounds (statement : V8PublicStatement) (witness : V8Witness) : Prop where
  ratioSlack : (sourceAux statement.stablecoin witness.stablecoin).ratioSlack < 2^32
  enabledAge : (sourceAux statement.stablecoin witness.stablecoin).enabledAge < 2^63
  retirementOrderGap : (sourceAux statement.stablecoin witness.stablecoin).retirementOrderGap < 2^63
  retirementHeightGap : (sourceAux statement.stablecoin witness.stablecoin).retirementHeightGap < 2^63
  oracleAge : (sourceAux statement.stablecoin witness.stablecoin).oracleAge < 2^63
  oracleSlack : (sourceAux statement.stablecoin witness.stablecoin).oracleSlack < 2^63
  attestationAge : (sourceAux statement.stablecoin witness.stablecoin).attestationAge < 2^63
  attestationSlack : (sourceAux statement.stablecoin witness.stablecoin).attestationSlack < 2^63
  beforeCapSlack : (sourceAux statement.stablecoin witness.stablecoin).beforeCapSlack < 2^56
  afterCapSlack : (sourceAux statement.stablecoin witness.stablecoin).afterCapSlack < 2^56

theorem valid_source_stable_aux_bounds (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) : SourceStableAuxRangeBounds statement witness := by
  obtain ⟨_,height,ratio,_,_,cap,_,_,_,retiredAt,oracleMax,attestationMax,_,_⟩ :=
    valid_numeric_input_bounds statement witness valid
  by_cases disabled : statement.stablecoin.direction=.disabled
  · refine ⟨?_,?_,?_,?_,?_,?_,?_,?_,?_,?_⟩
    all_goals rw [source_aux_disabled _ _ disabled]; decide
  · refine ⟨?_,?_,?_,?_,?_,?_,?_,?_,?_,?_⟩
    all_goals simp only [sourceAux,if_neg disabled]
    all_goals (try split_ifs) <;> omega

end HegemonCrypto.SmallWood.V8Smz9SourceStableAuxRangeBounds
