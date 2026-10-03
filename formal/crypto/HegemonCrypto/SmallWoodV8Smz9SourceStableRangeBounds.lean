import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeDigits
import HegemonCrypto.SmallWoodV8Smz9SourceStableDirectRangeBounds
import HegemonCrypto.SmallWoodV8Smz9SourceStableAuxRangeBounds

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRangeBounds
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits
open HegemonCrypto.SmallWood.V8Smz9SourceStableDirectRangeBounds
open HegemonCrypto.SmallWood.V8Smz9SourceStableAuxRangeBounds
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem source_range_entry_bound (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 66) :
    (sourceRangeEntry statement witness slot.val).1<2^(sourceRangeWidth slot.val) := by
  have numeric := valid_numeric_input_bounds statement witness valid
  have left := actual_left_mul3_bounds statement witness numeric
  have right := actual_right_mul3_bounds statement witness numeric
  obtain ⟨lx0,lx1,lp0,lp1,lp2,lc0,lout,_,lc1,lc2⟩ := left
  obtain ⟨rx0,rx1,rp0,rp1,rp2,rc0,rout,_,rc1,rc2⟩ := right
  have lo0 := lout 0
  have lo1 := lout 1
  have lo2 := lout 2
  have lo3 := lout 3
  have ro0 := rout 0
  have ro1 := rout 1
  have ro2 := rout 2
  have ro3 := rout 3
  have d0 := actual_difference_bound statement witness 0
  have d1 := actual_difference_bound statement witness 1
  have d2 := actual_difference_bound statement witness 2
  have d3 := actual_difference_bound statement witness 3
  obtain ⟨_,height,ratio,numerator,denominator,cap,amount,debt,beforeMinted,retiredAt,oracleMax,attestationMax,_,_⟩ := numeric
  obtain ⟨configAsset,configPolicy,collateralAsset,enabledAt,oracleSubmittedAt,attestationCreatedAt,
    collateralScale,beforeSequence,afterSequence,beforeEpoch,afterEpoch,magnitude,beforeTotalDebt,afterMinted⟩ :=
    valid_source_stable_direct_bounds statement witness valid
  obtain ⟨ratioSlack,enabledAge,retirementOrderGap,retirementHeightGap,oracleAge,oracleSlack,
    attestationAge,attestationSlack,beforeCapSlack,afterCapSlack⟩ :=
    valid_source_stable_aux_bounds statement witness valid
  obtain ⟨epochGap,epochRemainder,pathQuotient⟩ := valid_aux_epoch_and_path_ranges statement witness valid
  simp only [limbBase] at *
  fin_cases slot <;>
    simp only [sourceRangeEntry,sourceRangeValues,SourceMul3.rangeValues,List.ofFn_succ,
      List.map_cons,List.map_nil,List.nil_append,List.cons_append,List.getD_cons_zero,
      List.getD_cons_succ,sourceRangeWidth] <;> norm_num <;> omega

end HegemonCrypto.SmallWood.V8Smz9SourceStableRangeBounds
