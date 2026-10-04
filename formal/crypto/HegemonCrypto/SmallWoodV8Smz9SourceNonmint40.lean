import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeDigits

/-! Actual-source zero lanes for the non-mint stablecoin branches. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceNonmint40

open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem source_nonmint_numeric_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (nonmint : statement.stablecoin.direction ≠ .mint) :
    ∀ lane, (1 ≤ lane ∧ lane ≤ 8) ∨ (18 ≤ lane ∧ lane < 46) →
      (sourceNumericValues (sourceAux statement.stablecoin witness.stablecoin)).getD lane 0 = 0 := by
  intro lane selected
  cases mode : statement.stablecoin.direction with
  | mint => exact False.elim (nonmint mode)
  | disabled =>
    rcases selected with ⟨lower,upper⟩ | ⟨lower,upper⟩
    all_goals interval_cases lane <;>
      simp [sourceNumericValues,sourceAux,mode,disabledSourceAux,SourceMul3.rangeValues,List.ofFn_succ]
  | burn =>
    rcases selected with ⟨lower,upper⟩ | ⟨lower,upper⟩
    all_goals interval_cases lane <;>
      simp [sourceNumericValues,sourceAux,mode,SourceMul3.rangeValues,List.ofFn_succ]

theorem source_nonmint_boolean_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (nonmint : statement.stablecoin.direction ≠ .mint) :
    ∀ lane, 22 ≤ lane → lane < 26 →
      (sourceBooleanValues statement.stablecoin witness.stablecoin
        (sourceAux statement.stablecoin witness.stablecoin)).getD lane 0 = 0 := by
  intro lane lower upper
  cases mode : statement.stablecoin.direction with
  | mint => exact False.elim (nonmint mode)
  | disabled =>
    interval_cases lane <;> simp [sourceBooleanValues,sourceAux,mode,disabledSourceAux,List.ofFn_succ]
  | burn =>
    interval_cases lane <;> simp [sourceBooleanValues,sourceAux,mode,List.ofFn_succ]

/- Physical full candidate bindings. Numeric row 12 starts at 42176, so the
   requested numeric lanes are 42177..42184 and 42194..42221; Boolean row 11
   starts at 42112, so borrow lanes are 42134..42137. -/
theorem full_candidate_nonmint_numeric_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (nonmint : statement.stablecoin.direction ≠ .mint) :
    ∀ lane, (1 ≤ lane ∧ lane ≤ 8) ∨ (18 ≤ lane ∧ lane < 46) →
      (fullTypedSourceCandidate statement witness).getD
        (42176 + lane) 0 = 0 := by
  intro lane selected
  have rb := full_candidate_tail_flat_nat_readback statement witness
    .numeric 0 (by decide) ⟨lane, by
      rcases selected with h | h <;> omega⟩
  have address : (647 + TailFamily.numeric.base + 0) * 64 + lane = 42176 + lane := by
    simp only [TailFamily.base]
  rw [address] at rb
  have zero := source_nonmint_numeric_zero statement witness nonmint lane selected
  simpa only [tailFamilyWord, zero] using rb

theorem full_candidate_nonmint_boolean_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (nonmint : statement.stablecoin.direction ≠ .mint) :
    ∀ lane, 22 ≤ lane → lane < 26 →
      (fullTypedSourceCandidate statement witness).getD (42112 + lane) 0 = 0 := by
  intro lane lower upper
  have rb := full_candidate_tail_flat_nat_readback statement witness
    .booleans 0 (by decide) ⟨lane, by omega⟩
  have address : (647 + TailFamily.booleans.base + 0) * 64 + lane = 42112 + lane := by
    simp only [TailFamily.base]
  rw [address] at rb
  have zero := source_nonmint_boolean_zero statement witness nonmint lane lower upper
  simpa only [tailFamilyWord, zero] using rb

end HegemonCrypto.SmallWood.V8Smz9SourceNonmint40
