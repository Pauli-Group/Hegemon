import HegemonCrypto.SmallWoodV8Smz9SourceActionIntentControls
import HegemonCrypto.SmallWoodV8Smz9SourceDummyInitialResiduals

/-! One injective 288-entry index selects exactly two disjoint raw CSR families.
This is a source-construction endpoint, not acceptance of all20605 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceInitial288
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SourceActionIntentInitial
open HegemonCrypto.SmallWood.V8Smz9SourceDummyInitial
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

def initial288GlobalIndex (offset : Fin 288) : Nat :=
  if offset.val < 240 then 18468 + offset.val else 19120 + (offset.val - 240)

def initial288Family (offset : Fin 288) : Nat := if offset.val < 240 then 24 else 35
def initial288LocalIndex (offset : Fin 288) : Nat :=
  if offset.val < 240 then offset.val else offset.val - 240

theorem initial288_global_index_injective : Function.Injective initial288GlobalIndex := by
  intro left right equal
  apply Fin.ext
  unfold initial288GlobalIndex at equal
  split_ifs at equal <;> omega

theorem initial288_global_index_bound (offset : Fin 288) : initial288GlobalIndex offset < 20605 := by
  unfold initial288GlobalIndex
  split_ifs <;> omega

noncomputable section

theorem full_candidate_actual_all_288_initial_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (offset : Fin 288) :
    ∃ entry, exactCsrAttempts[initial288GlobalIndex offset]? = some entry ∧
      entry.family = initial288Family offset ∧ entry.localIndex = initial288LocalIndex offset ∧
      actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
        (fullTypedSourceCandidate statement witness) entry = 0 := by
  by_cases action : offset.val < 240
  · simpa only [initial288GlobalIndex, initial288Family, initial288LocalIndex, if_pos action] using
      full_candidate_actual_action_all_240_zero statement witness valid ⟨offset.val, action⟩
  · simpa only [initial288GlobalIndex, initial288Family, initial288LocalIndex, if_neg action] using
      full_candidate_actual_dummy_all_48_zero statement witness valid ⟨offset.val - 240, by omega⟩

end
end HegemonCrypto.SmallWood.V8Smz9SourceInitial288
