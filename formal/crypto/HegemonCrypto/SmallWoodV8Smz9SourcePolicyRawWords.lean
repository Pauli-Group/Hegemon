import HegemonCrypto.SmallWoodV8Smz9SourceReplicateReadback
import HegemonCrypto.SmallWoodV8Smz9PolicySourceWords
import Mathlib.Data.Fintype.Fin
import Mathlib.Tactic.FinCases

namespace HegemonCrypto.SmallWood.V8Smz9SourcePolicyInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9PolicySourceWords
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

theorem policy_word_row_bound (wordIndex : Fin 32) : policyWordRow wordIndex.val < 247 := by
  unfold policyWordRow
  split <;> (try split) <;> omega

/-- Threshold, signer count, then all six five-word tags, in source order.
This is a fixed-array projection identity; no semantic hash equality is used. -/
theorem constructed_policy_source_word (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (wordIndex : Fin 32) :
    constructedRawWord statement witness live (policyWordRow wordIndex.val) =
      (sourcePolicyWords witness.authorization).getD wordIndex.val 0 := by
  fin_cases wordIndex <;> rfl

theorem typed_policy_raw_word (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (wordIndex : Fin 32) :
    (typedAssignment statement witness tail).getD (rawIndex (policyWordRow wordIndex.val)) 0 =
      (sourcePolicyWords witness.authorization).getD wordIndex.val 0 := by
  simp only [rawIndex, rawRowStart, Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
    Nat.zero_add, typedAssignment]
  change (constructedAssignment statement witness (typedLiveInitialStates statement witness) tail).getD
    ((policyWordRow wordIndex.val)*64+0) 0 = _
  rw [constructed_all_raw_rows_readback statement witness _ tail
      ⟨policyWordRow wordIndex.val, policy_word_row_bound wordIndex⟩ ⟨0, by decide⟩,
    constructed_policy_source_word]



end HegemonCrypto.SmallWood.V8Smz9SourcePolicyInitial
