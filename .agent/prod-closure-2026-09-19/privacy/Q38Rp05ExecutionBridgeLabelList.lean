import Q38Rp05ExecutionBridgeNamedState
import Q38ConcreteAdaptivePrivacy

namespace HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge

open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Other Branch BaseWork : Type}
variable [Fintype Other] [DecidableEq Other]
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype BaseWork] [DecidableEq BaseWork]

local notation "FullInput" => Rp05LeafInput ⊕ Other

section IndexedRawEnvironment

variable {Input Work Index : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work]
variable [Fintype Index] [DecidableEq Index]

def swapOracleLabelsList (keys : Index → Input) : List Index →
    ((Input → DigestRegister) × (Index → DigestRegister)) →
      ((Input → DigestRegister) × (Index → DigestRegister))
  | [], pair => pair
  | index :: remaining, pair =>
      swapOracleLabelsList keys remaining
        (swapOracleLabels (keys index) index pair)

omit [Fintype Work] [DecidableEq Work] in
/-- Exact list form; this is the missing state-level register bookkeeping,
before any labels are traced out. -/
theorem raw_swap_list_vector_labeled_state
    (keys : Index → Input) (indices : List Index)
    (oracle : Input → DigestRegister) (labels : Index → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    rawSwapList keys indices (vectorLabeledOracleState oracle labels state) =
      let pair := swapOracleLabelsList keys indices (oracle, labels)
      vectorLabeledOracleState pair.1 pair.2 state := by
  induction indices generalizing oracle labels with
  | nil => rfl
  | cons index remaining inductionHypothesis =>
      simp only [rawSwapList, swapOracleLabelsList]
      rw [indexed_raw_swap_vector_labeled_state]
      exact inductionHypothesis
        (Function.update oracle (keys index) (labels index))
        (Function.update labels index (oracle (keys index)))

omit [Fintype Other] [Fintype Index] in
theorem swap_oracle_labels_list_first_is_update
    (count : Nat) (keys : Index → FullInput)
    (sites : Fin count → Index) (siteDistinct : Function.Injective sites)
    (keyDistinct : Function.Injective (fun i => keys (sites i)))
    (oracle : FullInput → DigestRegister) (labels : Index → DigestRegister) :
    (swapOracleLabelsList keys (List.ofFn sites) (oracle, labels)).1 =
      updateRp05Batch count (fun i => keys (sites i))
        (fun i => labels (sites i)) oracle := by
  induction count generalizing oracle labels with
  | zero => rfl
  | succ count inductionHypothesis =>
      rw [List.ofFn_succ]
      simp only [swapOracleLabelsList, swapOracleLabels, updateRp05Batch]
      have tailEquality := inductionHypothesis (fun i => sites i.succ)
        (fun left right same => Fin.succ_injective _ (siteDistinct same))
        (fun left right same => Fin.succ_injective _ (keyDistinct same))
        (Function.update oracle (keys (sites 0)) (labels (sites 0)))
        (Function.update labels (sites 0) (oracle (keys (sites 0))))
      have labelsTail :
          (fun (i : Fin count) => Function.update labels (sites 0) (oracle (keys (sites 0)))
            (sites i.succ)) = (fun (i : Fin count) => labels (sites i.succ)) := by
        funext (i : Fin count)
        exact Function.update_of_ne
          (show sites i.succ ≠ sites 0 by
            intro same
            exact Fin.succ_ne_zero i (siteDistinct same)) _ _
      rw [labelsTail] at tailEquality
      exact tailEquality

end IndexedRawEnvironment
end

end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
