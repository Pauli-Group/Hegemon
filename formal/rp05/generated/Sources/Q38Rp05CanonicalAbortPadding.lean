import Q38Rp05PostFinalCompiler
import HegemonCrypto.SmallWoodV8Smz9AdjacentComposition

/-! Concrete mathematical padding for the nonce-abort branch. These points
are never emitted by the program; the abort kernel ignores them. -/
namespace HegemonCrypto.SmallWood.Q38Rp05CanonicalAbortPadding

open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9SourceIndexSampler
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 500000

def points : Fin 6 → Goldilocks := fun i => ((64 + i.val : Nat) : Goldilocks)

theorem points_distinct : Function.Injective points := by
  intro left right same
  have indices : (⟨64 + left.val, by omega⟩ : Fin 388) = ⟨64 + right.val, by omega⟩ :=
    actual_interpolation_nodes_distinct same
  apply Fin.ext
  have values : 64 + left.val = 64 + right.val := by
    simpa using congrArg (fun i : Fin 388 => i.val) indices
  exact Nat.add_left_cancel values

theorem points_nonzero (i : Fin 6) : points i ≠ 0 := by
  intro zero
  have indices : (⟨64 + i.val, by omega⟩ : Fin 388) = ⟨0, by omega⟩ :=
    actual_interpolation_nodes_distinct zero
  have values : 64 + i.val = 0 := by
    simpa using congrArg (fun j : Fin 388 => j.val) indices
  omega

theorem points_admissible : Smz9WitnessInterpolationAdmissible points := by
  refine ⟨actual_packing_nodes_distinct, points_distinct, ?_⟩
  intro opening lane same
  have laneBound : lane.val < 64 := lane.isLt
  have openingBound : opening.val < 6 := by
    simpa only [HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge.piopOpeningCount] using
      opening.isLt
  have indices : (⟨64 + opening.val, by omega⟩ : Fin 388) = ⟨lane.val, by omega⟩ :=
    actual_interpolation_nodes_distinct same
  have values : 64 + opening.val = lane.val := by
    simpa using congrArg (fun j : Fin 388 => j.val) indices
  omega

def targets : Targets points :=
  let indices : Fin 38 → LeafIndex := fun i => ⟨i.val, by omega⟩
  ⟨Q38Rp05PostFinalCompiler.indexedPoints indices,
    indexed_targets_admissible points points_distinct indices
      (by intro left right same
          exact Fin.ext (congrArg (fun i : LeafIndex => i.val) same))⟩

end
end HegemonCrypto.SmallWood.Q38Rp05CanonicalAbortPadding
