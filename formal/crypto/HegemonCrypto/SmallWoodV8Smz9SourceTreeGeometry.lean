import HegemonCrypto.SmallWoodV8Smz9DynamicTransport

/-! Structural geometry of the actual interpreted source Merkle schedule.
These statements quantify over every nonleaf oracle and do not evaluate a
2^23-leaf tree, assume a caller-supplied shape, or assert Rust refinement. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceTreeGeometry

open V8Smz9HiddenLeafQrom V8Smz9HonestRequestSchedule V8Smz9RawCounterCompiler
open V8Smz9HiddenPatch V8Smz9EagerOracleGame V8Smz9HonestFinalGame
open V8Smz9RuntimeRandomness V8Smz9WholeViewObservation V8Smz9EagerPrivacy V8Smz9HonestHybrid
open V8Smz9DynamicRequest V8Smz9DynamicTransport
open Hegemon.Transaction.Poseidon2V8SemanticSpecification

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000

attribute [local irreducible] sourceParentLevel allSourceMerkleLevels sourceFieldXof

theorem source_merkle_levels_height (bound : Nat) (largeEnough : 249 ≤ bound)
    (depth : Nat) (labels : Fin (2 ^ depth) → DigestRegister)
    (oracle : OtherRawInput bound → DigestRegister) :
    (NonleafProgram.interpret oracle (sourceMerkleLevels bound largeEnough depth labels)).2.length =
      depth + 1 := by
  induction depth with
  | zero => rfl
  | succ depth ih =>
      simp only [sourceMerkleLevels, NonleafProgram.interpret_bind, NonleafProgram.interpret,
        List.length_cons]
      rw [ih]

theorem source_merkle_levels_widths (bound : Nat) (largeEnough : 249 ≤ bound)
    (depth : Nat) (labels : Fin (2 ^ depth) → DigestRegister)
    (oracle : OtherRawInput bound → DigestRegister) :
    ((NonleafProgram.interpret oracle (sourceMerkleLevels bound largeEnough depth labels)).2.map
      List.length) = (List.range (depth + 1)).reverse.map (fun exponent => 2 ^ exponent) := by
  induction depth with
  | zero => simp [sourceMerkleLevels, NonleafProgram.interpret]
  | succ depth ih =>
      simp only [sourceMerkleLevels, NonleafProgram.interpret_bind, NonleafProgram.interpret,
        List.map_cons, List.length_ofFn]
      rw [ih]
      conv_rhs => rw [List.range_succ]
      simp only [List.reverse_append, List.reverse_singleton, List.singleton_append, List.map_cons]

theorem source_merkle_levels_layer_width (bound : Nat) (largeEnough : 249 ≤ bound)
    (depth : Nat) (labels : Fin (2 ^ depth) → DigestRegister)
    (oracle : OtherRawInput bound → DigestRegister) (layer : Nat) (inRange : layer ≤ depth) :
    (((NonleafProgram.interpret oracle (sourceMerkleLevels bound largeEnough depth labels)).2.getD
      layer []).length) = 2 ^ (depth - layer) := by
  induction depth generalizing layer with
  | zero =>
      have layerZero : layer = 0 := by omega
      subst layer
      simp [sourceMerkleLevels, NonleafProgram.interpret]
  | succ depth ih =>
      simp only [sourceMerkleLevels, NonleafProgram.interpret_bind, NonleafProgram.interpret]
      cases layer with
      | zero => simp only [List.getD_cons_zero, List.length_ofFn, Nat.sub_zero]
      | succ layer =>
          simp only [List.getD_cons_succ, Nat.add_sub_add_right]
          exact ih _ layer (by omega)

attribute [local irreducible] sourceMerkleLevels sourcePrefinal sourceDynamicPrefinal

theorem all_source_merkle_levels_height (bound : Nat) (largeEnough : 249 ≤ bound)
    (labels : LeafIndex → DigestRegister) (oracle : OtherRawInput bound → DigestRegister) :
    (NonleafProgram.interpret oracle (allSourceMerkleLevels bound largeEnough labels)).2.length =
      24 := by
  simp only [allSourceMerkleLevels]
  exact source_merkle_levels_height bound largeEnough 23 labels oracle

theorem all_source_merkle_levels_layer_width (bound : Nat) (largeEnough : 249 ≤ bound)
    (labels : LeafIndex → DigestRegister) (oracle : OtherRawInput bound → DigestRegister)
    (layer : Nat) (inRange : layer ≤ 23) :
    (((NonleafProgram.interpret oracle (allSourceMerkleLevels bound largeEnough labels)).2.getD
      layer []).length) = 2 ^ (23 - layer) := by
  simp only [allSourceMerkleLevels]
  exact source_merkle_levels_layer_width bound largeEnough 23 labels oracle layer inRange

theorem prefinal_shape_fixed_tree {Other : Type} (shape : PrefinalShape Other)
    (oracle : Other → DigestRegister) (response : DecsFullCoefficients Goldilocks) :
    (NonleafProgram.interpret oracle (shape.fixed response)).tree =
      (NonleafProgram.interpret oracle shape.build).2 := by
  simp only [PrefinalShape.fixed, NonleafProgram.interpret_bind, NonleafProgram.interpret]

theorem prefinal_shape_dynamic_tree {Other : Type} (shape : PrefinalShape Other)
    (oracle : Other → DigestRegister)
    (respond : Option (List FieldWord) → DecsFullCoefficients Goldilocks) :
    (NonleafProgram.interpret oracle (shape.dynamic respond)).1.tree =
      (NonleafProgram.interpret oracle shape.build).2 := by
  simp only [PrefinalShape.dynamic, NonleafProgram.interpret_bind, NonleafProgram.interpret]

theorem source_prefinal_tree_is_actual_merkle_tree
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (response : DecsFullCoefficients Goldilocks) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister) :
    (NonleafProgram.interpret oracle
      (sourcePrefinal bound largeEnough statementBinding bindingFits salt labels response
        retainedRows rowBound)).tree =
      (NonleafProgram.interpret oracle (allSourceMerkleLevels bound (by omega) labels)).2 := by
  rw [source_prefinal_is_shape, prefinal_shape_fixed_tree]
  rfl

theorem source_dynamic_prefinal_tree_is_actual_merkle_tree
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (respond : Option (List FieldWord) → DecsFullCoefficients Goldilocks)
    (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister) :
    (NonleafProgram.interpret oracle
      (sourceDynamicPrefinal bound largeEnough statementBinding bindingFits salt labels respond
        retainedRows rowBound)).1.tree =
      (NonleafProgram.interpret oracle (allSourceMerkleLevels bound (by omega) labels)).2 := by
  rw [source_dynamic_prefinal_is_shape, prefinal_shape_dynamic_tree]
  rfl

theorem source_prefinal_tree_height
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (response : DecsFullCoefficients Goldilocks) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister) :
    (NonleafProgram.interpret oracle
      (sourcePrefinal bound largeEnough statementBinding bindingFits salt labels response
        retainedRows rowBound)).tree.length = 24 := by
  rw [source_prefinal_tree_is_actual_merkle_tree]
  exact all_source_merkle_levels_height _ _ _ _

theorem source_dynamic_prefinal_tree_height
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (respond : Option (List FieldWord) → DecsFullCoefficients Goldilocks)
    (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (oracle : OtherRawInput bound → DigestRegister) :
    (NonleafProgram.interpret oracle
      (sourceDynamicPrefinal bound largeEnough statementBinding bindingFits salt labels respond
        retainedRows rowBound)).1.tree.length = 24 := by
  rw [source_dynamic_prefinal_tree_is_actual_merkle_tree]
  exact all_source_merkle_levels_height _ _ _ _

end
end HegemonCrypto.SmallWood.V8Smz9SourceTreeGeometry
