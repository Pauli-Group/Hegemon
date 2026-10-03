import HegemonCrypto.SmallWoodV8Smz9SourceTreeGeometry
import HegemonCrypto.SmallWoodV8Smz9PostFinalSerializer

/-! In-range compact-path lookup certificates for the actual source tree.
The leaf positions are divided once per level, and every parity sibling is
inside that level. No zero/default lookup value is needed. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourcePathRange

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9HonestFinalGame
open V8Smz9HonestRequestSchedule V8Smz9SourceTreeGeometry V8Smz9PostFinalSerializer

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000

attribute [local irreducible] sourceMerkleLevels allSourceMerkleLevels sourceParentLevel

theorem source_sibling_lt_even_width (width index : Nat) (bounded : index < 2 * width) :
    sourceSibling index < 2 * width := by
  unfold sourceSibling
  split <;> omega

theorem source_sibling_lt_power (depth index : Nat) (positive : 0 < depth)
    (bounded : index < 2 ^ depth) : sourceSibling index < 2 ^ depth := by
  obtain ⟨previous, rfl⟩ := Nat.exists_eq_succ_of_ne_zero (by omega : depth ≠ 0)
  have bounded' : index < 2 * 2 ^ previous := by
    simpa only [pow_succ, Nat.mul_comm] using bounded
  simpa only [pow_succ, Nat.mul_comm] using source_sibling_lt_even_width (2 ^ previous) index bounded'

theorem source_current_index_bound (depth layer index : Nat)
    (inRange : layer ≤ depth) (bounded : index < 2 ^ depth) :
    index / 2 ^ layer < 2 ^ (depth - layer) := by
  apply (Nat.div_lt_iff_lt_mul (by positivity : 0 < 2 ^ layer)).2
  rw [← pow_add, Nat.sub_add_cancel inRange]
  exact bounded

theorem source_current_index_next (index layer : Nat) :
    index / 2 ^ layer / 2 = index / 2 ^ (layer + 1) := by
  rw [Nat.div_div_eq_div_mul, pow_succ]

theorem source_current_index_shift (index layer : Nat) :
    index / 2 / 2 ^ layer = index / 2 ^ (layer + 1) := by
  rw [Nat.div_div_eq_div_mul, pow_succ, Nat.mul_comm 2]

theorem actual_source_path_layer_indices_in_range
    (bound : Nat) (largeEnough : 249 ≤ bound) (labels : LeafIndex → DigestRegister)
    (oracle : OtherRawInput bound → DigestRegister) (index : LeafIndex)
    (layer : Nat) (inRange : layer < 23) :
    let level := (NonleafProgram.interpret oracle
      (allSourceMerkleLevels bound largeEnough labels)).2.getD layer []
    index.val / 2 ^ layer < level.length ∧
      sourceSibling (index.val / 2 ^ layer) < level.length := by
  dsimp only
  rw [all_source_merkle_levels_layer_width bound largeEnough labels oracle layer (by omega)]
  have current := source_current_index_bound 23 layer index.val (by omega) index.isLt
  exact ⟨current, source_sibling_lt_power (23 - layer) _ (by omega) current⟩

theorem getD_is_actual_element {Value : Type} (values : List Value) (index : Nat)
    (bounded : index < values.length) (fallback : Value) :
    values.getD index fallback = values.get ⟨index, bounded⟩ := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem bounded, Option.getD_some,
    List.get_eq_getElem]

theorem actual_source_path_layer_lookup_is_actual_element
    (bound : Nat) (largeEnough : 249 ≤ bound) (labels : LeafIndex → DigestRegister)
    (oracle : OtherRawInput bound → DigestRegister) (index : LeafIndex)
    (layer : Nat) (inRange : layer < 23) (fallback : DigestRegister) :
    let level := (NonleafProgram.interpret oracle
      (allSourceMerkleLevels bound largeEnough labels)).2.getD layer []
    let sibling := sourceSibling (index.val / 2 ^ layer)
    ∃ position : Fin level.length, position.val = sibling ∧
      level.getD sibling fallback = level.get position := by
  dsimp only
  have bounded := (actual_source_path_layer_indices_in_range bound largeEnough labels oracle index layer inRange).2
  exact ⟨⟨_, bounded⟩, rfl, getD_is_actual_element _ _ bounded fallback⟩

def CompactPathLookupsInRange : List (List DigestRegister) → (Fin 20 → Nat) → Prop
  | [], _ => True
  | level :: rest, indices =>
      (∀ opening, sourceSibling (indices opening) < level.length) ∧
        CompactPathLookupsInRange rest (fun opening => indices opening / 2)

theorem compact_path_range_of_layer_bounds (levels : List (List DigestRegister))
    (indices : Fin 20 → Nat)
    (bounded : ∀ layer, layer < levels.length → ∀ opening,
      sourceSibling (indices opening / 2 ^ layer) < (levels.getD layer []).length) :
    CompactPathLookupsInRange levels indices := by
  induction levels generalizing indices with
  | nil => trivial
  | cons level rest ih =>
      constructor
      · intro opening
        simpa only [pow_zero, Nat.div_one, List.getD_cons_zero] using
          bounded 0 (by simp only [List.length_cons]; omega) opening
      · apply ih
        intro layer layerBound opening
        have later := bounded (layer + 1) (by simp only [List.length_cons]; omega) opening
        simpa only [source_current_index_shift, List.getD_cons_succ] using later

theorem actual_source_compact_paths_all_lookups_in_range
    (bound : Nat) (largeEnough : 249 ≤ bound) (labels : LeafIndex → DigestRegister)
    (oracle : OtherRawInput bound → DigestRegister) (indices : Fin 20 → LeafIndex) :
    CompactPathLookupsInRange
      ((NonleafProgram.interpret oracle (allSourceMerkleLevels bound largeEnough labels)).2.take 23)
      (fun opening => (indices opening).val) := by
  apply compact_path_range_of_layer_bounds
  intro layer layerBound opening
  have layerRange : layer < 23 := lt_of_lt_of_le layerBound (List.length_take_le _ _)
  have bounded := (actual_source_path_layer_indices_in_range bound largeEnough labels oracle
    (indices opening) layer layerRange).2
  simpa only [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos layerRange] using bounded

/-- Same loop, but every included sibling is obtained with a checked Fin
index. This constructor has no fallback value at all. -/
def compactPathLevelsChecked : (levels : List (List DigestRegister)) → (indices : Fin 20 → Nat) →
    CompactPathLookupsInRange levels indices → Fin 20 → List DigestRegister
  | [], _, _ => fun _ => []
  | level :: rest, indices, bounded =>
      let later := compactPathLevelsChecked rest (fun opening => indices opening / 2) bounded.2
      fun opening =>
        let sibling := sourceSibling (indices opening)
        if sibling ∈ Finset.univ.image indices then later opening
        else level.get ⟨sibling, bounded.1 opening⟩ :: later opening

theorem compact_path_levels_equal_checked_loop (levels : List (List DigestRegister))
    (indices : Fin 20 → Nat) (bounded : CompactPathLookupsInRange levels indices) :
    compactPathLevels levels indices = compactPathLevelsChecked levels indices bounded := by
  induction levels generalizing indices with
  | nil => rfl
  | cons level rest ih =>
      funext opening
      simp only [compactPathLevels, compactPathLevelsChecked]
      split
      · exact congrFun (ih _ bounded.2) opening
      · rw [getD_is_actual_element _ _ (bounded.1 opening) 0, ih _ bounded.2]

end
end HegemonCrypto.SmallWood.V8Smz9SourcePathRange
