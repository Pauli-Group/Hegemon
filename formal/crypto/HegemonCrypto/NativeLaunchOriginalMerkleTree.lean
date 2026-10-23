import HegemonCrypto.NativeLaunchMerklePathBinding

/-!
Calculated complete binary trees for GENERAL leaf inputs. This does not assume
honest polynomial generation or low degree for an adversarial tree. At depth d
only indices below 2^d occur. The source's adjacent pairs and successive integer
divisions calculate both the root and each ordinary path. Native node inputs
contain ordered full child digests only; the root wrapper uses full salt/root/
statement. Query membership below is in a calculated finite list, not a claim
of temporal oracle execution. Rust refinement and chronology remain open.
-/
set_option autoImplicit false
namespace HegemonCrypto.NativeLaunchOriginalMerkleTree
open NativeLaunchAdaptiveHistoryCodec (Family Word RawInput)
open NativeLaunchRelationModelStatement
open NativeLaunchMerklePathBinding
open NativeLaunchFppHistoryBinding (Digest Oracle History RelevantCollision)

abbrev Level := Nat → Digest

def reduce (H : Oracle) (family : Family) (level : Level) : Level :=
  fun index => H (nodeFrame family (level (2 * index)) (level (2 * index + 1)))

def root (H : Oracle) (family : Family) : Nat → Level → Digest
  | 0, level => level 0
  | depth + 1, level => root H family depth (reduce H family level)

def sibling (level : Level) (index : Nat) : Digest :=
  if index % 2 = 0 then level (index + 1) else level (index - 1)

def route (index : Nat) : Bool := decide (index % 2 ≠ 0)

/-- Both sides initially have the calculated sibling. A routing adapter may
replace the rebuilt siblings while preserving these index-derived directions. -/
def path (H : Oracle) (family : Family) : (depth : Nat) → Level → Nat → PairedPath depth
  | 0, _, _ => .nil
  | depth + 1, level, index =>
      .step (route index) (sibling level index) (sibling level index)
        (path H family depth (reduce H family level) (index / 2))

def siblings (H : Oracle) (family : Family) : Nat → Level → Nat → List Digest
  | 0, _, _ => []
  | depth + 1, level, index =>
      sibling level index :: siblings H family depth (reduce H family level) (index / 2)

theorem siblings_length (H : Oracle) (family : Family) (depth : Nat) (level : Level) (index : Nat) :
    (siblings H family depth level index).length = depth := by
  induction depth generalizing level index with
  | zero => rfl
  | succ depth ih => simp [siblings, ih]

/-- The arithmetic is precisely even: current,left; odd: sibling,left. -/
theorem calculated_node (family : Family) (level : Level) (index : Nat) :
    nodeInput family (route index) (level index) (sibling level index) =
      nodeFrame family (level (2 * (index / 2))) (level (2 * (index / 2) + 1)) := by
  have remainder := Nat.mod_lt index (by decide : 0 < 2)
  have decomposition := Nat.mod_add_div index 2
  by_cases even : index % 2 = 0
  · have current : index = 2 * (index / 2) := by omega
    have next : index + 1 = 2 * (index / 2) + 1 := by omega
    simp only [nodeInput, route, even, ne_eq, not_true_eq_false, decide_false, Bool.false_eq_true,
      ↓reduceIte, sibling]
    exact congrArg₂ (nodeFrame family) (congrArg level current) (congrArg level next)
  · have previous : index - 1 = 2 * (index / 2) := by omega
    have current : index = 2 * (index / 2) + 1 := by omega
    simp only [nodeInput, route, even, ne_eq, not_false_eq_true, decide_true, ↓reduceIte, sibling]
    exact congrArg₂ (nodeFrame family) (congrArg level previous) (congrArg level current)

theorem half_bound {depth index : Nat} (bound : index < 2 ^ (depth + 1)) :
    index / 2 < 2 ^ depth := by
  rw [pow_succ] at bound
  omega

theorem calculated_path_root (H : Oracle) (family : Family) (depth : Nat)
    (level : Level) (index : Nat) (bound : index < 2 ^ depth) (rebuilt : Bool) :
    pathRoot H family rebuilt (path H family depth level index) (level index) =
      root H family depth level := by
  induction depth generalizing level index with
  | zero =>
      have h : index = 0 := by simpa using bound
      subst index
      rfl
  | succ depth ih =>
      simp only [path, pathRoot, ite_self, calculated_node, root]
      exact ih (reduce H family level) (index / 2) (half_bound bound)

/-- Every internal-node query, bottom level first, in source leaf-index order. -/
def nodeQueries (H : Oracle) (family : Family) : Nat → Level → History
  | 0, _ => []
  | depth + 1, level =>
      List.ofFn (fun index : Fin (2 ^ depth) =>
        nodeFrame family (level (2 * index.val)) (level (2 * index.val + 1))) ++
      nodeQueries H family depth (reduce H family level)

theorem calculated_path_queries (H : Oracle) (family : Family) (depth : Nat)
    (level : Level) (index : Nat) (bound : index < 2 ^ depth) (rebuilt : Bool) :
    ∀ key ∈ pathInputs H family rebuilt (path H family depth level index) (level index),
      key ∈ nodeQueries H family depth level := by
  induction depth generalizing level index with
  | zero => simp [path, pathInputs]
  | succ depth ih =>
      intro key member
      simp only [path, pathInputs, ite_self, calculated_node, List.mem_cons] at member
      rcases member with equal | later
      · subst key
        apply List.mem_append_left
        exact List.mem_ofFn.mpr ⟨⟨index / 2, half_bound bound⟩, rfl⟩
      · apply List.mem_append_right
        exact ih (reduce H family level) (index / 2) (half_bound bound) key later

def leafLevel (H : Oracle) (leaves : Nat → RawInput) : Level := fun index => H (leaves index)

def treeRoot (H : Oracle) (family : Family) (depth : Nat) (leaves : Nat → RawInput) : Digest :=
  root H family depth (leafLevel H leaves)

def treeQueries (H : Oracle) (family : Family) (depth : Nat) (leaves : Nat → RawInput) : History :=
  List.ofFn (fun index : Fin (2 ^ depth) => leaves index.val) ++
    nodeQueries H family depth (leafLevel H leaves)

def wrapper {family : Family} (H : Oracle) (depth : Nat) (leaves : Nat → RawInput)
    (salt : Fin 4 → Word) (statement : Statement family) : RawInput :=
  rootFrame salt (treeRoot H family depth leaves) statement

def queries {family : Family} (H : Oracle) (depth : Nat) (leaves : Nat → RawInput)
    (salt : Fin 4 → Word) (statement : Statement family) : History :=
  treeQueries H family depth leaves ++ [wrapper H depth leaves salt statement]

theorem leaf_recorded {family : Family} (H : Oracle) (depth : Nat) (leaves : Nat → RawInput)
    (salt : Fin 4 → Word) (statement : Statement family) (index : Nat) (bound : index < 2 ^ depth) :
    leaves index ∈ queries H depth leaves salt statement := by
  apply List.mem_append_left
  apply List.mem_append_left
  exact List.mem_ofFn.mpr ⟨⟨index, bound⟩, rfl⟩

theorem nodes_recorded {family : Family} (H : Oracle) (depth : Nat) (leaves : Nat → RawInput)
    (salt : Fin 4 → Word) (statement : Statement family) (index : Nat) (bound : index < 2 ^ depth)
    (rebuilt : Bool) :
    ∀ key ∈ pathInputs H family rebuilt (path H family depth (leafLevel H leaves) index) (H (leaves index)),
      key ∈ queries H depth leaves salt statement := by
  intro key member
  apply List.mem_append_left
  apply List.mem_append_right
  exact calculated_path_queries H family depth (leafLevel H leaves) index bound rebuilt key member

theorem calculated_wrapper {family : Family} (H : Oracle) (depth : Nat) (leaves : Nat → RawInput)
    (salt : Fin 4 → Word) (statement : Statement family) (index : Nat) (bound : index < 2 ^ depth)
    (rebuilt : Bool) :
    wrappedPath H family rebuilt (path H family depth (leafLevel H leaves) index)
      (leaves index) salt statement = wrapper H depth leaves salt statement := by
  unfold wrappedPath wrapper treeRoot
  rw [show H (leaves index) = leafLevel H leaves index from rfl,
    calculated_path_root H family depth (leafLevel H leaves) index bound rebuilt]

theorem wrapper_recorded {family : Family} (H : Oracle) (depth : Nat) (leaves : Nat → RawInput)
    (salt : Fin 4 → Word) (statement : Statement family) (index : Nat) (bound : index < 2 ^ depth) :
    wrappedPath H family false (path H family depth (leafLevel H leaves) index)
      (leaves index) salt statement ∈ queries H depth leaves salt statement := by
  rw [calculated_wrapper H depth leaves salt statement index bound false]
  simp [queries]

/-- General canonical source: arbitrary cells/masks, with no polynomial-origin
or bounded-degree restriction. Index, common salt and complete statement are
constructed, not supplied independently at every leaf. -/
structure NativeLeaves (family : Family) where
  salt : Fin 4 → Word
  statement : Statement family
  tapes : Fin (2^23) → Fin 8 → Word
  cells : Fin (2^23) → Fin 140 → FieldWord
  masks : Fin (2^23) → Fin 5 → FieldWord

def nativeFields {family : Family} (source : NativeLeaves family) (index : Fin (2^23)) : LeafFields :=
  ⟨source.salt, index, source.tapes index, source.cells index, source.masks index⟩

def nativeLeaves {family : Family} (source : NativeLeaves family) (index : Nat) : RawInput :=
  if bound : index < 2^23 then strictLeafFrame source.statement (nativeFields source ⟨index, bound⟩)
  else []

theorem native_leaf_at {family : Family} (source : NativeLeaves family) (index : Fin (2^23)) :
    nativeLeaves source index.val = strictLeafFrame source.statement (nativeFields source index) := by
  simp [nativeLeaves]

/-- Symbolic specialization: no enumeration of the 2^23 leaves is performed. -/
theorem native_calculated_path_root {family : Family} (H : Oracle) (source : NativeLeaves family)
    (index : Fin (2^23)) :
    pathRoot H family false (path H family 23 (leafLevel H (nativeLeaves source)) index.val)
      (H (strictLeafFrame source.statement (nativeFields source index))) =
      treeRoot H family 23 (nativeLeaves source) := by
  rw [← native_leaf_at source index]
  exact calculated_path_root H family 23 (leafLevel H (nativeLeaves source)) index.val index.isLt false

end HegemonCrypto.NativeLaunchOriginalMerkleTree
