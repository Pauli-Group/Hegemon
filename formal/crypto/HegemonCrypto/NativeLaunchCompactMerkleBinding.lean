import HegemonCrypto.NativeLaunchCompactMerklePath
import HegemonCrypto.NativeLaunchMerklePathBinding

/-! Composition of executable compact reconstruction with exact framed Merkle
binding. Direction bits are computed from the selected Nat index, never supplied
as an alignment premise. Prior ordinary-path/history provenance remains explicit.
No original-tree construction, Rust refinement, chronology or QROM claim. -/
set_option autoImplicit false
namespace HegemonCrypto.NativeLaunchCompactMerkleBinding
open NativeLaunchAdaptiveHistoryCodec (Family Word RawInput)
open NativeLaunchRelationModelStatement
open NativeLaunchLeafReadback
open NativeLaunchFppHistoryBinding (Digest Oracle History RelevantCollision)
open NativeLaunchMerklePathBinding
open NativeLaunchCompactMerklePath (Opening walk parent reconstruct)

def nodeHash (H : Oracle) (family : Family) (left right : Digest) : Digest :=
  H (nodeFrame family left right)

/-- The same index supplies BOTH paths' directions, then progresses by /2. -/
def pairPaths : (index : Nat) → (prior rebuilt : List Digest) →
    prior.length = rebuilt.length → PairedPath prior.length
  | _, [], [], _ => .nil
  | _, [], _ :: _, same => False.elim (by simp at same)
  | _, _ :: _, [], same => False.elim (by simp at same)
  | index, left :: prior, right :: rebuilt, same =>
      .step (decide (index % 2 ≠ 0)) left right
        (pairPaths (index / 2) prior rebuilt (by simpa using same))

theorem paired_root_eq_walk (H : Oracle) (family : Family) (side : Bool)
    (index : Nat) (prior rebuilt : List Digest) (same : prior.length = rebuilt.length)
    (leaf : Digest) :
    pathRoot H family side (pairPaths index prior rebuilt same) leaf =
      (walk (nodeHash H family) index leaf (if side then rebuilt else prior)).2 := by
  induction prior generalizing index rebuilt leaf with
  | nil => cases rebuilt with
    | nil => cases side <;> rfl
    | cons _ _ => simp at same
  | cons left prior ih => cases rebuilt with
    | nil => simp at same
    | cons right rebuilt =>
      cases side <;> by_cases parity : index % 2 = 0 <;>
        simp [pairPaths, pathRoot, walk, nodeInput, parent, nodeHash, parity, ih]

/-- Ordinary framed query trace with exactly the same source index progression. -/
def ordinaryInputs (H : Oracle) (family : Family) : Nat → Digest → List Digest → History
  | _, _, [] => []
  | index, leaf, sibling :: rest =>
      let input := if index % 2 = 0 then nodeFrame family leaf sibling
        else nodeFrame family sibling leaf
      input :: ordinaryInputs H family (index / 2) (H input) rest

theorem paired_inputs_eq_ordinary (H : Oracle) (family : Family) (side : Bool)
    (index : Nat) (prior rebuilt : List Digest) (same : prior.length = rebuilt.length)
    (leaf : Digest) :
    pathInputs H family side (pairPaths index prior rebuilt same) leaf =
      ordinaryInputs H family index leaf (if side then rebuilt else prior) := by
  induction prior generalizing index rebuilt leaf with
  | nil => cases rebuilt with
    | nil => cases side <;> rfl
    | cons _ _ => simp at same
  | cons left prior ih => cases rebuilt with
    | nil => simp at same
    | cons right rebuilt =>
      cases side <;> by_cases parity : index % 2 = 0 <;>
        simp [pairPaths, pathInputs, ordinaryInputs, nodeInput, parity, ih]

def ordinaryWrapped (H : Oracle) (family : Family) (index : Nat)
    (leaf : RawInput) (path : List Digest) (salt : Fin 4 → Word)
    (statement : Statement family) : RawInput :=
  rootFrame salt (walk (nodeHash H family) index (H leaf) path).2 statement

def ordinaryRelevant (H : Oracle) (history : History) (family : Family) (index : Nat)
    (leaf : RawInput) (path : List Digest) (salt : Fin 4 → Word)
    (statement : Statement family) : History :=
  leaf :: ordinaryWrapped H family index leaf path salt statement ::
    (ordinaryInputs H family index (H leaf) path ++ history)

theorem ordinary_wrapper_binds_leaf (H : Oracle) (history : History) (family : Family)
    (index : Nat) (prior rebuilt : List Digest) (same : prior.length = rebuilt.length)
    (priorLeaf rebuiltLeaf : RawInput) (priorSalt rebuiltSalt : Fin 4 → Word)
    (priorStatement rebuiltStatement : Statement family)
    (leafRecorded : priorLeaf ∈ history)
    (nodesRecorded : ∀ key ∈ ordinaryInputs H family index (H priorLeaf) prior, key ∈ history)
    (wrapperRecorded : ordinaryWrapped H family index priorLeaf prior priorSalt priorStatement ∈ history)
    (equal : H (ordinaryWrapped H family index priorLeaf prior priorSalt priorStatement) =
      H (ordinaryWrapped H family index rebuiltLeaf rebuilt rebuiltSalt rebuiltStatement))
    (clean : ¬ RelevantCollision H
      (ordinaryRelevant H history family index rebuiltLeaf rebuilt rebuiltSalt rebuiltStatement)) :
    priorLeaf = rebuiltLeaf ∧ priorSalt = rebuiltSalt ∧ priorStatement = rebuiltStatement := by
  apply wrapper_digest_binds_leaf H history family (pairPaths index prior rebuilt same)
    priorLeaf rebuiltLeaf priorSalt rebuiltSalt priorStatement rebuiltStatement leafRecorded
  · simpa only [paired_inputs_eq_ordinary, Bool.false_eq_true, ↓reduceIte] using nodesRecorded
  · simpa only [wrappedPath, paired_root_eq_walk, Bool.false_eq_true, ↓reduceIte,
      ordinaryWrapped] using wrapperRecorded
  · simpa only [wrappedPath, paired_root_eq_walk, Bool.false_eq_true, ↓reduceIte,
      ordinaryWrapped] using equal
  · simpa only [relevantInputs, wrappedPath, paired_root_eq_walk,
      paired_inputs_eq_ordinary, ↓reduceIte, ordinaryRelevant, ordinaryWrapped] using clean

/-- Deterministic instrumentation of the modeled initialized executable run.
The empty default is used only on failure; success theorems eliminate it. -/
def expandedPath (H : Oracle) (family : Family) {count : Nat}
    (openings : Fin count → Opening Digest) (depth : Nat) (selected : Fin count) : List Digest :=
  match reconstruct (nodeHash H family) openings depth with
  | none => []
  | some result => (result.states selected).siblings

theorem accepted_expanded_path (H : Oracle) (family : Family) {count depth : Nat}
    (openings : Fin count → Opening Digest) (selected : Fin count) (root : Digest)
    (accepted : (reconstruct (nodeHash H family) openings depth).map (fun result => result.root) = some root) :
    (expandedPath H family openings depth selected).length = depth ∧
    walk (nodeHash H family) (openings selected).index (openings selected).hash
      (expandedPath H family openings depth selected) = ((openings selected).index / 2 ^ depth, root) := by
  cases execution : reconstruct (nodeHash H family) openings depth with
  | none => simp [execution] at accepted
  | some result =>
      have root_eq : result.root = root := by simpa [execution] using accepted
      have extracted := NativeLaunchCompactMerklePath.successful_extraction
        (nodeHash H family) openings result execution selected
      simpa only [expandedPath, execution, root_eq] using And.intro extracted.1 extracted.2.2.1

/-- Root-only compact execution + exact selected opening + prior ordinary path
at that SAME Nat index. No independently supplied direction alignment or fold
certificate. The finite collision set contains modeled selected reconstructed queries. -/
theorem compact_wrapper_binds_leaf (H : Oracle) (history : History) (family : Family)
    {count depth : Nat} (openings : Fin count → Opening Digest) (selected : Fin count)
    (index : Nat) (root : Digest) (prior : List Digest) (priorLength : prior.length = depth)
    (priorLeaf rebuiltLeaf : RawInput) (priorSalt rebuiltSalt : Fin 4 → Word)
    (priorStatement rebuiltStatement : Statement family)
    (accepted : (reconstruct (nodeHash H family) openings depth).map (fun result => result.root) = some root)
    (selectedIndex : (openings selected).index = index)
    (selectedHash : (openings selected).hash = H rebuiltLeaf)
    (leafRecorded : priorLeaf ∈ history)
    (nodesRecorded : ∀ key ∈ ordinaryInputs H family index (H priorLeaf) prior, key ∈ history)
    (wrapperRecorded : ordinaryWrapped H family index priorLeaf prior priorSalt priorStatement ∈ history)
    (equal : H (ordinaryWrapped H family index priorLeaf prior priorSalt priorStatement) =
      H (rootFrame rebuiltSalt root rebuiltStatement))
    (clean : ¬ RelevantCollision H (ordinaryRelevant H history family index rebuiltLeaf
      (expandedPath H family openings depth selected) rebuiltSalt rebuiltStatement)) :
    priorLeaf = rebuiltLeaf ∧ priorSalt = rebuiltSalt ∧ priorStatement = rebuiltStatement := by
  have extracted := accepted_expanded_path H family openings selected root accepted
  have folded : (walk (nodeHash H family) index (H rebuiltLeaf)
      (expandedPath H family openings depth selected)).2 = root := by
    have h := congrArg Prod.snd extracted.2
    simpa only [selectedIndex, selectedHash] using h
  apply ordinary_wrapper_binds_leaf H history family index prior
    (expandedPath H family openings depth selected) (priorLength.trans extracted.1.symm)
    priorLeaf rebuiltLeaf priorSalt rebuiltSalt priorStatement rebuiltStatement
    leafRecorded nodesRecorded wrapperRecorded
  · simpa only [ordinaryWrapped, folded] using equal
  · exact clean

/-- Native depth23 strict-leaf specialization recovers raw bytes and all fields.
Prior history/path provenance is still an input, not an original-tree theorem. -/
theorem compact_strict_leaf_fields (H : Oracle) (history : History) (family : Family)
    {count : Nat} (openings : Fin count → Opening Digest) (selected : Fin count)
    (root : Digest) (prior : List Digest) (priorLength : prior.length = 23)
    (left right : Statement family) (lf rf : LeafFields)
    (accepted : (reconstruct (nodeHash H family) openings 23).map (fun result => result.root) = some root)
    (selectedIndex : (openings selected).index = rf.index.val)
    (selectedHash : (openings selected).hash = H (strictLeafFrame right rf))
    (leafRecorded : strictLeafFrame left lf ∈ history)
    (nodesRecorded : ∀ key ∈ ordinaryInputs H family rf.index.val (H (strictLeafFrame left lf)) prior, key ∈ history)
    (wrapperRecorded : ordinaryWrapped H family rf.index.val (strictLeafFrame left lf) prior lf.salt left ∈ history)
    (equal : H (ordinaryWrapped H family rf.index.val (strictLeafFrame left lf) prior lf.salt left) =
      H (rootFrame rf.salt root right))
    (clean : ¬ RelevantCollision H (ordinaryRelevant H history family rf.index.val
      (strictLeafFrame right rf) (expandedPath H family openings 23 selected) rf.salt right)) :
    strictLeafFrame left lf = strictLeafFrame right rf ∧
    left = right ∧ lf.index = rf.index ∧ lf.committed = rf.committed ∧
      lf.masks = rf.masks ∧ lf.salt = rf.salt ∧ lf.tape = rf.tape := by
  have raw := (compact_wrapper_binds_leaf H history family openings selected rf.index.val root prior priorLength
    (strictLeafFrame left lf) (strictLeafFrame right rf) lf.salt rf.salt left right
    accepted selectedIndex selectedHash leafRecorded nodesRecorded wrapperRecorded equal clean).1
  exact ⟨raw, raw_leaf_equality_recovers_fields left right lf rf raw⟩

end HegemonCrypto.NativeLaunchCompactMerkleBinding
