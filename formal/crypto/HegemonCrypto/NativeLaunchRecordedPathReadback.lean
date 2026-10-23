import HegemonCrypto.NativeLaunchRecordedOracleGraph
import HegemonCrypto.NativeLaunchCompactMerkleBinding

/-!
Recorded extraction of the leaf at a calculated ordinary/compact verifier path.
All record selections follow from valid literal query membership and finite
collision exclusion. No complete original tree, selected-key equality premise,
source-cell equality, independent direction alignment or global injectivity.
The augmented graph includes modeled verifier queries; its relationship to a
prechallenge real execution and extraction-change probability remains open.
-/
set_option autoImplicit false
set_option maxRecDepth 5000
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchRecordedPathReadback
open NativeLaunchAdaptiveHistoryCodec (Family Word RawInput)
open NativeLaunchRelationModelStatement
open NativeLaunchLeafReadback
open NativeLaunchFppHistoryBinding (Digest Oracle History RelevantCollision)
open NativeLaunchMerklePathBinding (nodeFrame rootFrame saltBytes)
open NativeLaunchCompactMerkleBinding
open NativeLaunchCompactMerklePath (Opening walk parent reconstruct walk_append walk_index)
open NativeLaunchRecordedMerkleExtraction
open NativeLaunchRecordedOracleGraph
open SmallWood.V8Smz9CoherentMerkleGeometry (extract)
local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq
noncomputable section
open Classical

/-- Output metadata and full decoded leaf, excluding only the retained raw-key list. -/
def view (result : Readback) := (result.status, result.leaf)

def context {family : Family} (statement : Statement family) (fields : LeafFields) : Context family :=
  ⟨fields.salt, statement⟩

def parentInput (family : Family) (index : Nat) (current sibling : Digest) : RawInput :=
  if index % 2 = 0 then nodeFrame family current sibling else nodeFrame family sibling current

def pathRoot (H : Oracle) (family : Family) (index : Nat) (leaf : Digest) (path : List Digest) : Digest :=
  (walk (nodeHash H family) index leaf path).2

theorem ordinary_inputs_append (H : Oracle) (family : Family) (path tail : List Digest)
    (index : Nat) (leaf : Digest) :
    ordinaryInputs H family index leaf (path ++ tail) =
      ordinaryInputs H family index leaf path ++
        ordinaryInputs H family (walk (nodeHash H family) index leaf path).1
          (walk (nodeHash H family) index leaf path).2 tail := by
  induction path generalizing index leaf with
  | nil => rfl
  | cons sibling rest ih =>
      simp only [List.cons_append, ordinaryInputs, List.cons_append, walk]
      rw [ih]
      by_cases parity : index % 2 = 0 <;> simp [parent, nodeHash, parity]

theorem path_root_append (H : Oracle) (family : Family) (index : Nat) (leaf : Digest)
    (path : List Digest) (sibling : Digest) :
    pathRoot H family index leaf (path ++ [sibling]) =
      H (parentInput family (index / 2^path.length) (pathRoot H family index leaf path) sibling) := by
  simp only [pathRoot, walk_append, walk, walk_index, parent, nodeHash, parentInput]
  split <;> rfl

theorem next_parent {family : Family} (ctx : Context family) (depth : Nat) (index : Position)
    (current sibling : Digest) :
    next family (.tree ctx (depth+1) index)
      (parentInput family (index.val / 2^depth) current sibling) =
      some [(.tree ctx depth index, toOutput current)] := by
  by_cases parity : (index.val / 2^depth) % 2 = 0 <;>
    simp [parentInput, parity, next, parse_node_frame, parsedNext]

theorem parent_extract_view (H : Oracle) (history : History) {family : Family}
    (ctx : Context family) (depth fuel : Nat) (index : Position) (current sibling : Digest)
    (recorded : parentInput family (index.val / 2^depth) current sibling ∈ history)
    (clean : ¬ RelevantCollision H history) :
    view (finish ctx index (extract (next family) (oracleGraph H history) (fuel+2)
      (.tree ctx (depth+1) index)
      (toOutput (H (parentInput family (index.val / 2^depth) current sibling))))) =
    view (finish ctx index (extract (next family) (oracleGraph H history) (fuel+1)
      (.tree ctx depth index) (toOutput current))) := by
  have parsed := next_parent ctx depth index current sibling
  have selected := selected_valid_key H history family (.tree ctx (depth+1) index)
    (parentInput family (index.val / 2^depth) current sibling) recorded (congrArg Option.isSome parsed) clean
  simp only [extract, selected, parsed, List.map_cons, List.map_nil, finish, view]

theorem leaf_context_matches {family : Family} (statement : Statement family) (fields : LeafFields) :
    leafMatches (context statement fields) fields.index (decodedFields (statementBytes statement) fields) :=
  ⟨rfl, rfl, rfl⟩

theorem next_leaf {family : Family} (statement : Statement family) (fields : LeafFields) :
    next family (.tree (context statement fields) 0 fields.index) (strictLeafFrame statement fields) = some [] := by
  unfold next
  rw [parse_leaf_frame]
  change (if leafMatches (context statement fields) fields.index
    (decodedFields (statementBytes statement) fields) then some [] else none) = some []
  exact if_pos (leaf_context_matches statement fields)

/-- Normalized terminal calculation, isolated from list induction. -/
theorem terminal_view (H : Oracle) (history : History) {family : Family}
    (statement : Statement family) (fields : LeafFields)
    (recorded : strictLeafFrame statement fields ∈ history)
    (clean : ¬ RelevantCollision H history) :
    view (finish (context statement fields) fields.index
      (extract (next family) (oracleGraph H history) 1
        (.tree (context statement fields) 0 fields.index)
        (toOutput (H (strictLeafFrame statement fields))))) =
      (.complete, some (decodedFields (statementBytes statement) fields)) := by
  have contextOk := leaf_context_matches statement fields
  have parsed := next_leaf statement fields
  have selected := selected_valid_key H history family (.tree (context statement fields) 0 fields.index)
    (strictLeafFrame statement fields) recorded (congrArg Option.isSome parsed) clean
  simp only [extract, selected, parsed, List.map_nil, finish, parse_leaf_frame, if_pos contextOk, view]

/-- Bottom-up path induction is reversed to match top-down extraction. The
quotient invariant computes every direction from the original leaf index. -/
theorem tree_path_readback (H : Oracle) (history : History) {family : Family}
    (statement : Statement family) (fields : LeafFields) (path : List Digest)
    (leafRecorded : strictLeafFrame statement fields ∈ history)
    (nodesRecorded : ∀ key ∈ ordinaryInputs H family fields.index.val
      (H (strictLeafFrame statement fields)) path, key ∈ history)
    (clean : ¬ RelevantCollision H history) :
    view (finish (context statement fields) fields.index
      (extract (next family) (oracleGraph H history) (path.length+1)
        (.tree (context statement fields) path.length fields.index)
        (toOutput (pathRoot H family fields.index.val (H (strictLeafFrame statement fields)) path)))) =
      (.complete, some (decodedFields (statementBytes statement) fields)) := by
  revert nodesRecorded
  induction path using List.reverseRecOn with
  | nil =>
      intro _
      exact terminal_view H history statement fields leafRecorded clean
  | append_singleton path sibling ih =>
      intro nodesRecorded
      have priorRecorded : ∀ key ∈ ordinaryInputs H family fields.index.val
          (H (strictLeafFrame statement fields)) path, key ∈ history := by
        intro key member
        apply nodesRecorded key
        rw [ordinary_inputs_append]
        exact List.mem_append_left _ member
      have lastRecorded : parentInput family (fields.index.val / 2^path.length)
          (pathRoot H family fields.index.val (H (strictLeafFrame statement fields)) path) sibling ∈ history := by
        apply nodesRecorded
        rw [ordinary_inputs_append, walk_index]
        change parentInput family (fields.index.val / 2^path.length)
          (pathRoot H family fields.index.val (H (strictLeafFrame statement fields)) path) sibling ∈
          ordinaryInputs H family fields.index.val (H (strictLeafFrame statement fields)) path ++
            [parentInput family (fields.index.val / 2^path.length)
              (pathRoot H family fields.index.val (H (strictLeafFrame statement fields)) path) sibling]
        exact List.mem_append_right _ (List.mem_cons_self)
      simp only [List.length_append, List.length_singleton, path_root_append]
      rw [parent_extract_view H history (context statement fields) path.length path.length
        fields.index _ sibling lastRecorded clean]
      exact ih priorRecorded

/-- Exact verifier-query augmentation, with all literal leaf/node/wrapper keys. -/
def augmented (H : Oracle) (history : History) {family : Family}
    (statement : Statement family) (fields : LeafFields) (path : List Digest) : History :=
  strictLeafFrame statement fields ::
    ordinaryWrapped H family fields.index.val (strictLeafFrame statement fields) path fields.salt statement ::
      (ordinaryInputs H family fields.index.val (H (strictLeafFrame statement fields)) path ++ history)

theorem wrapper_extract_view (H : Oracle) (history : History) {family : Family}
    (ctx : Context family) (index : Position) (bare : Digest) (fuel : Nat)
    (recorded : rootFrame ctx.salt bare ctx.statement ∈ history)
    (clean : ¬ RelevantCollision H history) :
    view (finish ctx index (extract (next family) (oracleGraph H history) (fuel+2)
      (.wrapped ctx index) (toOutput (H (rootFrame ctx.salt bare ctx.statement))))) =
    view (finish ctx index (extract (next family) (oracleGraph H history) (fuel+1)
      (.tree ctx 23 index) (toOutput bare))) := by
  have parsed : next family (.wrapped ctx index) (rootFrame ctx.salt bare ctx.statement) =
      some [(.tree ctx 23 index, toOutput bare)] := by
    simp [next, parse_root_frame, parsedNext]
  have selected := selected_valid_key H history family (.wrapped ctx index)
    (rootFrame ctx.salt bare ctx.statement) recorded (congrArg Option.isSome parsed) clean
  rw [extract, selected]
  dsimp only
  rw [parsed]
  rfl

theorem ordinary_readback_of_recorded (H : Oracle) (history : History) {family : Family}
    (statement : Statement family) (fields : LeafFields) (path : List Digest)
    (length : path.length = 23)
    (leafRecorded : strictLeafFrame statement fields ∈ history)
    (nodesRecorded : ∀ key ∈ ordinaryInputs H family fields.index.val
      (H (strictLeafFrame statement fields)) path, key ∈ history)
    (wrapperRecorded : ordinaryWrapped H family fields.index.val (strictLeafFrame statement fields)
      path fields.salt statement ∈ history)
    (clean : ¬ RelevantCollision H history) :
    view (readback (oracleGraph H history) (context statement fields)
      (toOutput (H (ordinaryWrapped H family fields.index.val (strictLeafFrame statement fields)
        path fields.salt statement))) fields.index) =
      (.complete, some (decodedFields (statementBytes statement) fields)) := by
  let bare := pathRoot H family fields.index.val (H (strictLeafFrame statement fields)) path
  change view (finish (context statement fields) fields.index
    (extract (next family) (oracleGraph H history) (23+2) (.wrapped (context statement fields) fields.index)
      (toOutput (H (rootFrame (context statement fields).salt bare (context statement fields).statement))))) = _
  rw [wrapper_extract_view H history (context statement fields) fields.index bare 23 wrapperRecorded clean]
  have tree := tree_path_readback H history statement fields path leafRecorded nodesRecorded clean
  simpa only [length] using tree

theorem ordinary_readback (H : Oracle) (history : History) {family : Family}
    (statement : Statement family) (fields : LeafFields) (path : List Digest)
    (length : path.length = 23)
    (clean : ¬ RelevantCollision H (augmented H history statement fields path)) :
    view (readback (oracleGraph H (augmented H history statement fields path)) (context statement fields)
      (toOutput (H (ordinaryWrapped H family fields.index.val (strictLeafFrame statement fields)
        path fields.salt statement))) fields.index) =
      (.complete, some (decodedFields (statementBytes statement) fields)) := by
  apply ordinary_readback_of_recorded H (augmented H history statement fields path) statement fields path length
  · exact List.mem_cons_self
  · intro key member
    exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_append_left _ member))
  · exact List.mem_cons_of_mem _ List.mem_cons_self
  · exact clean

/-- Indices and hashes are constructed from the selected literal strict leaf. -/
def openings (H : Oracle) {family : Family} {count : Nat} (statement : Statement family)
    (fields : Fin count → LeafFields) (compact : Fin count → List Digest) : Fin count → Opening Digest :=
  fun index => ⟨(fields index).index.val, H (strictLeafFrame statement (fields index)), compact index⟩

/-- Initialized compact success supplies the path and length; no external fold
certificate, direction alignment or complete canonical source tree is given. -/
theorem compact_readback (H : Oracle) (history : History) {family : Family} {count : Nat}
    (statement : Statement family) (fields : Fin count → LeafFields) (compact : Fin count → List Digest)
    (root : Digest) (selected : Fin count)
    (accepted : (reconstruct (nodeHash H family) (openings H statement fields compact) 23).map
      (fun result => result.root) = some root)
    (clean : ¬ RelevantCollision H (augmented H history statement (fields selected)
      (expandedPath H family (openings H statement fields compact) 23 selected))) :
    view (readback (oracleGraph H (augmented H history statement (fields selected)
      (expandedPath H family (openings H statement fields compact) 23 selected)))
      (context statement (fields selected)) (toOutput (H (rootFrame (fields selected).salt root statement)))
      (fields selected).index) =
      (.complete, some (decodedFields (statementBytes statement) (fields selected))) := by
  have extracted := accepted_expanded_path H family (openings H statement fields compact) selected root accepted
  have result := ordinary_readback H history statement (fields selected)
    (expandedPath H family (openings H statement fields compact) 23 selected) extracted.1 clean
  have folded : (walk (nodeHash H family) (fields selected).index.val
      (H (strictLeafFrame statement (fields selected)))
      (expandedPath H family (openings H statement fields compact) 23 selected)).2 = root :=
    congrArg Prod.snd extracted.2
  have wrapped : ordinaryWrapped H family (fields selected).index.val
      (strictLeafFrame statement (fields selected))
      (expandedPath H family (openings H statement fields compact) 23 selected)
      (fields selected).salt statement = rootFrame (fields selected).salt root statement :=
    congrArg (fun value => rootFrame (fields selected).salt value statement) folded
  simpa only [wrapped] using result

/-- Full decoded recovery entails every canonical data and masking cell. -/
theorem recovered_projections (result : Readback) {family : Family}
    (statement : Statement family) (fields : LeafFields)
    (recovered : view result = (.complete, some (decodedFields (statementBytes statement) fields))) :
    result.status = .complete ∧
    (∀ column, cells result column = fields.committed column) ∧
    (∀ row, masks result row = fields.masks row) := by
  have status := congrArg Prod.fst recovered
  have leaf := congrArg Prod.snd recovered
  refine ⟨status, ?_, ?_⟩
  · intro column
    simp only [cells, show result.leaf = some (decodedFields (statementBytes statement) fields) from leaf]
    exact committed_projection _ _ _
  · intro row
    simp only [masks, show result.leaf = some (decodedFields (statementBytes statement) fields) from leaf]
    exact masking_projection _ _ _

end
end HegemonCrypto.NativeLaunchRecordedPathReadback
