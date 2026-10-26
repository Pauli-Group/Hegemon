import HegemonCrypto.NativeLaunchOriginalMerkleTree
import HegemonCrypto.NativeLaunchCompactMerkleBinding
import HegemonCrypto.NativeLaunchCommitmentResponseBinding

/-!
Conditional authenticated readback from a selected general canonical source
TREE. No honest polynomial origin or degree restriction is assumed. Openings
are calculated from wire fields; successful modeled compact reconstruction and
literal wrapped-digest equality bind them to the selected tree, unless a finite
relevant collision occurs. Existence/selection of such an original tree for an
adversarial real execution, history chronology, Rust refinement and QROM bounds
remain external. Calculated query membership is not an execution record.
-/
set_option autoImplicit false
namespace HegemonCrypto.NativeLaunchAuthenticatedReadback
open NativeLaunchAdaptiveHistoryCodec (Family Word RawInput)
open NativeLaunchRelationModelStatement
open NativeLaunchFppHistoryBinding (Digest Oracle History RelevantCollision)
open NativeLaunchMerklePathBinding
open NativeLaunchCompactMerkleBinding
open NativeLaunchCompactMerklePath (Opening walk parent reconstruct)
open NativeLaunchOriginalMerkleTree
open NativeLaunchCommitmentResponseBinding (canonicalField interpretField canonical_field_roundtrip)
open SmallWood
open SmallWood.NativeLaunchRelationModelResponse
noncomputable section

/-- The ordinary walk and calculated tree use exactly the same arithmetic. -/
theorem ordinary_root (H : Oracle) (family : Family) (depth : Nat) (level : Level)
    (index : Nat) (bound : index < 2^depth) :
    (walk (nodeHash H family) index (level index) (siblings H family depth level index)).2 =
      root H family depth level := by
  induction depth generalizing level index with
  | zero =>
      have zero : index = 0 := by simpa using bound
      subst index
      rfl
  | succ depth ih =>
      have next : parent (nodeHash H family) index (level index) (sibling level index) =
          reduce H family level (index / 2) := by
        have h := congrArg H (calculated_node family level index)
        by_cases parity : index % 2 = 0 <;>
          simpa [parent, nodeHash, nodeInput, route, parity, reduce] using h
      simp only [siblings, walk, next, root]
      exact ih (reduce H family level) (index / 2) (half_bound bound)

theorem ordinary_inputs (H : Oracle) (family : Family) (depth : Nat) (level : Level)
    (index : Nat) :
    ordinaryInputs H family index (level index) (siblings H family depth level index) =
      pathInputs H family false (path H family depth level index) (level index) := by
  induction depth generalizing level index with
  | zero => rfl
  | succ depth ih =>
      have key : (if index % 2 = 0 then nodeFrame family (level index) (sibling level index)
          else nodeFrame family (sibling level index) (level index)) =
          nodeInput family (route index) (level index) (sibling level index) := by
        by_cases parity : index % 2 = 0 <;> simp [nodeInput, route, parity]
      simp only [siblings, ordinaryInputs, path, pathInputs, Bool.false_eq_true, ↓reduceIte, key]
      rw [calculated_node]
      congr 1
      exact ih (reduce H family level) (index / 2)

abbrev Position := Fin (2^23)

def wireLeaf {branch : Branch} (wire : WireFields branch Position) (salt : Fin 4 → Word)
    (tapes : Fin (queryCount branch) → Fin 8 → Word) (selected : Fin (queryCount branch)) : LeafFields :=
  ⟨salt, wire.positions selected, tapes selected,
    (fun column => canonicalField (wire.sourceCells selected column)),
    (fun row => canonicalField (wire.maskingEvals selected row))⟩

/-- Selected index and leaf hash are definitions, never alignment premises. -/
def wireOpenings {branch : Branch} (H : Oracle) (wire : WireFields branch Position)
    (salt : Fin 4 → Word) (tapes : Fin (queryCount branch) → Fin 8 → Word)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (compact : Fin (queryCount branch) → List Digest) : Fin (queryCount branch) → Opening Digest :=
  fun selected => ⟨(wire.positions selected).val,
    H (strictLeafFrame statement (wireLeaf wire salt tapes selected)), compact selected⟩

def sourceData {family : Family} (source : NativeLeaves family) (column : Nat) (index : Position) : Goldilocks :=
  if bound : column < 140 then interpretField (source.cells index ⟨column, bound⟩) else 0

def sourceMasks {family : Family} (source : NativeLeaves family) (row : MaskRow) (index : Position) : Goldilocks :=
  interpretField (source.masks index row)

/-- Finite list per selected opening: calculated original tree queries plus
that opening's modeled reconstructed leaf/node/wrapper queries. No chronology. -/
def readbackInputs {branch : Branch} (H : Oracle)
    (source : NativeLeaves (NativeLaunchCommitmentReadback.family branch))
    (wire : WireFields branch Position) (salt : Fin 4 → Word)
    (tapes : Fin (queryCount branch) → Fin 8 → Word)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (compact : Fin (queryCount branch) → List Digest) (selected : Fin (queryCount branch)) : History :=
  ordinaryRelevant H (queries H 23 (nativeLeaves source) source.salt source.statement)
    (NativeLaunchCommitmentReadback.family branch) (wire.positions selected).val
    (strictLeafFrame statement (wireLeaf wire salt tapes selected))
    (expandedPath H (NativeLaunchCommitmentReadback.family branch)
      (wireOpenings H wire salt tapes statement compact) 23 selected) salt statement

/-- Every original path/history premise is discharged from the calculated tree.
The only acceptance input is root-mapped reconstruction of wire-derived openings. -/
theorem authenticated_leaf_fields {branch : Branch} (H : Oracle)
    (source : NativeLeaves (NativeLaunchCommitmentReadback.family branch))
    (wire : WireFields branch Position) (salt : Fin 4 → Word)
    (tapes : Fin (queryCount branch) → Fin 8 → Word)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (compact : Fin (queryCount branch) → List Digest) (rebuiltRoot : Digest)
    (accepted : (reconstruct (nodeHash H (NativeLaunchCommitmentReadback.family branch))
      (wireOpenings H wire salt tapes statement compact) 23).map (fun result => result.root) = some rebuiltRoot)
    (equal : H (wrapper H 23 (nativeLeaves source) source.salt source.statement) =
      H (rootFrame salt rebuiltRoot statement))
    (selected : Fin (queryCount branch))
    (clean : ¬ RelevantCollision H (readbackInputs H source wire salt tapes statement compact selected)) :
    (nativeFields source (wire.positions selected)).committed = (wireLeaf wire salt tapes selected).committed ∧
    (nativeFields source (wire.positions selected)).masks = (wireLeaf wire salt tapes selected).masks := by
  let family := NativeLaunchCommitmentReadback.family branch
  let leaves := nativeLeaves source
  let index := wire.positions selected
  let level := leafLevel H leaves
  let prior := siblings H family 23 level index.val
  let history := queries H 23 leaves source.salt source.statement
  have raw : leaves index.val = strictLeafFrame source.statement (nativeFields source index) :=
    native_leaf_at source index
  have wrapped : ordinaryWrapped H family index.val
      (strictLeafFrame source.statement (nativeFields source index)) prior source.salt source.statement =
      wrapper H 23 leaves source.salt source.statement := by
    rw [← raw]
    unfold ordinaryWrapped
    rw [show H (leaves index.val) = level index.val from rfl]
    rw [ordinary_root H family 23 level index.val index.isLt]
    rfl
  have bound := compact_strict_leaf_fields H history family
    (wireOpenings H wire salt tapes statement compact) selected rebuiltRoot prior
    (siblings_length H family 23 level index.val)
    source.statement statement (nativeFields source index) (wireLeaf wire salt tapes selected)
    accepted rfl rfl
    (by rw [← raw]; exact leaf_recorded H 23 leaves source.salt source.statement index.val index.isLt)
    (by
      intro key member
      rw [← raw] at member
      have converted : key ∈ pathInputs H family false (path H family 23 level index.val) (level index.val) := by
        rw [← ordinary_inputs]
        exact member
      exact nodes_recorded H 23 leaves source.salt source.statement index.val index.isLt false key converted)
    (by
      change ordinaryWrapped H family index.val (strictLeafFrame source.statement (nativeFields source index))
        prior source.salt source.statement ∈ history
      rw [wrapped]
      simp [history, queries])
    (by
      change H (ordinaryWrapped H family index.val
        (strictLeafFrame source.statement (nativeFields source index)) prior source.salt source.statement) =
        H (rootFrame salt rebuiltRoot statement)
      rw [wrapped]
      exact equal)
    clean
  exact ⟨bound.2.2.2.1, bound.2.2.2.2.1⟩

/-- SourceReadback derived without assumed cell equality, independent index/hash
alignment, supplied proof-bearing compact states, or honest polynomial origin. -/
theorem authenticated_source_readback {branch : Branch} (H : Oracle)
    (source : NativeLeaves (NativeLaunchCommitmentReadback.family branch))
    (wire : WireFields branch Position) (salt : Fin 4 → Word)
    (tapes : Fin (queryCount branch) → Fin 8 → Word)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (compact : Fin (queryCount branch) → List Digest) (rebuiltRoot : Digest)
    (accepted : (reconstruct (nodeHash H (NativeLaunchCommitmentReadback.family branch))
      (wireOpenings H wire salt tapes statement compact) 23).map (fun result => result.root) = some rebuiltRoot)
    (equal : H (wrapper H 23 (nativeLeaves source) source.salt source.statement) =
      H (rootFrame salt rebuiltRoot statement))
    (clean : ∀ selected, ¬ RelevantCollision H (readbackInputs H source wire salt tapes statement compact selected)) :
    SourceReadback wire (sourceData source) (sourceMasks source) := by
  constructor
  · intro selected column
    have fields := (authenticated_leaf_fields H source wire salt tapes statement compact rebuiltRoot
      accepted equal selected (clean selected)).1
    have cell := congrArg (fun values => interpretField (values column)) fields
    simpa [nativeFields, wireLeaf, canonical_field_roundtrip, sourceData] using cell.symm
  · intro selected row
    have fields := (authenticated_leaf_fields H source wire salt tapes statement compact rebuiltRoot
      accepted equal selected (clean selected)).2
    have cell := congrArg (fun values => interpretField (values row)) fields
    simpa [nativeFields, wireLeaf, canonical_field_roundtrip, sourceMasks] using cell.symm

end
end HegemonCrypto.NativeLaunchAuthenticatedReadback
