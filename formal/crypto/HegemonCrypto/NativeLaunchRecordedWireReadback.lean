import HegemonCrypto.NativeLaunchRecordedPathReadback
import HegemonCrypto.NativeLaunchAuthenticatedReadback

/-! Whole-wire readback from ONE common finite oracle graph, for ONE salt,
full statement and wrapped-root target. All leaf/node/wrapper memberships are
constructed from the modeled compact execution. No original tree, desired
cell equality, separate index/hash alignment or readback premise is supplied.
The union list is not the Rust level-major query log or a prechallenge record.
Rust refinement, chronology, QROM and all eight production gates remain open. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchRecordedWireReadback
open NativeLaunchAdaptiveHistoryCodec (Family Word RawInput)
open NativeLaunchRelationModelStatement
open NativeLaunchFppHistoryBinding (Digest Oracle History RelevantCollision)
open NativeLaunchMerklePathBinding (rootFrame)
open NativeLaunchCompactMerkleBinding (nodeHash expandedPath accepted_expanded_path ordinaryInputs ordinaryWrapped)
open NativeLaunchCompactMerklePath (reconstruct walk)
open NativeLaunchRecordedMerkleExtraction (Database Context Output readback cells masks)
open NativeLaunchRecordedOracleGraph (oracleGraph toOutput)
open NativeLaunchRecordedPathReadback (view ordinary_readback_of_recorded recovered_projections)
open NativeLaunchAuthenticatedReadback (Position wireLeaf wireOpenings)
open NativeLaunchCommitmentResponseBinding (canonicalField interpretField canonical_field_roundtrip)
open SmallWood
open SmallWood.NativeLaunchRelationModelResponse
local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq
noncomputable section
open Classical

def sharedContext {branch : Branch} (salt : Fin 4 → Word)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch)) :
    Context (NativeLaunchCommitmentReadback.family branch) := ⟨salt, statement⟩

/-- Calculated keys for one selected opening; their placement here asserts
membership only, not execution ordering. -/
def openingKeys {branch : Branch} (H : Oracle) (wire : WireFields branch Position)
    (salt : Fin 4 → Word) (tapes : Fin (queryCount branch) → Fin 8 → Word)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (compact : Fin (queryCount branch) → List Digest) (selected : Fin (queryCount branch)) : History :=
  let family : Family := NativeLaunchCommitmentReadback.family branch
  let leaf := strictLeafFrame statement (wireLeaf wire salt tapes selected)
  let path : List Digest := expandedPath H family (wireOpenings H wire salt tapes statement compact) 23 selected
  leaf :: (ordinaryInputs H family (wire.positions selected).val (H leaf) path ++
    [ordinaryWrapped H family (wire.positions selected).val leaf path salt statement])

def laterKeys {branch : Branch} (H : Oracle) (wire : WireFields branch Position)
    (salt : Fin 4 → Word) (tapes : Fin (queryCount branch) → Fin 8 → Word)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (compact : Fin (queryCount branch) → List Digest) : History :=
  (List.ofFn (openingKeys H wire salt tapes statement compact)).flatten

def commonHistory {branch : Branch} (H : Oracle) (earlier : History) (wire : WireFields branch Position)
    (salt : Fin 4 → Word) (tapes : Fin (queryCount branch) → Fin 8 → Word)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (compact : Fin (queryCount branch) → List Digest) : History :=
  earlier ++ laterKeys H wire salt tapes statement compact

theorem opening_key_recorded {branch : Branch} (H : Oracle) (earlier : History)
    (wire : WireFields branch Position) (salt : Fin 4 → Word)
    (tapes : Fin (queryCount branch) → Fin 8 → Word)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (compact : Fin (queryCount branch) → List Digest) (selected : Fin (queryCount branch))
    (key : RawInput) (member : key ∈ openingKeys H wire salt tapes statement compact selected) :
    key ∈ commonHistory H earlier wire salt tapes statement compact := by
  apply List.mem_append_right
  apply List.mem_flatten.mpr
  exact ⟨openingKeys H wire salt tapes statement compact selected,
    List.mem_ofFn.mpr ⟨selected, rfl⟩, member⟩

/-- The SAME graph and context recover every selected decoded leaf. -/
theorem common_leaf_readback {branch : Branch} (H : Oracle) (earlier : History)
    (wire : WireFields branch Position) (salt : Fin 4 → Word)
    (tapes : Fin (queryCount branch) → Fin 8 → Word)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (compact : Fin (queryCount branch) → List Digest) (bareRoot : Digest)
    (accepted : (reconstruct (nodeHash H (NativeLaunchCommitmentReadback.family branch))
      (wireOpenings H wire salt tapes statement compact) 23).map (fun result => result.root) = some bareRoot)
    (clean : ¬ RelevantCollision H (commonHistory H earlier wire salt tapes statement compact))
    (selected : Fin (queryCount branch)) :
    view (readback (oracleGraph H (commonHistory H earlier wire salt tapes statement compact))
      (sharedContext (branch := branch) salt statement) (toOutput (H (rootFrame salt bareRoot statement))) (wire.positions selected)) =
      (.complete, some (NativeLaunchLeafReadback.decodedFields (statementBytes statement)
        (wireLeaf wire salt tapes selected))) := by
  let family : Family := NativeLaunchCommitmentReadback.family branch
  let path : List Digest := expandedPath H family (wireOpenings H wire salt tapes statement compact) 23 selected
  let fields : LeafFields := wireLeaf wire salt tapes selected
  let history : History := commonHistory H earlier wire salt tapes statement compact
  have extracted := accepted_expanded_path H family (wireOpenings H wire salt tapes statement compact)
    selected bareRoot accepted
  have leafRecorded : strictLeafFrame statement fields ∈ history := by
    apply opening_key_recorded H earlier wire salt tapes statement compact selected
    exact List.mem_cons_self
  have nodesRecorded : ∀ key ∈ ordinaryInputs H family fields.index.val
      (H (strictLeafFrame statement fields)) path, key ∈ history := by
    intro key member
    apply opening_key_recorded H earlier wire salt tapes statement compact selected
    exact List.mem_cons_of_mem _ (List.mem_append_left _ member)
  have wrapperRecorded : ordinaryWrapped H family fields.index.val
      (strictLeafFrame statement fields) path fields.salt statement ∈ history := by
    apply opening_key_recorded H earlier wire salt tapes statement compact selected
    exact List.mem_cons_of_mem _ (List.mem_append_right _ List.mem_cons_self)
  have recovered := ordinary_readback_of_recorded H history statement fields path extracted.1
    leafRecorded nodesRecorded wrapperRecorded clean
  have folded : (walk (nodeHash H family) fields.index.val
      (H (strictLeafFrame statement fields)) path).2 = bareRoot :=
    congrArg Prod.snd extracted.2
  have wrapped : ordinaryWrapped H family fields.index.val
      (strictLeafFrame statement fields) path fields.salt statement = rootFrame salt bareRoot statement :=
    congrArg (fun value => rootFrame salt value statement) folded
  rw [wrapped] at recovered
  exact recovered

def recordedData {family : NativeLaunchAdaptiveHistoryCodec.Family} (H : Oracle) (history : History)
    (context : Context family) (wrappedRoot : Digest) (column : Nat) (index : Position) : Goldilocks :=
  if bound : column < 140 then
    interpretField (cells (readback (oracleGraph H history) context (toOutput wrappedRoot) index) ⟨column, bound⟩)
  else 0

def recordedMasks {family : NativeLaunchAdaptiveHistoryCodec.Family} (H : Oracle) (history : History)
    (context : Context family) (wrappedRoot : Digest) (row : MaskRow) (index : Position) : Goldilocks :=
  interpretField (masks (readback (oracleGraph H history) context (toOutput wrappedRoot) index) row)

/-- Complete SourceReadback for the actual typed wire follows from compact
success and finite collision exclusion on one constructed common history.
No source tree or supplied readback equation is used. -/
theorem common_wire_source_readback {branch : Branch} (H : Oracle) (earlier : History)
    (wire : WireFields branch Position) (salt : Fin 4 → Word)
    (tapes : Fin (queryCount branch) → Fin 8 → Word)
    (statement : Statement (NativeLaunchCommitmentReadback.family branch))
    (compact : Fin (queryCount branch) → List Digest) (bareRoot : Digest)
    (accepted : (reconstruct (nodeHash H (NativeLaunchCommitmentReadback.family branch))
      (wireOpenings H wire salt tapes statement compact) 23).map (fun result => result.root) = some bareRoot)
    (clean : ¬ RelevantCollision H (commonHistory H earlier wire salt tapes statement compact)) :
    SourceReadback wire
      (recordedData H (commonHistory H earlier wire salt tapes statement compact)
        (sharedContext (branch := branch) salt statement) (H (rootFrame salt bareRoot statement)))
      (recordedMasks H (commonHistory H earlier wire salt tapes statement compact)
        (sharedContext (branch := branch) salt statement) (H (rootFrame salt bareRoot statement))) := by
  constructor
  · intro selected column
    have recovered := common_leaf_readback H earlier wire salt tapes statement compact bareRoot accepted clean selected
    have projections := recovered_projections _ statement (wireLeaf wire salt tapes selected) recovered
    have cell := congrArg interpretField (projections.2.1 column)
    simpa [recordedData, wireLeaf, canonical_field_roundtrip] using cell.symm
  · intro selected row
    have recovered := common_leaf_readback H earlier wire salt tapes statement compact bareRoot accepted clean selected
    have projections := recovered_projections _ statement (wireLeaf wire salt tapes selected) recovered
    have cell := congrArg interpretField (projections.2.2 row)
    simpa [recordedMasks, wireLeaf, canonical_field_roundtrip] using cell.symm

end
end HegemonCrypto.NativeLaunchRecordedWireReadback
