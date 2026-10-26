import HegemonCrypto.NativeLaunchRecordedWireReadback
import HegemonCrypto.NativeLaunchRecordedSourceStability

/-! Compact acceptance determines the actual typed wire from an earlier-only
finite oracle graph unless a relevant collision or an ACTUAL completed-readback
change occurs. The context and wrapped-root target are fixed in the comparison.
Earlier/later are list names, not chronology or independence certificates.
No full tree, desired SourceReadback premise, QROM bound or release authority.
Rust refinement, challenge chronology and all eight production gates stay open. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchFrozenRecordedSource
open NativeLaunchAdaptiveHistoryCodec (Family Word RawInput)
open NativeLaunchRelationModelStatement
open NativeLaunchFppHistoryBinding (Digest Oracle History RelevantCollision)
open NativeLaunchMerklePathBinding (rootFrame)
open NativeLaunchCompactMerkleBinding (nodeHash)
open NativeLaunchCompactMerklePath (reconstruct)
open NativeLaunchRecordedMerkleExtraction (Context readback cells masks children)
open NativeLaunchRecordedOracleGraph (oracleGraph toOutput)
open NativeLaunchAuthenticatedReadback (Position wireOpenings)
open NativeLaunchRecordedWireReadback
open NativeLaunchRecordedSourceStability (history_change_has_fresh_insertion)
open SmallWood.V8Smz9CoherentMerkleGeometry (databaseChildren)
open SmallWood
open SmallWood.NativeLaunchRelationModelResponse
local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq
noncomputable section
open Classical

/-- Actual equality failure of the whole completed readback, including status,
raw-key metadata and optional decoded leaf. This is not merely an insertion hit. -/
def ReadbackChanged (H : Oracle) (earlier later : History) {family : Family}
    (context : Context family) (wrappedRoot : Digest) : Prop :=
  ∃ index, readback (oracleGraph H (earlier ++ later)) context (toOutput wrappedRoot) index ≠
    readback (oracleGraph H earlier) context (toOutput wrappedRoot) index

/-- Absence of the actual event forces equality of the canonical data/mask
functions; it is not a caller-supplied desired cell or source equality. -/
theorem recorded_sources_equal_of_no_change (H : Oracle) (earlier later : History)
    {family : Family} (context : Context family) (wrappedRoot : Digest)
    (stable : ¬ ReadbackChanged H earlier later context wrappedRoot) :
    recordedData H (earlier ++ later) context wrappedRoot = recordedData H earlier context wrappedRoot ∧
    recordedMasks H (earlier ++ later) context wrappedRoot = recordedMasks H earlier context wrappedRoot := by
  have same (index : Position) :
      readback (oracleGraph H (earlier ++ later)) context (toOutput wrappedRoot) index =
      readback (oracleGraph H earlier) context (toOutput wrappedRoot) index := by
    by_contra changed
    exact stable ⟨index, changed⟩
  constructor
  · funext column index
    simp only [recordedData, same index]
  · funext row index
    simp only [recordedMasks, same index]

section Wire
variable {branch : Branch} (H : Oracle) (earlier : History)
  (wire : WireFields branch Position) (salt : Fin 4 → Word)
  (tapes : Fin (queryCount branch) → Fin 8 → Word)
  (statement : Statement (NativeLaunchCommitmentReadback.family branch))
  (compact : Fin (queryCount branch) → List Digest) (bareRoot : Digest)

/-- Source functions constructed solely from the earlier records, at the same
fixed context and wrapped-root target used for the final graph. -/
def EarlierSourceReadback : Prop :=
  SourceReadback wire
    (recordedData H earlier (sharedContext (branch := branch) salt statement) (H (rootFrame salt bareRoot statement)))
    (recordedMasks H earlier (sharedContext (branch := branch) salt statement) (H (rootFrame salt bareRoot statement)))

def WireReadbackChanged : Prop :=
  ReadbackChanged H earlier (laterKeys H wire salt tapes statement compact)
    (sharedContext (branch := branch) salt statement) (H (rootFrame salt bareRoot statement))

variable (accepted : (reconstruct (nodeHash H (NativeLaunchCommitmentReadback.family branch))
  (wireOpenings H wire salt tapes statement compact) 23).map (fun result => result.root) = some bareRoot)

include accepted in
/-- Earlier-only whole-wire readback is DERIVED from compact success,
collision exclusion and absence of actual completed-readback change. -/
theorem earlier_source_readback_of_no_change
    (clean : ¬ RelevantCollision H (commonHistory H earlier wire salt tapes statement compact))
    (stable : ¬ WireReadbackChanged H earlier wire salt tapes statement compact bareRoot) :
    EarlierSourceReadback H earlier wire salt statement bareRoot := by
  have recovered := common_wire_source_readback H earlier wire salt tapes statement compact bareRoot accepted clean
  have same := recorded_sources_equal_of_no_change H earlier (laterKeys H wire salt tapes statement compact)
    (sharedContext (branch := branch) salt statement) (H (rootFrame salt bareRoot statement)) stable
  change SourceReadback wire
    (recordedData H (earlier ++ laterKeys H wire salt tapes statement compact)
      (sharedContext (branch := branch) salt statement) (H (rootFrame salt bareRoot statement)))
    (recordedMasks H (earlier ++ laterKeys H wire salt tapes statement compact)
      (sharedContext (branch := branch) salt statement) (H (rootFrame salt bareRoot statement))) at recovered
  rw [same.1, same.2] at recovered
  exact recovered

include accepted in
/-- A deterministic event cover. Its change event is the actual completed
readback difference, not the larger set of all root/child hits. -/
theorem compact_success_event_cover :
    RelevantCollision H (commonHistory H earlier wire salt tapes statement compact) ∨
    WireReadbackChanged H earlier wire salt tapes statement compact bareRoot ∨
    EarlierSourceReadback H earlier wire salt statement bareRoot := by
  by_cases collision : RelevantCollision H (commonHistory H earlier wire salt tapes statement compact)
  · exact Or.inl collision
  by_cases changed : WireReadbackChanged H earlier wire salt tapes statement compact bareRoot
  · exact Or.inr (Or.inl changed)
  exact Or.inr (Or.inr (earlier_source_readback_of_no_change H earlier wire salt tapes statement compact
    bareRoot accepted collision changed))

include accepted in
theorem failed_earlier_source_event_cover
    (failed : ¬ EarlierSourceReadback H earlier wire salt statement bareRoot) :
    RelevantCollision H (commonHistory H earlier wire salt tapes statement compact) ∨
    WireReadbackChanged H earlier wire salt tapes statement compact bareRoot := by
  rcases compact_success_event_cover H earlier wire salt tapes statement compact bareRoot accepted with
    collision | changed | recovered
  · exact Or.inl collision
  · exact Or.inr changed
  · exact False.elim (failed recovered)

/-- The actual event has a concrete fresh insertion witness. Freshness excludes
duplicate-key insertions; the hit is at the fixed target or a parsed child of
the graph immediately before insertion. No chronological randomness is claimed. -/
theorem actual_change_has_fresh_hit
    (changed : WireReadbackChanged H earlier wire salt tapes statement compact bareRoot) :
    ∃ before key after, laterKeys H wire salt tapes statement compact = before ++ key :: after ∧
      key ∉ earlier ++ before ∧
      toOutput (H key) ∈ {toOutput (H (rootFrame salt bareRoot statement))} ∪
        databaseChildren (children (NativeLaunchCommitmentReadback.family branch))
          (oracleGraph H (earlier ++ before)) := by
  exact history_change_has_fresh_insertion H earlier (laterKeys H wire salt tapes statement compact)
    (sharedContext (branch := branch) salt statement) (toOutput (H (rootFrame salt bareRoot statement))) changed

end Wire
end
end HegemonCrypto.NativeLaunchFrozenRecordedSource
