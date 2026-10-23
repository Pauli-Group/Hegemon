import HegemonCrypto.NativeLaunchRecordedOracleGraph

/-! Deterministic finite insertion stability at a FIXED context and wrapped
root target. Lists named earlier/later carry no chronological or independence
certificate. No accepted execution, desired source readback, collision exclusion,
polynomial origin, random-output assumption or QROM bound is used. -/
set_option autoImplicit false
namespace HegemonCrypto.NativeLaunchRecordedSourceStability
open NativeLaunchAdaptiveHistoryCodec (Family RawInput)
open NativeLaunchFppHistoryBinding (Oracle History)
open NativeLaunchRecordedMerkleExtraction
open NativeLaunchRecordedOracleGraph
open SmallWood.V8Smz9CoherentMerkleGeometry (databaseChildren)
local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq
noncomputable section
open Classical

/-- Insert the supplied keys in list order, with outputs from one oracle.
Repeated keys are allowed; insertion into the finite record set is idempotent. -/
def extend (H : Oracle) (records : Database) : History → Database
  | [] => records
  | key :: rest => extend H (insert (key, toOutput (H key)) records) rest

theorem oracleGraph_append_one (H : Oracle) (history : History) (key : RawInput) :
    oracleGraph H (history ++ [key]) = insert (key, toOutput (H key)) (oracleGraph H history) := by
  simp [oracleGraph, List.map_append, Finset.union_comm]

theorem extend_oracleGraph (H : Oracle) (earlier later : History) :
    extend H (oracleGraph H earlier) later = oracleGraph H (earlier ++ later) := by
  induction later generalizing earlier with
  | nil => simp [extend]
  | cons key rest ih =>
      rw [extend, ← oracleGraph_append_one, ih]
      simp only [List.append_assoc, List.singleton_append]

/-- A concrete position in the insertion list hits the fixed root or a parsed
child of the database immediately BEFORE that insertion. -/
def InsertionHit (H : Oracle) (records : Database) (later : History)
    (family : Family) (root : Output) : Prop :=
  ∃ before key after, later = before ++ key :: after ∧
    toOutput (H key) ∈ {root} ∪ databaseChildren (children family) (extend H records before)

/-- Telescoping gives an actual insertion which changed this position's
completed readback, as well as its target/child-hit localization. -/
theorem readback_change_has_insertion (H : Oracle) (records : Database) (later : History)
    {family : Family} (context : Context family) (root : Output) (index : Position)
    (changed : readback (extend H records later) context root index ≠ readback records context root index) :
    ∃ before key after, later = before ++ key :: after ∧
      readback (insert (key, toOutput (H key)) (extend H records before)) context root index ≠
        readback (extend H records before) context root index ∧
      toOutput (H key) ∈ {root} ∪ databaseChildren (children family) (extend H records before) := by
  induction later generalizing records with
  | nil => exact False.elim (changed rfl)
  | cons key rest ih =>
      by_cases first : readback (insert (key, toOutput (H key)) records) context root index =
          readback records context root index
      · have tailChanged : readback (extend H (insert (key, toOutput (H key)) records) rest)
            context root index ≠ readback (insert (key, toOutput (H key)) records) context root index := by
          intro same
          exact changed (same.trans first)
        obtain ⟨before, found, after, split, changedHere, hit⟩ := ih _ tailChanged
        refine ⟨key :: before, found, after, ?_, changedHere, hit⟩
        simpa only [List.cons_append] using congrArg (List.cons key) split
      · exact ⟨[], key, rest, rfl, first,
          source_changed_target_or_child records key (toOutput (H key)) context root ⟨index, first⟩⟩

theorem readback_change_implies_hit (H : Oracle) (records : Database) (later : History)
    {family : Family} (context : Context family) (root : Output) (index : Position)
    (changed : readback (extend H records later) context root index ≠ readback records context root index) :
    InsertionHit H records later family root := by
  obtain ⟨before, key, after, split, _, hit⟩ :=
    readback_change_has_insertion H records later context root index changed
  exact ⟨before, key, after, split, hit⟩

/-- No hits implies equality of the ENTIRE completed readback, including raw
keys, status and optional leaf, at every position. -/
theorem no_hits_readback_equal (H : Oracle) (records : Database) (later : History)
    {family : Family} (context : Context family) (root : Output)
    (noHits : ¬ InsertionHit H records later family root) (index : Position) :
    readback (extend H records later) context root index = readback records context root index := by
  by_contra changed
  exact noHits (readback_change_implies_hit H records later context root index changed)

theorem history_readback_change_implies_hit (H : Oracle) (earlier later : History)
    {family : Family} (context : Context family) (root : Output)
    (changed : ∃ index, readback (oracleGraph H (earlier ++ later)) context root index ≠
      readback (oracleGraph H earlier) context root index) :
    InsertionHit H (oracleGraph H earlier) later family root := by
  obtain ⟨index, changed⟩ := changed
  apply readback_change_implies_hit H (oracleGraph H earlier) later context root index
  simpa only [extend_oracleGraph] using changed

/-- For oracle graphs the insertion witnessing a real change must be fresh
relative to this list prefix: repeating a key inserts the identical pair.
This is deterministic freshness, not a random-output or chronology premise. -/
theorem history_change_has_fresh_insertion (H : Oracle) (earlier later : History)
    {family : Family} (context : Context family) (root : Output)
    (changed : ∃ index, readback (oracleGraph H (earlier ++ later)) context root index ≠
      readback (oracleGraph H earlier) context root index) :
    ∃ before key after, later = before ++ key :: after ∧ key ∉ earlier ++ before ∧
      toOutput (H key) ∈ {root} ∪ databaseChildren (children family) (oracleGraph H (earlier ++ before)) := by
  obtain ⟨index, changed⟩ := changed
  have changedExtension : readback (extend H (oracleGraph H earlier) later) context root index ≠
      readback (oracleGraph H earlier) context root index := by
    simpa only [extend_oracleGraph] using changed
  obtain ⟨before, key, after, split, changedHere, hit⟩ :=
    readback_change_has_insertion H (oracleGraph H earlier) later context root index changedExtension
  refine ⟨before, key, after, split, ?_, ?_⟩
  · intro recorded
    have pairMem : (key, toOutput (H key)) ∈ extend H (oracleGraph H earlier) before := by
      rw [extend_oracleGraph]
      exact oracleGraph_recorded H (earlier ++ before) key recorded
    rw [Finset.insert_eq_of_mem pairMem] at changedHere
    exact changedHere rfl
  · simpa only [extend_oracleGraph] using hit

theorem no_hits_history_readback_equal (H : Oracle) (earlier later : History)
    {family : Family} (context : Context family) (root : Output)
    (noHits : ¬ InsertionHit H (oracleGraph H earlier) later family root) (index : Position) :
    readback (oracleGraph H (earlier ++ later)) context root index =
      readback (oracleGraph H earlier) context root index := by
  simpa only [extend_oracleGraph] using
    no_hits_readback_equal H (oracleGraph H earlier) later context root noHits index

/-- Canonical cell/mask equality is a consequence of complete extraction
stability; no source-cell equality is assumed. -/
theorem no_hits_history_sources_equal (H : Oracle) (earlier later : History)
    {family : Family} (context : Context family) (root : Output)
    (noHits : ¬ InsertionHit H (oracleGraph H earlier) later family root) :
    sourceCells (oracleGraph H (earlier ++ later)) context root =
      sourceCells (oracleGraph H earlier) context root ∧
    sourceMasks (oracleGraph H (earlier ++ later)) context root =
      sourceMasks (oracleGraph H earlier) context root := by
  constructor
  · funext index column
    exact congrArg (fun result => cells result column)
      (no_hits_history_readback_equal H earlier later context root noHits index)
  · funext index row
    exact congrArg (fun result => masks result row)
      (no_hits_history_readback_equal H earlier later context root noHits index)

end
end HegemonCrypto.NativeLaunchRecordedSourceStability
