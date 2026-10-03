import SmzaRecordedTracePath
import SmzaRawRecordedPrefix

/-!
# Statement-indexed record filters for RP04

The parser is deliberately abstract here.  A later source-refinement theorem
must instantiate it with the exact strict-leaf-v2 decoder.  These definitions
filter the finite raw record relation *before* the existing deterministic
least-preimage extractor is run.
-/
namespace HegemonCrypto.SmallWood.SmzaRp04StatementRecordFilter

open V8Smz9CoherentMerkleGeometry
open SmzaRecordedTracePath
open scoped Classical

noncomputable section
set_option autoImplicit false

abbrev Records (Input Output : Type*) :=
  V8Smz9CoherentMerkleGeometry.Records Input Output

/-- An exact leaf-namespace parser. `none` includes every nonleaf or malformed
raw input; the concrete strict-leaf-v2 parser is supplied by later work. -/
abbrev StatementParser (RawInput Statement : Type*) := RawInput → Option Statement

def keepOutsideAuthorized {RawInput Statement : Type*} [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (authorized : Finset Statement) (input : RawInput) : Prop :=
  match leafStatement input with
  | none => True
  | some statement => statement ∉ authorized

def authorizedFilter {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (authorized : Finset Statement) (records : Records RawInput RawDigest) :
    Records RawInput RawDigest :=
  records.filter fun record => keepOutsideAuthorized leafStatement authorized record.1

def keepOneStatement {RawInput Statement : Type*}
    (leafStatement : StatementParser RawInput Statement)
    (statement : Statement) (input : RawInput) : Prop :=
  leafStatement input = none ∨ leafStatement input = some statement

def oneStatementFilter {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (statement : Statement) (records : Records RawInput RawDigest) :
    Records RawInput RawDigest :=
  records.filter fun record => keepOneStatement leafStatement statement record.1

def nonleafFilter {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest]
    (leafStatement : StatementParser RawInput Statement)
    (records : Records RawInput RawDigest) : Records RawInput RawDigest :=
  records.filter fun record => leafStatement record.1 = none

private theorem filter_erase_excluded {α : Type*} [DecidableEq α]
    (records : Finset α) (keep : α → Prop) [DecidablePred keep]
    (record : α) (excluded : ¬ keep record) :
    (records.erase record).filter keep = records.filter keep := by
  ext candidate
  by_cases same : candidate = record
  · subst candidate
    simp [Finset.mem_filter, excluded]
  · simp [Finset.mem_filter, Finset.mem_erase, same]

/-- Authorization is monotone, while the relation retained for collision
accounting is antitone in the authorization set. -/
theorem authorizedFilter_antitone
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    {earlier later : Finset Statement} (grows : earlier ⊆ later)
    (records : Records RawInput RawDigest) :
    authorizedFilter leafStatement later records ⊆
      authorizedFilter leafStatement earlier records := by
  intro record member
  obtain ⟨recorded, retained⟩ := Finset.mem_filter.mp member
  apply Finset.mem_filter.mpr
  refine ⟨recorded, ?_⟩
  cases parsed : leafStatement record.1 with
  | none => simp [keepOutsideAuthorized, parsed]
  | some statement =>
      simp only [keepOutsideAuthorized, parsed] at retained ⊢
      exact fun present => retained (grows present)

theorem authorizedFilter_mark_subset
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (authorized : Finset Statement) (statement : Statement)
    (records : Records RawInput RawDigest) :
    authorizedFilter leafStatement (insert statement authorized) records ⊆
      authorizedFilter leafStatement authorized records :=
  authorizedFilter_antitone leafStatement
    (by intro other member; exact Finset.mem_insert_of_mem member) records

/-- A decoder for a statement fresh relative to `authorized` sees a subset
of the global outside-authorization collision relation. -/
theorem oneStatementFilter_subset_authorizedFilter
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (authorized : Finset Statement) (statement : Statement)
    (fresh : statement ∉ authorized) (records : Records RawInput RawDigest) :
    oneStatementFilter leafStatement statement records ⊆
      authorizedFilter leafStatement authorized records := by
  intro record member
  obtain ⟨recorded, retained⟩ := Finset.mem_filter.mp member
  change leafStatement record.1 = none ∨
    leafStatement record.1 = some statement at retained
  apply Finset.mem_filter.mpr
  refine ⟨recorded, ?_⟩
  cases parsed : leafStatement record.1 with
  | none => simp [keepOutsideAuthorized, parsed]
  | some parsedStatement =>
      have same : parsedStatement = statement := by
        rcases retained with absent | same
        · simp [parsed] at absent
        · simpa [parsed] using same
      subst parsedStatement
      simpa [keepOutsideAuthorized, parsed] using fresh

theorem recordsCollisionFree_mono
    {RawInput RawDigest : Type*} [LinearOrder RawInput] [DecidableEq RawDigest]
    {smaller larger : Records RawInput RawDigest}
    (subset : smaller ⊆ larger) (collisionFree : RecordsCollisionFree larger) :
    RecordsCollisionFree smaller := by
  intro input other output left right
  exact collisionFree input other output (subset left) (subset right)

theorem oneStatementFilter_collisionFree_of_authorized
    {RawInput RawDigest Statement : Type*}
    [LinearOrder RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (authorized : Finset Statement) (statement : Statement)
    (fresh : statement ∉ authorized) (records : Records RawInput RawDigest)
    (collisionFree : RecordsCollisionFree
      (authorizedFilter leafStatement authorized records)) :
    RecordsCollisionFree (oneStatementFilter leafStatement statement records) :=
  recordsCollisionFree_mono
    (oneStatementFilter_subset_authorizedFilter
      leafStatement authorized statement fresh records)
    collisionFree

/-- Filtering out authorized namespaces never removes a nonleaf record. -/
theorem nonleafFilter_authorizedFilter
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (authorized : Finset Statement) (records : Records RawInput RawDigest) :
    nonleafFilter leafStatement (authorizedFilter leafStatement authorized records) =
      nonleafFilter leafStatement records := by
  ext record
  cases parsed : leafStatement record.1 <;>
    simp [nonleafFilter, authorizedFilter, keepOutsideAuthorized, parsed]

/-- For a fresh statement, prefiltering by authorization does not further
change its one-statement relation. -/
theorem oneStatementFilter_authorizedFilter_of_fresh
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (authorized : Finset Statement) (statement : Statement)
    (fresh : statement ∉ authorized) (records : Records RawInput RawDigest) :
    oneStatementFilter leafStatement statement
        (authorizedFilter leafStatement authorized records) =
      oneStatementFilter leafStatement statement records := by
  ext record
  cases parsed : leafStatement record.1 with
  | none =>
      simp [oneStatementFilter, authorizedFilter, keepOneStatement,
        keepOutsideAuthorized, parsed]
  | some parsedStatement =>
      by_cases same : parsedStatement = statement
      · subst parsedStatement
        simp [oneStatementFilter, authorizedFilter, keepOneStatement,
          keepOutsideAuthorized, parsed, fresh]
      · simp [oneStatementFilter, authorizedFilter, keepOneStatement,
          keepOutsideAuthorized, parsed, same]

theorem oneStatementFilter_insert_ignored
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (statement other : Statement) (different : other ≠ statement)
    (input : RawInput) (parsed : leafStatement input = some other)
    (output : RawDigest) (records : Records RawInput RawDigest) :
    oneStatementFilter leafStatement statement (insert (input, output) records) =
      oneStatementFilter leafStatement statement records := by
  simp [oneStatementFilter, keepOneStatement, Finset.filter_insert,
    parsed, different]

theorem oneStatementFilter_erase_ignored
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (statement other : Statement) (different : other ≠ statement)
    (input : RawInput) (parsed : leafStatement input = some other)
    (output : RawDigest) (records : Records RawInput RawDigest) :
    oneStatementFilter leafStatement statement (records.erase (input, output)) =
      oneStatementFilter leafStatement statement records := by
  unfold oneStatementFilter
  apply filter_erase_excluded
  simp [keepOneStatement, parsed, different]

def overwriteRecords {RawInput RawDigest : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest]
    (records : Records RawInput RawDigest) (input : RawInput)
    (oldOutput newOutput : RawDigest) : Records RawInput RawDigest :=
  insert (input, newOutput) (records.erase (input, oldOutput))

theorem oneStatementFilter_overwrite_ignored
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (statement other : Statement) (different : other ≠ statement)
    (input : RawInput) (parsed : leafStatement input = some other)
    (oldOutput newOutput : RawDigest) (records : Records RawInput RawDigest) :
    oneStatementFilter leafStatement statement
        (overwriteRecords records input oldOutput newOutput) =
      oneStatementFilter leafStatement statement records := by
  calc
    _ = oneStatementFilter leafStatement statement
        (records.erase (input, oldOutput)) :=
      oneStatementFilter_insert_ignored leafStatement statement other different
        input parsed newOutput (records.erase (input, oldOutput))
    _ = oneStatementFilter leafStatement statement records :=
      oneStatementFilter_erase_ignored leafStatement statement other different
        input parsed oldOutput records

theorem authorizedFilter_insert_authorized
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (authorized : Finset Statement) (statement : Statement)
    (marked : statement ∈ authorized) (input : RawInput)
    (parsed : leafStatement input = some statement)
    (output : RawDigest) (records : Records RawInput RawDigest) :
    authorizedFilter leafStatement authorized (insert (input, output) records) =
      authorizedFilter leafStatement authorized records := by
  simp [authorizedFilter, keepOutsideAuthorized, Finset.filter_insert,
    parsed, marked]

theorem authorizedFilter_overwrite_authorized
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (authorized : Finset Statement) (statement : Statement)
    (marked : statement ∈ authorized) (input : RawInput)
    (parsed : leafStatement input = some statement)
    (oldOutput newOutput : RawDigest) (records : Records RawInput RawDigest) :
    authorizedFilter leafStatement authorized
        (overwriteRecords records input oldOutput newOutput) =
      authorizedFilter leafStatement authorized records := by
  calc
    _ = authorizedFilter leafStatement authorized
        (records.erase (input, oldOutput)) := by
      exact authorizedFilter_insert_authorized leafStatement authorized statement
        marked input parsed newOutput (records.erase (input, oldOutput))
    _ = authorizedFilter leafStatement authorized records := by
      unfold authorizedFilter
      apply filter_erase_excluded
      simp [keepOutsideAuthorized, parsed, marked]

theorem nonleafFilter_insert_leaf
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest]
    (leafStatement : StatementParser RawInput Statement)
    (statement : Statement) (input : RawInput)
    (parsed : leafStatement input = some statement)
    (output : RawDigest) (records : Records RawInput RawDigest) :
    nonleafFilter leafStatement (insert (input, output) records) =
      nonleafFilter leafStatement records := by
  simp [nonleafFilter, Finset.filter_insert, parsed]

theorem nonleafFilter_overwrite_leaf
    {RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest]
    (leafStatement : StatementParser RawInput Statement)
    (statement : Statement) (input : RawInput)
    (parsed : leafStatement input = some statement)
    (oldOutput newOutput : RawDigest) (records : Records RawInput RawDigest) :
    nonleafFilter leafStatement
        (overwriteRecords records input oldOutput newOutput) =
      nonleafFilter leafStatement records := by
  calc
    _ = nonleafFilter leafStatement (records.erase (input, oldOutput)) := by
      exact nonleafFilter_insert_leaf leafStatement statement input parsed newOutput
        (records.erase (input, oldOutput))
    _ = nonleafFilter leafStatement records := by
      unfold nonleafFilter
      apply filter_erase_excluded
      simp [parsed]

/-- Congruence uses the existing deterministic raw extractor, after equality
of the relations supplied to least-preimage selection has been established. -/
theorem extract_congr_of_filtered_records_eq
    {RawInput RawDigest Statement Stage : Type*}
    [LinearOrder RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement) (statement : Statement)
    (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (left right : Records RawInput RawDigest)
    (same : oneStatementFilter leafStatement statement left =
      oneStatementFilter leafStatement statement right)
    (fuel : Nat) (stage : Stage) (target : RawDigest) :
    extract next (oneStatementFilter leafStatement statement left) fuel stage target =
      extract next (oneStatementFilter leafStatement statement right) fuel stage target := by
  rw [same]

theorem extract_insert_ignored
    {RawInput RawDigest Statement Stage : Type*}
    [LinearOrder RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (statement other : Statement) (different : other ≠ statement)
    (input : RawInput) (parsed : leafStatement input = some other)
    (output : RawDigest) (records : Records RawInput RawDigest)
    (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (fuel : Nat) (stage : Stage) (target : RawDigest) :
    extract next
        (oneStatementFilter leafStatement statement (insert (input, output) records))
        fuel stage target =
      extract next (oneStatementFilter leafStatement statement records)
        fuel stage target := by
  apply extract_congr_of_filtered_records_eq
  exact oneStatementFilter_insert_ignored leafStatement statement other different
    input parsed output records

theorem extract_overwrite_ignored
    {RawInput RawDigest Statement Stage : Type*}
    [LinearOrder RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (statement other : Statement) (different : other ≠ statement)
    (input : RawInput) (parsed : leafStatement input = some other)
    (oldOutput newOutput : RawDigest) (records : Records RawInput RawDigest)
    (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (fuel : Nat) (stage : Stage) (target : RawDigest) :
    extract next
        (oneStatementFilter leafStatement statement
          (overwriteRecords records input oldOutput newOutput))
        fuel stage target =
      extract next (oneStatementFilter leafStatement statement records)
        fuel stage target := by
  apply extract_congr_of_filtered_records_eq
  exact oneStatementFilter_overwrite_ignored leafStatement statement other different
    input parsed oldOutput newOutput records

/-- The existing recorded-prefix theorem applies directly to the filtered
relation.  Collision freedom is inherited from the global fresh relation;
no new extractor or successful-extraction premise is introduced. -/
theorem fresh_recorded_prefix_is_complete_subtree
    {Statement : Type*} [DecidableEq Statement]
    (leafStatement : StatementParser V8SmzaOracleParser.RawInput Statement)
    (authorized : Finset Statement) (statement : Statement)
    (fresh : statement ∉ authorized)
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (collisionFree : RecordsCollisionFree
      (authorizedFilter leafStatement authorized records))
    (stage : V8SmzaOracleParser.Stage) (target : V8SmzaOracleParser.RawDigest)
    (path : List Nat) (finalStage : V8SmzaOracleParser.Stage)
    (finalTarget : V8SmzaOracleParser.RawDigest)
    (recorded : SmzaRawRecordedPrefix.RecordedStages
      (oneStatementFilter leafStatement statement records)
      stage target path finalStage finalTarget)
    (fuel : Nat) (enough : SmzaRawTraceDepth.stageDepth stage ≤ fuel) :
    SmzaRawRecordedPrefix.subtree path
        (extract SmzaRawStageGeometry.rawOnlineNext
          (oneStatementFilter leafStatement statement records) fuel stage target) =
      extract SmzaRawStageGeometry.rawOnlineNext
        (oneStatementFilter leafStatement statement records)
        fuel finalStage finalTarget := by
  apply SmzaRawRecordedPrefix.recorded_prefix_is_complete_subtree
  · exact oneStatementFilter_collisionFree_of_authorized
      leafStatement authorized statement fresh records collisionFree
  · exact recorded
  · exact enough

end
end HegemonCrypto.SmallWood.SmzaRp04StatementRecordFilter
