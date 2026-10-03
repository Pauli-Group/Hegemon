import SmzaRp05FilteredReadback
import SmzaRp04RawCollisionBound

/-!
# RP05 collision accounting outside authorized statement namespaces

The event in this file is collision of the literal 512-bit raw-coordinate
records after deleting every leaf record whose statement is in one fixed
authorization set.  Nonleaf records and leaves for fresh statements remain.

`CmsClassicalDatabase.query` below is only the auxiliary classical query used
to calculate CMS instability.  Marking a statement is an auxiliary classical
filter update, not a physical compressed-oracle query.  The exact insert and
overwrite identities show why an already marked leaf write is invisible to
the filtered collision relation.

The final theorem applies the implemented CMS database game to the proved
`InstabilityBound`; it does not assume a collision probability.  Integration
with a protocol execution still has to identify one final classical
authorization set containing every mark before the corresponding simulated
source write.  That execution-order statement is deliberately not postulated
as an endpoint here.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05FilteredCollision

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsLifting
open V8Smz9HiddenLeafQrom
open V8Smz9CoherentMerkleGeometry
open V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle
open SmzaRecordedTracePath
open SmzaRawDatabaseRecords
open SmzaRp04StatementRecordFilter
open SmzaRp05FilteredReadback
open SmzaRp04RawCollisionBound

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev RawRecordSet :=
  V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest

local instance : DecidableEq RawInput :=
  (inferInstance : LinearOrder RawInput).toDecidableEq

variable {Key Counter Workspace : Type*}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]

/-- Literal raw records retained by the global outside-authorization filter. -/
def filteredRawRecords
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter)) :
    RawRecordSet :=
  outsideAuthorizedRecords ns authorized
    (rawRecords keyBytes (vectorOutputBytes counter) database)

/-- A collision among the records which remain relevant to every fresh
statement and to every nonleaf readback. -/
def filteredRawCollision
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter)) : Prop :=
  ¬ RecordsCollisionFree
    (filteredRawRecords ns authorized keyBytes counter database)

theorem filtered_raw_records_subset_raw
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter)) :
    filteredRawRecords ns authorized keyBytes counter database ⊆
      rawRecords keyBytes (vectorOutputBytes counter) database := by
  intro record member
  simp only [filteredRawRecords, outsideAuthorizedRecords, authorizedFilter] at member
  exact (Finset.mem_filter.mp member).1

theorem filtered_raw_records_card_le
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter)) :
    (filteredRawRecords ns authorized keyBytes counter database).card ≤
      size database := by
  exact (Finset.card_le_card
      (filtered_raw_records_subset_raw ns authorized keyBytes counter database)).trans
    (raw_records_card_le keyBytes (vectorOutputBytes counter) database)

/-- Adding a CMS database entry only enlarges the retained record relation;
if its statement is authorized, the enlargement is empty (proved below). -/
theorem filtered_raw_records_query_subset
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter))
    (key : Key) (output : VectorOutput Counter) :
    filteredRawRecords ns authorized keyBytes counter database ⊆
      filteredRawRecords ns authorized keyBytes counter
        (query database key output) := by
  by_cases absent : database key = none
  · intro record member
    simp only [filteredRawRecords, outsideAuthorizedRecords, authorizedFilter,
      query_of_absent absent,
      raw_records_insert keyBytes (vectorOutputBytes counter) database key output absent]
      at member ⊢
    apply Finset.mem_filter.mpr
    exact ⟨Finset.mem_insert_of_mem (Finset.mem_filter.mp member).1,
      (Finset.mem_filter.mp member).2⟩
  · simp [query, absent]

theorem filtered_raw_collision_query_monotone
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter))
    (key : Key) (output : VectorOutput Counter)
    (collision : filteredRawCollision ns authorized keyBytes counter database) :
    filteredRawCollision ns authorized keyBytes counter
      (query database key output) := by
  intro freeAfter
  exact collision (recordsCollisionFree_mono
    (filtered_raw_records_query_subset ns authorized keyBytes counter
      database key output) freeAfter)

/-- The reverse instability is exactly zero: once collision holds, no sampled
answer to the auxiliary query can return to collision freedom. -/
theorem filtered_raw_collision_reverse_step_probability_eq_zero
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter))
    (key : Key)
    (collision : filteredRawCollision ns authorized keyBytes counter database) :
    stepProbability
        (complement (filteredRawCollision ns authorized keyBytes counter))
        database key = 0 := by
  apply step_probability_eq_zero_of_never
  intro output outside
  exact outside (filtered_raw_collision_query_monotone ns authorized
    keyBytes counter database key output collision)

/-- Marking removes records, hence cannot make a previously collision-free
filtered relation enter the collision event. -/
theorem filtered_raw_records_mark_subset
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter)) :
    filteredRawRecords ns (insert statement authorized) keyBytes counter database ⊆
      filteredRawRecords ns authorized keyBytes counter database := by
  exact authorizedFilter_mark_subset (globalLeafStatement ns)
    authorized statement (rawRecords keyBytes (vectorOutputBytes counter) database)

theorem filtered_raw_collision_mark_monotone
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter))
    (collision : filteredRawCollision ns (insert statement authorized)
      keyBytes counter database) :
    filteredRawCollision ns authorized keyBytes counter database := by
  intro freeBefore
  exact collision (recordsCollisionFree_mono
    (filtered_raw_records_mark_subset ns authorized statement keyBytes counter database)
    freeBefore)

theorem authorization_mark_does_not_enter_collision
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter))
    (free : ¬ filteredRawCollision ns authorized keyBytes counter database) :
    ¬ filteredRawCollision ns (insert statement authorized)
      keyBytes counter database := by
  exact fun collision => free
    (filtered_raw_collision_mark_monotone ns authorized statement
      keyBytes counter database collision)

/-- If an absent CMS key is retained by the filter, its sampled coordinate is
literally one inserted raw record. -/
theorem filtered_raw_records_query_of_absent_retained
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter))
    (key : Key) (output : VectorOutput Counter)
    (absent : database key = none)
    (retained : keepOutsideAuthorized (globalLeafStatement ns)
      authorized (keyBytes key)) :
    filteredRawRecords ns authorized keyBytes counter
        (query database key output) =
      insert (keyBytes key, vectorOutputBytes counter output)
        (filteredRawRecords ns authorized keyBytes counter database) := by
  simp only [filteredRawRecords, query_of_absent absent,
    raw_records_insert keyBytes (vectorOutputBytes counter) database key output absent]
  change (insert (keyBytes key, vectorOutputBytes counter output)
      (rawRecords keyBytes (vectorOutputBytes counter) database)).filter
        (fun record => keepOutsideAuthorized (globalLeafStatement ns)
          authorized record.1) =
    insert (keyBytes key, vectorOutputBytes counter output)
      ((rawRecords keyBytes (vectorOutputBytes counter) database).filter
        (fun record => keepOutsideAuthorized (globalLeafStatement ns)
          authorized record.1))
  rw [Finset.filter_insert]
  simp only [if_pos retained]

/-- If the queried raw input belongs to an authorized leaf namespace, the
auxiliary query leaves the filtered relation exactly unchanged. -/
theorem filtered_raw_records_query_of_absent_ignored
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter))
    (key : Key) (output : VectorOutput Counter)
    (absent : database key = none)
    (ignored : ¬ keepOutsideAuthorized (globalLeafStatement ns)
      authorized (keyBytes key)) :
    filteredRawRecords ns authorized keyBytes counter
        (query database key output) =
      filteredRawRecords ns authorized keyBytes counter database := by
  simp only [filteredRawRecords, query_of_absent absent,
    raw_records_insert keyBytes (vectorOutputBytes counter) database key output absent]
  change (insert (keyBytes key, vectorOutputBytes counter output)
      (rawRecords keyBytes (vectorOutputBytes counter) database)).filter
        (fun record => keepOutsideAuthorized (globalLeafStatement ns)
          authorized record.1) =
    (rawRecords keyBytes (vectorOutputBytes counter) database).filter
      (fun record => keepOutsideAuthorized (globalLeafStatement ns)
        authorized record.1)
  rw [Finset.filter_insert]
  simp only [if_neg ignored]

/-- A marked source insert is invisible to collision accounting. -/
theorem authorized_insert_collision_invariant
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (marked : statement ∈ authorized) (input : RawInput)
    (parsed : globalLeafStatement ns input = some statement)
    (output : RawDigest) (records : RawRecordSet) :
    (¬ RecordsCollisionFree
        (outsideAuthorizedRecords ns authorized
          (insert (input, output) records))) ↔
      ¬ RecordsCollisionFree
        (outsideAuthorizedRecords ns authorized records) := by
  apply Iff.of_eq
  exact congrArg (fun filtered : RawRecordSet => ¬ RecordsCollisionFree filtered)
    (authorizedFilter_insert_authorized
      (globalLeafStatement ns) authorized statement marked input parsed
      output records)

/-- The generic overwrite used by the old-answer environment is likewise
invisible once its statement has been marked. -/
theorem authorized_overwrite_collision_invariant
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (marked : statement ∈ authorized) (input : RawInput)
    (parsed : globalLeafStatement ns input = some statement)
    (oldOutput newOutput : RawDigest) (records : RawRecordSet) :
    (¬ RecordsCollisionFree
        (outsideAuthorizedRecords ns authorized
          (overwriteRecords records input oldOutput newOutput))) ↔
      ¬ RecordsCollisionFree
        (outsideAuthorizedRecords ns authorized records) := by
  apply Iff.of_eq
  exact congrArg (fun filtered : RawRecordSet => ¬ RecordsCollisionFree filtered)
    (authorizedFilter_overwrite_authorized
      (globalLeafStatement ns) authorized statement marked input parsed
      oldOutput newOutput records)

/-- Exact invariance for an authorized raw leaf when expressed as the
auxiliary CMS query. -/
theorem authorized_query_collision_invariant
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (marked : statement ∈ authorized)
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter)) (key : Key)
    (parsed : globalLeafStatement ns (keyBytes key) = some statement)
    (output : VectorOutput Counter) :
    filteredRawCollision ns authorized keyBytes counter
        (query database key output) ↔
      filteredRawCollision ns authorized keyBytes counter database := by
  by_cases absent : database key = none
  · have ignored : ¬ keepOutsideAuthorized (globalLeafStatement ns)
        authorized (keyBytes key) := by
      simp [keepOutsideAuthorized, parsed, marked]
    unfold filteredRawCollision
    rw [filtered_raw_records_query_of_absent_ignored ns authorized
      keyBytes counter database key output absent ignored]
  · simp [query, absent]

/-- One auxiliary query creates a filtered selected-coordinate collision with
probability at most the number of occupied CMS entries divided by `2^512`. -/
theorem filtered_raw_collision_step_probability_le_size
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter)) (key : Key)
    (free : ¬ filteredRawCollision ns authorized keyBytes counter database) :
    stepProbability (filteredRawCollision ns authorized keyBytes counter)
        database key ≤ (size database : Rat) / (2 ^ 512 : Rat) := by
  classical
  let records := filteredRawRecords ns authorized keyBytes counter database
  have recordsFree : RecordsCollisionFree records := Classical.not_not.mp free
  by_cases absent : database key = none
  · by_cases retained : keepOutsideAuthorized (globalLeafStatement ns)
        authorized (keyBytes key)
    · have subset :
          successfulAnswers
              (filteredRawCollision ns authorized keyBytes counter)
              database key ⊆
            Finset.univ.filter (fun vector : VectorOutput Counter =>
              rawDigestBits.symm (vector counter) ∈ recordedDigests records) := by
        intro output member
        apply Finset.mem_filter.mpr
        refine ⟨Finset.mem_univ _, ?_⟩
        apply inserted_collision_implies_recorded_digest records
          (keyBytes key) (vectorOutputBytes counter output) recordsFree
        have afterCollision := (Finset.mem_filter.mp member).2
        have relation := filtered_raw_records_query_of_absent_retained
          ns authorized keyBytes counter database key output absent retained
        simpa only [filteredRawCollision, relation, records] using afterCollision
      have digestCard :
          (Finset.univ.filter fun output : DigestRegister =>
            rawDigestBits.symm output ∈ recordedDigests records).card =
              (recordedDigests records).card :=
        equiv_event_card rawDigestBits.symm (recordedDigests records)
      have recordCard : (recordedDigests records).card ≤ size database :=
        (Finset.card_image_le).trans
          (filtered_raw_records_card_le ns authorized keyBytes counter database)
      calc
        stepProbability (filteredRawCollision ns authorized keyBytes counter)
            database key ≤
            ((Finset.univ.filter fun vector : VectorOutput Counter =>
              rawDigestBits.symm (vector counter) ∈ recordedDigests records).card : Rat) /
                Fintype.card (VectorOutput Counter) := by
          unfold stepProbability
          apply div_le_div_of_nonneg_right
          · exact_mod_cast Finset.card_le_card subset
          · positivity
        _ = ((recordedDigests records).card : Rat) / (2 ^ 512 : Rat) := by
          rw [coordinate_event_probability counter
            (fun output => rawDigestBits.symm output ∈ recordedDigests records),
            digestCard, V8Smz9RawCounterCompiler.digest_register_cardinality]
          simp only [Nat.cast_pow, Nat.cast_ofNat]
        _ ≤ (size database : Rat) / (2 ^ 512 : Rat) := by
          apply div_le_div_of_nonneg_right
          · exact_mod_cast recordCard
          · positivity
    · rw [step_probability_eq_zero_of_never
          (filteredRawCollision ns authorized keyBytes counter) database key]
      · positivity
      · intro output afterCollision
        apply free
        have relation := filtered_raw_records_query_of_absent_ignored
          ns authorized keyBytes counter database key output absent retained
        unfold filteredRawCollision at afterCollision ⊢
        rw [relation] at afterCollision
        exact afterCollision
  · rw [step_probability_eq_zero_of_never
        (filteredRawCollision ns authorized keyBytes counter) database key]
    · positivity
    · intro output afterCollision
      apply free
      simpa [query, absent] using afterCollision

/-- Exact two-sided instability of the actual filtered raw-record event.  The
reverse density is zero because an auxiliary query never removes a retained
record. -/
theorem filtered_raw_collision_instability
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter) (cap : Nat) :
    InstabilityBound
      (filteredRawCollision ns authorized keyBytes counter) cap
      ((cap : Rat) / (2 ^ 512 : Rat)) := by
  constructor
  · refine ⟨by positivity, ?_⟩
    intro database free bounded key
    calc
      stepProbability (filteredRawCollision ns authorized keyBytes counter)
          database key ≤ (size database : Rat) / (2 ^ 512 : Rat) :=
        filtered_raw_collision_step_probability_le_size ns authorized
          keyBytes counter database key free
      _ ≤ (cap : Rat) / (2 ^ 512 : Rat) := by
        apply div_le_div_of_nonneg_right
        · exact_mod_cast Nat.le_of_lt bounded
        · positivity
  · refine ⟨by positivity, ?_⟩
    intro database collision _ key
    rw [filtered_raw_collision_reverse_step_probability_eq_zero ns authorized
      keyBytes counter database key collision]
    positivity

theorem initial_filtered_raw_collision_project_zero
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter) (cap : Nat)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Workspace) → ℂ) :
    project (filteredRawCollision ns authorized keyBytes counter) cap
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) = 0 := by
  classical
  funext basis
  by_cases records : RecordsExactly (Output := VectorOutput Counter) ∅ basis.database
  · have databaseEmpty : basis.database =
        (empty : Database Key (VectorOutput Counter)) :=
      (records_exactly_empty_iff basis.database).mp records
    have outside : ¬ filteredRawCollision ns authorized keyBytes counter
        (empty : Database Key (VectorOutput Counter)) := by
      unfold filteredRawCollision
      apply Classical.not_not.mpr
      intro left right digest leftMember _
      have rawMember := (filtered_raw_records_subset_raw ns authorized
        keyBytes counter (empty : Database Key (VectorOutput Counter))) leftMember
      simp [rawRecords] at rawMember
    simp [project, databaseEmpty, size_empty, outside]
  · simp [project, partialRandomOracleState, records]

/-- Exact rational loss obtained by applying the CMS database theorem to the
proved filtered instability. -/
def filteredRawCollisionLoss (queries : Nat) : Rat :=
  6 * (queries : Rat) ^ 3 / (2 : Rat) ^ 512

variable [Fintype Workspace] [DecidableEq Workspace]

/-- The measured final compressed database has a collision in the global
outside-authorization relation with mass at most `6*T^3/2^512`. -/
theorem measured_filtered_raw_collision_bound
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte))
    (keyBytes : Key → RawInput) (counter : Counter)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Workspace)))
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) :
    normSquared
        (project (filteredRawCollision ns authorized keyBytes counter)
          steps.length
          (rawRun vectorPhaseSystem steps.length
            (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
            (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) ≤
      (filteredRawCollisionLoss steps.length : ℝ) := by
  classical
  let blind := steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅ registers
  have capacity : blind.length ≤ steps.length := by simp [blind]
  have emptySupport : BoundedState 0 initial :=
    partial_random_oracle_empty_bounded registers
  have result := implemented_raw_database_game_le_database_loss
    vectorPhaseSystem
    (filteredRawCollision ns authorized keyBytes counter)
    steps.length blind initial
    (filtered_raw_collision_instability ns authorized keyBytes counter
      steps.length).toReal
    capacity emptySupport normalized
    (initial_filtered_raw_collision_project_zero ns authorized keyBytes counter
      steps.length registers)
  calc
    _ ≤ databaseLoss steps.length
        ((((steps.length : Rat) / (2 ^ 512 : Rat)) : Rat) : ℝ) := by
      simpa only [blind, initial, List.length_map] using result
    _ = (filteredRawCollisionLoss steps.length : ℝ) := by
      unfold databaseLoss filteredRawCollisionLoss
      push_cast
      ring

end
end HegemonCrypto.SmallWood.SmzaRp05FilteredCollision
