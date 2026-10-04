import SmzaRawDatabaseRecords
import SmzaRp04FourRoleLedger
import HegemonCrypto.SmallWoodV8Smz9CoherentVectorMerkle
import HegemonCrypto.CmsLifting
import HegemonCrypto.CmsOracleSimulation

/-!
# Raw-coordinate collision bound for the RP04 execution

The raw extractor reads one literal 512-bit coordinate of the full counter
vector.  This file bounds collision of that coordinate on the measured CMS
database.  It does not use the classical-ROM `hashCollisionLoss`, and it does
not identify this event with collision of the Poseidon2 note commitment used
by the finite supply ledger.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04RawCollisionBound

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
open SmzaRp04FourRoleLedger

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest

local instance : DecidableEq RawInput :=
  (inferInstance : LinearOrder RawInput).toDecidableEq

/-- Digests already present in a literal raw record relation. -/
def recordedDigests (records : Records RawInput RawDigest) : Finset RawDigest :=
  records.image Prod.snd

/-- Inserting a digest not previously recorded cannot create two different
raw inputs with that digest. -/
theorem records_collision_free_insert_of_digest_not_mem
    (records : Records RawInput RawDigest) (input : RawInput) (digest : RawDigest)
    (free : RecordsCollisionFree records)
    (fresh : digest ∉ recordedDigests records) :
    RecordsCollisionFree (Insert.insert (input, digest) records) := by
  intro left right output leftMember rightMember
  rcases Finset.mem_insert.mp leftMember with leftNew | leftOld
  · rcases Finset.mem_insert.mp rightMember with rightNew | rightOld
    · exact (congrArg Prod.fst leftNew).trans (congrArg Prod.fst rightNew).symm
    · exfalso
      apply fresh
      apply Finset.mem_image.mpr
      exact ⟨(right, output), rightOld, congrArg Prod.snd leftNew⟩
  · rcases Finset.mem_insert.mp rightMember with rightNew | rightOld
    · exfalso
      apply fresh
      apply Finset.mem_image.mpr
      exact ⟨(left, output), leftOld, congrArg Prod.snd rightNew⟩
    · exact free left right output leftOld rightOld

theorem inserted_collision_implies_recorded_digest
    (records : Records RawInput RawDigest) (input : RawInput) (digest : RawDigest)
    (free : RecordsCollisionFree records)
    (collision : ¬ RecordsCollisionFree (Insert.insert (input, digest) records)) :
    digest ∈ recordedDigests records := by
  by_contra fresh
  exact collision
    (records_collision_free_insert_of_digest_not_mem records input digest free fresh)

variable {Key Counter Workspace : Type*}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]

/-- Collision of the literal 512-bit coordinate read by the raw extractor.
The property is on the actual measured CMS database, not on the complete
counter vector. -/
def rawCoordinateCollision
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter)) : Prop :=
  ¬ RecordsCollisionFree
    (rawRecords keyBytes (vectorOutputBytes counter) database)

/-- The structural raw-record formulation is exactly failure of the encoded
coordinate collision-free predicate. -/
theorem raw_coordinate_collision_iff_not_encoded
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter)) :
    rawCoordinateCollision keyBytes counter database ↔
      ¬ EncodedCollisionFree keyBytes (vectorOutputBytes counter) database := by
  unfold rawCoordinateCollision
  rw [raw_records_collision_free_iff]

theorem raw_coordinate_collision_monotone
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter)) (key : Key)
    (output : VectorOutput Counter)
    (collision : rawCoordinateCollision keyBytes counter database) :
    rawCoordinateCollision keyBytes counter (query database key output) := by
  by_cases absent : database key = none
  · unfold rawCoordinateCollision at collision ⊢
    rw [query_of_absent absent,
      raw_records_insert keyBytes (vectorOutputBytes counter) database key output absent]
    intro freeAfter
    apply collision
    intro left right digest leftMember rightMember
    exact freeAfter left right digest
      (Finset.mem_insert_of_mem leftMember) (Finset.mem_insert_of_mem rightMember)
  · simpa [query, absent] using collision

/-- One query creates a selected-coordinate collision with probability at
most the number of already occupied database entries divided by `2^512`.
The proof counts the exact coordinate marginal of the full vector output. -/
theorem raw_coordinate_collision_step_probability_le_size
    (keyBytes : Key → RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter)) (key : Key)
    (free : ¬ rawCoordinateCollision keyBytes counter database) :
    stepProbability (rawCoordinateCollision keyBytes counter) database key ≤
      (size database : Rat) / (2 ^ 512 : Rat) := by
  classical
  let records := rawRecords keyBytes (vectorOutputBytes counter) database
  have recordsFree : RecordsCollisionFree records := by
    exact Classical.not_not.mp free
  by_cases absent : database key = none
  · have subset :
        successfulAnswers (rawCoordinateCollision keyBytes counter) database key ⊆
          Finset.univ.filter (fun vector : VectorOutput Counter =>
            rawDigestBits.symm (vector counter) ∈ recordedDigests records) := by
      intro output member
      apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_univ _, ?_⟩
      apply inserted_collision_implies_recorded_digest records
        (keyBytes key) (vectorOutputBytes counter output) recordsFree
      have afterCollision := (Finset.mem_filter.mp member).2
      simpa only [rawCoordinateCollision, query_of_absent absent,
        raw_records_insert keyBytes (vectorOutputBytes counter) database key output absent,
        records] using afterCollision
    have digestCard :
        (Finset.univ.filter fun output : DigestRegister =>
          rawDigestBits.symm output ∈ recordedDigests records).card =
            (recordedDigests records).card :=
      equiv_event_card rawDigestBits.symm (recordedDigests records)
    have recordCard : (recordedDigests records).card ≤ size database :=
      (Finset.card_image_le).trans
        (raw_records_card_le keyBytes (vectorOutputBytes counter) database)
    calc
      stepProbability (rawCoordinateCollision keyBytes counter) database key ≤
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
        (rawCoordinateCollision keyBytes counter) database key]
    · positivity
    · intro output afterCollision
      apply free
      simpa [query, absent] using afterCollision

/-- Exact two-sided CMS instability for collision of one raw 512-bit
coordinate.  A collision cannot disappear when another database entry is
queried, so the reverse transition probability is zero. -/
theorem raw_coordinate_collision_instability
    (keyBytes : Key → RawInput) (counter : Counter) (cap : Nat) :
    InstabilityBound (rawCoordinateCollision keyBytes counter) cap
      ((cap : Rat) / (2 ^ 512 : Rat)) := by
  constructor
  · refine ⟨by positivity, ?_⟩
    intro database free bounded key
    calc
      stepProbability (rawCoordinateCollision keyBytes counter) database key ≤
          (size database : Rat) / (2 ^ 512 : Rat) :=
        raw_coordinate_collision_step_probability_le_size
          keyBytes counter database key free
      _ ≤ (cap : Rat) / (2 ^ 512 : Rat) := by
        apply div_le_div_of_nonneg_right
        · exact_mod_cast Nat.le_of_lt bounded
        · positivity
  · refine ⟨by positivity, ?_⟩
    intro database collision _ key
    rw [step_probability_eq_zero_of_never
      (complement (rawCoordinateCollision keyBytes counter)) database key]
    · positivity
    · intro output outside
      exact outside
        (raw_coordinate_collision_monotone keyBytes counter database key output collision)

theorem initial_raw_coordinate_collision_project_zero
    (keyBytes : Key → RawInput) (counter : Counter) (cap : Nat)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Workspace) → ℂ) :
    project (rawCoordinateCollision keyBytes counter) cap
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) = 0 := by
  classical
  funext basis
  by_cases records : RecordsExactly (Output := VectorOutput Counter) ∅ basis.database
  · have databaseEmpty : basis.database =
        (empty : Database Key (VectorOutput Counter)) :=
      (records_exactly_empty_iff basis.database).mp records
    have outside : ¬ rawCoordinateCollision keyBytes counter
        (empty : Database Key (VectorOutput Counter)) := by
      unfold rawCoordinateCollision
      apply Classical.not_not.mpr
      intro left right digest leftMember _
      simp [rawRecords] at leftMember
    simp [project, databaseEmpty, size_empty, outside]
  · simp [project, partialRandomOracleState, records]

/-- Exact rational collision loss delivered by the CMS database game. -/
def rawCoordinateCollisionLoss (queries : Nat) : Rat :=
  6 * (queries : Rat) ^ 3 / (2 : Rat) ^ 512

variable [Fintype Workspace] [DecidableEq Workspace]

/-- The measured final compressed database has a selected-coordinate
collision with mass at most `6*T^3/2^512`.  This is the quantum CMS database
bound on the actual full-vector execution, rather than the classical ROM
birthday expression. -/
theorem measured_raw_coordinate_collision_bound
    (keyBytes : Key → RawInput) (counter : Counter)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Workspace)))
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) :
    normSquared
        (project (rawCoordinateCollision keyBytes counter) steps.length
          (rawRun vectorPhaseSystem steps.length
            (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
            (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) ≤
      (rawCoordinateCollisionLoss steps.length : ℝ) := by
  classical
  let blind := steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅ registers
  have capacity : blind.length ≤ steps.length := by simp [blind]
  have emptySupport : BoundedState 0 initial :=
    partial_random_oracle_empty_bounded registers
  have result := implemented_raw_database_game_le_database_loss
    vectorPhaseSystem (rawCoordinateCollision keyBytes counter) steps.length blind initial
    (raw_coordinate_collision_instability keyBytes counter steps.length).toReal
    capacity emptySupport normalized
    (initial_raw_coordinate_collision_project_zero keyBytes counter steps.length registers)
  calc
    _ ≤ databaseLoss steps.length
        ((((steps.length : Rat) / (2 ^ 512 : Rat)) : Rat) : ℝ) := by
      simpa only [blind, initial, List.length_map] using result
    _ = (rawCoordinateCollisionLoss steps.length : ℝ) := by
      unfold databaseLoss rawCoordinateCollisionLoss
      push_cast
      ring

/-- Existing execution/lifetime query cap. -/
def lifetimeQueryCap : Nat := 3 * 2 ^ 64

theorem raw_coordinate_collision_loss_mono {smaller larger : Nat}
    (bounded : smaller ≤ larger) :
    rawCoordinateCollisionLoss smaller ≤ rawCoordinateCollisionLoss larger := by
  unfold rawCoordinateCollisionLoss
  apply div_le_div_of_nonneg_right
  · apply mul_le_mul_of_nonneg_left
    · gcongr
    · norm_num
  · positivity

/-- Apply the measured CMS theorem under the existing lifetime query cap. -/
theorem measured_raw_coordinate_collision_at_lifetime_cap
    (keyBytes : Key → RawInput) (counter : Counter)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Workspace)))
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (queryCap : steps.length ≤ lifetimeQueryCap) :
    normSquared
        (project (rawCoordinateCollision keyBytes counter) steps.length
          (rawRun vectorPhaseSystem steps.length
            (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
            (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) ≤
      (rawCoordinateCollisionLoss lifetimeQueryCap : ℝ) := by
  exact (measured_raw_coordinate_collision_bound keyBytes counter steps registers normalized).trans
    (by exact_mod_cast (raw_coordinate_collision_loss_mono queryCap))

theorem lifetime_raw_coordinate_collision_loss_exact :
    rawCoordinateCollisionLoss lifetimeQueryCap = 162 / (2 : Rat) ^ 320 := by
  norm_num [rawCoordinateCollisionLoss, lifetimeQueryCap]

theorem lifetime_raw_coordinate_collision_loss_below_129_bits :
    rawCoordinateCollisionLoss lifetimeQueryCap < (1 / 2 : Rat) ^ 129 := by
  norm_num [rawCoordinateCollisionLoss, lifetimeQueryCap]

theorem lifetime_raw_coordinate_collision_fits_headroom :
    rawCoordinateCollisionLoss lifetimeQueryCap < bindingLifetimeHeadroom :=
  lifetime_raw_coordinate_collision_loss_below_129_bits.trans
    binding_lifetime_headroom_exceeds_half_target

/-- Concrete numerical composition with the checked four-role stage ledger.
This theorem charges only the raw-coordinate collision event.  The Poseidon2
note-commitment collision in `SmzaRp04SemanticLedger` remains a separate
primitive-security boundary. -/
theorem stage_plus_raw_coordinate_collision_below_128_bits :
    cappedFourRoleStageBudget + rawCoordinateCollisionLoss lifetimeQueryCap <
      (1 / 2 : Rat) ^ 128 :=
  stage_plus_binding_lifetime_below_128_bits _
    lifetime_raw_coordinate_collision_fits_headroom

end
end HegemonCrypto.SmallWood.SmzaRp04RawCollisionBound
