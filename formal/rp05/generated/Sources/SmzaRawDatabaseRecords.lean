import SmzaRecordedTracePath
import SmzaRawStageGeometry
import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleInstrument

/-! The recorded pairs used by the raw extractor are the literal image of
the same database. Collision freedom of a selected digest coordinate is
stated explicitly: collision freedom of entire output vectors does not imply
collision freedom of that coordinate. -/
namespace HegemonCrypto.SmallWood.SmzaRawDatabaseRecords

open HegemonCrypto.FiniteOracleDatabase
open V8Smz9CoherentMerkleInstrument SmzaRecordedTracePath
open scoped Classical
noncomputable section
set_option autoImplicit false

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  (inferInstance : LinearOrder V8SmzaOracleParser.RawInput).toDecidableEq

variable {Key Output : Type*} [Fintype Key]
  [Fintype Output] [DecidableEq Output]

theorem mem_raw_records_iff
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (outputBytes : Output → V8SmzaOracleParser.RawDigest)
    (database : Database Key Output)
    (input : V8SmzaOracleParser.RawInput) (digest : V8SmzaOracleParser.RawDigest) :
    (input, digest) ∈ rawRecords keyBytes outputBytes database ↔
      ∃ key output, database key = some output ∧
        keyBytes key = input ∧ outputBytes output = digest := by
  constructor
  · intro member
    obtain ⟨pair, present, same⟩ := Finset.mem_image.mp member
    exact ⟨pair.1, pair.2, (Finset.mem_filter.mp present).2,
      congrArg Prod.fst same, congrArg Prod.snd same⟩
  · rintro ⟨key, output, recorded, inputEq, outputEq⟩
    apply Finset.mem_image.mpr
    exact ⟨(key, output), Finset.mem_filter.mpr ⟨Finset.mem_univ _, recorded⟩,
      Prod.ext inputEq outputEq⟩

theorem raw_record_of_database_entry
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (outputBytes : Output → V8SmzaOracleParser.RawDigest)
    (database : Database Key Output) (key : Key) (output : Output)
    (recorded : database key = some output) :
    (keyBytes key, outputBytes output) ∈ rawRecords keyBytes outputBytes database :=
  (mem_raw_records_iff keyBytes outputBytes database _ _).mpr
    ⟨key, output, recorded, rfl, rfl⟩

def EncodedCollisionFree
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (outputBytes : Output → V8SmzaOracleParser.RawDigest)
    (database : Database Key Output) : Prop :=
  ∀ left right first second,
    database left = some first → database right = some second →
    outputBytes first = outputBytes second → keyBytes left = keyBytes right

theorem raw_records_collision_free_iff
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (outputBytes : Output → V8SmzaOracleParser.RawDigest)
    (database : Database Key Output) :
    RecordsCollisionFree (rawRecords keyBytes outputBytes database) ↔
      EncodedCollisionFree keyBytes outputBytes database := by
  constructor
  · intro free left right first second leftRecorded rightRecorded same
    have firstMem := raw_record_of_database_entry keyBytes outputBytes database
      left first leftRecorded
    have secondMem := raw_record_of_database_entry keyBytes outputBytes database
      right second rightRecorded
    rw [← same] at secondMem
    exact free _ _ _ firstMem secondMem
  · intro free input other digest left right
    obtain ⟨key, first, firstRecorded, keyEq, firstEq⟩ :=
      (mem_raw_records_iff keyBytes outputBytes database _ _).mp left
    obtain ⟨otherKey, second, secondRecorded, otherEq, secondEq⟩ :=
      (mem_raw_records_iff keyBytes outputBytes database _ _).mp right
    exact keyEq.symm.trans ((free key otherKey first second firstRecorded
      secondRecorded (firstEq.trans secondEq.symm)).trans otherEq)

end
end HegemonCrypto.SmallWood.SmzaRawDatabaseRecords
