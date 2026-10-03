import SmzaRp05ChallengeRecordErasure
import SmzaRp04StatementRecordFilter
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05GroupedSuffix
import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleInstrument

/-! # Database invariance of the erased grouped record view

After challenge frames are erased, grouped raw records depend only on the
database values at keys whose canonical representative is not a recognized
challenge input. The statement is about the actual raw-record projection;
it does not postulate an equality of oracle tables on challenge keys. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentNonchallengeRecordView

open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05CurrentFiniteGroupedProgram (Key included)
open SmzaRp05GroupedSuffix (groupRepresentative GroupCounter groupZero)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords eraseChallengeRecords_eq_parse_none)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8SmzaOracleParser (RawInput RawDigest)
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.SmallWood.SmzaChallengeStageTargets (parseStageQuery)

noncomputable section
set_option autoImplicit false

/-- General raw-record form: agreement only at keys whose exposed input is
not a recognized challenge frame is enough to make the erased record views
identical. -/
theorem erased_raw_records_eq_of_nonchallenge_key_agreement
    {Key Output : Type*} [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output]
    (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (left right : Database Key Output)
    (agree : ∀ key, parseStageQuery (keyBytes key) = none →
      left key = right key) :
    eraseChallengeRecords (rawRecords keyBytes outputBytes left) =
      eraseChallengeRecords (rawRecords keyBytes outputBytes right) := by
  classical
  rw [eraseChallengeRecords_eq_parse_none, eraseChallengeRecords_eq_parse_none]
  unfold rawRecords
  ext record
  simp only [Finset.mem_filter, Finset.mem_image, Finset.mem_univ, true_and]
  constructor
  · rintro ⟨⟨pair, leftRead, recordEq⟩, nonchallenge⟩
    have pairNonchallenge : parseStageQuery (keyBytes pair.1) = none := by
      have inputEq : keyBytes pair.1 = record.1 := congrArg Prod.fst recordEq
      rw [inputEq]
      exact nonchallenge
    have rightRead : right pair.1 = some pair.2 := by
      rw [← agree pair.1 pairNonchallenge]
      exact leftRead
    exact ⟨⟨pair, rightRead, recordEq⟩, nonchallenge⟩
  · rintro ⟨⟨pair, rightRead, recordEq⟩, nonchallenge⟩
    have pairNonchallenge : parseStageQuery (keyBytes pair.1) = none := by
      have inputEq : keyBytes pair.1 = record.1 := congrArg Prod.fst recordEq
      rw [inputEq]
      exact nonchallenge
    have leftRead : left pair.1 = some pair.2 := by
      rw [agree pair.1 pairNonchallenge]
      exact rightRead
    exact ⟨⟨pair, leftRead, recordEq⟩, nonchallenge⟩

/-- Concrete grouped-database specialization. Keys contributing to the
erased view may vary only when their grouped representatives parse as
challenge queries; those keys are absent from this raw-record view. -/
theorem grouped_erased_raw_records_eq_of_nonchallenge_key_agreement
    {Result : Type}
    (program : SmzaRp05ExecutableMerkleVerifier.Program Result)
    (left right : Database (Key program) (VectorOutput GroupCounter))
    (agree : ∀ key, parseStageQuery
      (groupRepresentative (included program key)) = none →
        left key = right key) :
    eraseChallengeRecords
        (rawRecords (fun key => groupRepresentative (included program key))
          (vectorOutputBytes groupZero) left) =
      eraseChallengeRecords
        (rawRecords (fun key => groupRepresentative (included program key))
          (vectorOutputBytes groupZero) right) := by
  exact erased_raw_records_eq_of_nonchallenge_key_agreement
    (fun key => groupRepresentative (included program key))
    (vectorOutputBytes groupZero)
    left right agree

/-- Statement-filtered traces inherit the same exact record equality. -/
theorem grouped_one_statement_view_eq_of_nonchallenge_key_agreement
    {Result : Type}
    (program : SmzaRp05ExecutableMerkleVerifier.Program Result)
    (left right : Database (Key program) (VectorOutput GroupCounter))
    (agree : ∀ key, parseStageQuery
      (groupRepresentative (included program key)) = none →
        left key = right key)
    (leafStatement : HegemonCrypto.SmallWood.SmzaRp04StatementRecordFilter.StatementParser
      RawInput (List Byte))
    (statement : List Byte) :
    oneStatementFilter leafStatement statement
      (eraseChallengeRecords
        (rawRecords (fun key => groupRepresentative (included program key))
          (vectorOutputBytes groupZero) left)) =
    oneStatementFilter leafStatement statement
      (eraseChallengeRecords
        (rawRecords (fun key => groupRepresentative (included program key))
          (vectorOutputBytes groupZero) right)) := by
  rw [grouped_erased_raw_records_eq_of_nonchallenge_key_agreement
    program left right agree]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentNonchallengeRecordView
