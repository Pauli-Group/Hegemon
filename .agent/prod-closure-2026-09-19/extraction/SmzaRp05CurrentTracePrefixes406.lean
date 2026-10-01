import SmzaRp05TracePrefixes
import SmzaRp05CurrentMaxAgreementRecovery
import SmzaRp05CurrentResponseInputDecoder
import SmzaRp05CurrentUniversalMatrixLoss
import SmzaRp05CurrentQ38DetectionProbability

/-!
# Current 406-map trace prefixes

The DECS-sample label is computed from the current-map support and decoder,
using only the earlier matrix challenge and the pre-query root/FPP trace.  The
selected q38 output is consulted only by the event predicate.  Bad matrices
are fail-closed here and charged by the separate current matrix-role event.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentTracePrefixes406

open scoped Classical
open HegemonCrypto.SmallWood
open HegemonCrypto.SmallWood.V8Smz9McaRecovery
open HegemonCrypto.SmallWood.V8Smz9McaDecoder
open SmzaRp05TracePrefixes
open SmzaRp05CurrentMaxAgreementRecovery
open SmzaRp05CurrentResponseInputDecoder
open SmzaRp05CurrentUniversalMatrixLoss
open SmzaRp05Q38CurrentRebinding
open SmzaQ38McaSourceBinding SmzaQ38OracleExtraction SmzaQ38Recovery
open SmzaRp04ChronologicalAlgebra
open SmzaRp05CurrentQ38DetectionProbability
open HegemonCrypto.SmallWood.Mca38UniversalMatrixEvent
open SmzaRp04McaRoleCells SmzaRp04RoleBadCells
open SmzaChallengeStageTargets
open V8Smz9AdaptiveFiniteAccounting

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

abbrev CurrentPosition := SmzaRp05CurrentMaxAgreementRecovery.Position
abbrev CurrentQuery := SmzaRp05CurrentMaxAgreementRecovery.Query
abbrev CurrentCoefficients := SmzaRp05CurrentMaxAgreementRecovery.Coefficients
abbrev CurrentResponseRule := SmzaRp05CurrentMaxAgreementRecovery.ResponseRule
abbrev CurrentCommittedOracle := SmzaQ38OracleExtraction.CommittedOracle

def currentResponseRule406 (fpp : Payload) : CurrentResponseRule :=
  SmzaRp05TracePrefixes.sourceResponse fpp

def currentResponseSupport406 (oracle : CurrentCommittedOracle) (fpp : Payload)
    (coefficients : CurrentCoefficients) : Finset CurrentPosition :=
  responseSupport SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint 405
    (oracleData oracle) (oracleMasks oracle)
    (currentResponseRule406 fpp) coefficients

def currentSourceDecoder406 (oracle : CurrentCommittedOracle) (fpp : Payload)
    (coefficients : CurrentCoefficients) :
    Option (DecodedSource Goldilocks (Fin 5) 140) :=
  responseDecoder SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint 405
    (oracleData oracle) (oracleMasks oracle)
    (currentResponseRule406 fpp) coefficients

structure CurrentDecodedLvcsLabel406 where
  rows : SmzaQ38Recovery.RecoveredRows
  rowsDegree : ∀ row, (rows row).natDegree ≤ 405
  points : Fin 6 → Goldilocks
  claimedCoefficients : SmzaRp04ChronologicalAlgebra.Fixed406Coefficients

structure CurrentSourcePrefix406 where
  oracle : CurrentCommittedOracle
  response : CurrentResponseRule
  coefficients : CurrentCoefficients
  matrixGood : ¬ currentMatrixBad (oracleData oracle) (oracleMasks oracle) coefficients
  responseSupport : Finset CurrentPosition
  supportMatchesResponse : responseSupport =
    HegemonCrypto.SmallWood.V8Smz9McaDecoder.responseSupport
      SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint 405
      (oracleData oracle) (oracleMasks oracle) response coefficients
  supportLabel : Option SmallSupportLabel
  decodedLvcs : Option CurrentDecodedLvcsLabel406

def currentAcceptedFailure406 (label : CurrentSourcePrefix406) : Finset CurrentQuery :=
  currentAcceptedExtractionFailureEvent (oracleData label.oracle)
    (oracleMasks label.oracle) label.response label.coefficients

def currentFailureAt406 (label : CurrentSourcePrefix406) (query : CurrentQuery) : Prop :=
  query ∈ currentAcceptedFailure406 label

/-- On the good-matrix branch, current-map maximum-agreement failure can only
occur when the very response support encoded in this label is small; the
accepted q38 query is contained in that support. -/
theorem accepted_current_failure_is_small_support406
    (label : CurrentSourcePrefix406) (query : CurrentQuery)
    (failed : currentFailureAt406 label query) :
    ∃ supportLabel : SmallSupportLabel,
      supportLabel.support = label.responseSupport ∧ smallSupportBad supportLabel query := by
  have genericFailure : query ∈ decoderFailureEvent
      SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint 405 38
      (oracleData label.oracle) (oracleMasks label.oracle)
      label.response label.coefficients := by
    exact failed
  obtain bad | small := accepted_decoder_failure_implies_bad_matrix_or_small_support
    SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint
    SmzaRp05Q38CurrentRebinding.smz9_evaluation_point_injective 405 65536 38 (by decide)
    (oracleData label.oracle) (oracleMasks label.oracle)
    label.response label.coefficients query genericFailure
  · exact False.elim (label.matrixGood bad)
  · refine ⟨⟨label.responseSupport, ?_⟩, rfl, ?_⟩
    · rw [label.supportMatchesResponse]
      exact small.1
    · simpa [smallSupportBad, label.supportMatchesResponse] using small.2

def currentDecodedLvcsBad406 (label : CurrentDecodedLvcsLabel406)
    (query : CurrentQuery) : Prop :=
  (∀ row, (label.rows row).natDegree ≤ 405) ∧
    query ∈ currentLvcsBadQueryEvent label.rows label.points
      (claimedPolynomials label.claimedCoefficients)

def currentSourceBad406 (label : CurrentSourcePrefix406) (query : CurrentQuery) : Prop :=
  currentFailureAt406 label query ∨
    ∃ decoded, label.decodedLvcs = some decoded ∧ currentDecodedLvcsBad406 decoded query

attribute [local irreducible] V8Smz9McaDecoder.decodeSource
  V8Smz9McaDecoder.responseSupport

/-- Separate the small dependent option eliminator from the finite source
decoder. Its equations can be checked without normalizing the source table. -/
def currentDecodedLabelOfResult406
    (readOption : Unit → Option (DecodedSource Goldilocks (Fin 5) 140))
    (degree : ∀ source, readOption () = some source →
      ∀ row, (source.data row).natDegree ≤ 405)
    (points : Fin 6 → Goldilocks) (claimed : Fixed406Coefficients) :
    Option CurrentDecodedLvcsLabel406 :=
  match read : readOption () with
  | none => none
  | some source => some ⟨source.data, degree source read, points, claimed⟩

theorem current_decoded_label_of_result_success
    (readOption : Unit → Option (DecodedSource Goldilocks (Fin 5) 140))
    (degree : ∀ source, readOption () = some source →
      ∀ row, (source.data row).natDegree ≤ 405)
    (points : Fin 6 → Goldilocks) (claimed : Fixed406Coefficients)
    (source : DecodedSource Goldilocks (Fin 5) 140)
    (read : readOption () = some source) :
    ∃ label, currentDecodedLabelOfResult406 readOption degree points claimed = some label ∧
      label.rows = source.data ∧ label.points = points ∧
      label.claimedCoefficients = claimed := by
  unfold currentDecodedLabelOfResult406
  split
  · rename_i absent
    rw [read] at absent
    contradiction
  · rename_i candidate present
    refine ⟨_, rfl, ?_, rfl, rfl⟩
    exact congrArg DecodedSource.data (Option.some.inj (present.symm.trans read))

def currentSourcePrefix406 (oracle : CurrentCommittedOracle) (fpp : Payload)
    (coefficients : CurrentCoefficients) (points : Fin 6 → Goldilocks)
    (claimed : Fixed406Coefficients)
    (matrixGood : ¬ currentMatrixBad (oracleData oracle) (oracleMasks oracle) coefficients) :
    CurrentSourcePrefix406 := by
  classical
  let support := currentResponseSupport406 oracle fpp coefficients
  let supportLabel : Option SmallSupportLabel :=
    if small : support.card < 65536 then some ⟨support, small⟩ else none
  let decodedLvcs : Option CurrentDecodedLvcsLabel406 :=
    currentDecodedLabelOfResult406 (fun _ => currentSourceDecoder406 oracle fpp coefficients)
      (fun (source : DecodedSource Goldilocks (Fin 5) 140)
          (decoded : currentSourceDecoder406 oracle fpp coefficients = some source) =>
        (decoded_source_agrees_and_has_bounded_degree
          SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint
          SmzaRp05Q38CurrentRebinding.smz9_evaluation_point_injective 405 support
          (oracleData oracle) (oracleMasks oracle) source decoded).2.2.2)
      points claimed
  exact ⟨oracle, currentResponseRule406 fpp, coefficients, matrixGood,
    support, rfl, supportLabel, decodedLvcs⟩

theorem current_source_prefix_decoded_of_success
    (oracle : CurrentCommittedOracle) (fpp : Payload)
    (coefficients : CurrentCoefficients) (points : Fin 6 → Goldilocks)
    (claimed : Fixed406Coefficients)
    (matrixGood : ¬ currentMatrixBad (oracleData oracle) (oracleMasks oracle) coefficients)
    (source : DecodedSource Goldilocks (Fin 5) 140)
    (read : currentSourceDecoder406 oracle fpp coefficients = some source) :
    ∃ label, (currentSourcePrefix406 oracle fpp coefficients points claimed
      matrixGood).decodedLvcs = some label ∧ label.rows = source.data ∧
      label.points = points ∧ label.claimedCoefficients = claimed := by
  dsimp only [currentSourcePrefix406]
  apply current_decoded_label_of_result_success
  exact read

/-- Source-backed current prefix construction.  The current matrix test uses
the root rows, the coefficients come from earlier-role advice, and the q38
challenge is not an input to this labeler. -/
def currentSourcePrefixFromTrace406 (model : RelationModel)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (advice : EarlierTables model statement .decsSample)
    (trace : Trace) :
    Option CurrentSourcePrefix406 := by
  classical
  exact do
    let decs ← payload ns .decs trace
    let _ ← payload ns .piop (child trace 0)
    let fpp ← payload ns .fpp (child (child trace 0) 0)
    let coefficients ← advice .decsMatrix (by decide)
      (V8SmzaOracleParser.digestAt fpp.bytes 0)
    let opening ← advice .piopOpening (by decide)
      (V8SmzaOracleParser.digestAt decs.bytes 0)
    let oracle := rootOracle ns (child (child (child trace 0) 0) 0)
    if bad : currentMatrixBad (oracleData oracle) (oracleMasks oracle) coefficients then
      none
    else
      some (currentSourcePrefix406 oracle fpp coefficients
        (baseOpeningPoints opening.1) (queryCoefficients decs) bad)

def currentMatrixLabelOfResult406 (model : RelationModel) (statement : Statement)
    (readOption : Unit → Option (DecodedSource Goldilocks (Fin 5) 140)) :
    Option (MatrixPrefixKey (model.width statement)) :=
  (readOption ()).map fun source => ⟨model.recoveredCandidate statement source.data⟩

theorem current_matrix_label_of_result_success406
    (model : RelationModel) (statement : Statement)
    (readOption : Unit → Option (DecodedSource Goldilocks (Fin 5) 140))
    (source : DecodedSource Goldilocks (Fin 5) 140)
    (read : readOption () = some source) :
    currentMatrixLabelOfResult406 model statement readOption =
      some ⟨model.recoveredCandidate statement source.data⟩ := by
  simp only [currentMatrixLabelOfResult406, read, Option.map_some]

def currentOpeningLabelOfResult406 (model : RelationModel) (statement : Statement)
    (readOption : Unit → Option (DecodedSource Goldilocks (Fin 5) 140))
    (matrix : V8Smz9PiopSoundness.Matrix (model.width statement))
    (response : V8Smz9PiopSoundness.ClaimedTranscript) :
    Option (OpeningLabel (model.width statement)) :=
  (readOption ()).map fun source =>
    ⟨model.recoveredCandidate statement source.data, matrix, response⟩

theorem current_opening_label_of_result_success406
    (model : RelationModel) (statement : Statement)
    (readOption : Unit → Option (DecodedSource Goldilocks (Fin 5) 140))
    (matrix : V8Smz9PiopSoundness.Matrix (model.width statement))
    (response : V8Smz9PiopSoundness.ClaimedTranscript)
    (source : DecodedSource Goldilocks (Fin 5) 140)
    (read : readOption () = some source) :
    currentOpeningLabelOfResult406 model statement readOption matrix response =
      some ⟨model.recoveredCandidate statement source.data, matrix, response⟩ := by
  simp only [currentOpeningLabelOfResult406, read, Option.map_some]

/-- Current-map matrix candidate.  It is decoded from the exact FPP response
table using the earlier DECS-matrix coefficients and the 406 evaluation map.
-/
def currentMatrixLabelUsingDecoder406
    (decoder : CurrentCommittedOracle → Payload → CurrentCoefficients →
      Option (DecodedSource Goldilocks (Fin 5) 140))
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (advice : EarlierTables model statement .piopMatrix)
    (trace : Trace) : Option (MatrixPrefixKey (model.width statement)) := do
  let fpp ← payload ns .fpp trace
  let coefficients ← advice .decsMatrix (by decide)
    (V8SmzaOracleParser.digestAt fpp.bytes 0)
  currentMatrixLabelOfResult406 model statement
    (fun _ => decoder (rootOracle ns (child trace 0)) fpp coefficients)

def currentMatrixLabel406 (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (advice : EarlierTables model statement .piopMatrix)
    (trace : Trace) : Option (MatrixPrefixKey (model.width statement)) :=
  currentMatrixLabelUsingDecoder406 currentSourceDecoder406 model ns statement advice trace

/-- Current-map opening candidate.  Both the decoded source and the prior
matrix are read from their chronological role tables before the opening
output is selected.
-/
def currentOpeningLabelUsingDecoder406
    (decoder : CurrentCommittedOracle → Payload → CurrentCoefficients →
      Option (DecodedSource Goldilocks (Fin 5) 140))
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (advice : EarlierTables model statement .piopOpening)
    (trace : Trace) : Option (OpeningLabel (model.width statement)) := do
  let piop ← payload ns .piop trace
  let fpp ← payload ns .fpp (child trace 0)
  let coefficients ← advice .decsMatrix (by decide)
    (V8SmzaOracleParser.digestAt fpp.bytes 0)
  let matrix ← advice .piopMatrix (by decide)
    (V8SmzaOracleParser.digestAt piop.bytes 0)
  let oracle := rootOracle ns (child (child trace 0) 0)
  currentOpeningLabelOfResult406 model statement
    (fun _ => decoder oracle fpp coefficients) matrix (piopResponse piop)

def currentOpeningLabel406 (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (advice : EarlierTables model statement .piopOpening)
    (trace : Trace) : Option (OpeningLabel (model.width statement)) :=
  currentOpeningLabelUsingDecoder406 currentSourceDecoder406 model ns statement advice trace

def currentPrefixLabels406 (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (role : Role)
    (advice : EarlierTables model statement role) (trace : Trace) :
    Prefix (model.width statement) := by
  classical
  cases role with
  | decsMatrix =>
      exact { emptyLabels (model.width statement) with
        decsMatrix := some (rootOracle ns trace) }
  | piopMatrix =>
      exact { emptyLabels (model.width statement) with
        piopMatrix := currentMatrixLabel406 model ns statement advice trace }
  | piopOpening =>
      exact { emptyLabels (model.width statement) with
        piopOpening := currentOpeningLabel406 model ns statement advice trace }
  | decsSample =>
      exact match currentSourcePrefixFromTrace406 model ns statement advice trace with
      | none => emptyLabels (model.width statement)
      | some sourceLabel =>
          { emptyLabels (model.width statement) with
            smallSupport := sourceLabel.supportLabel
            lvcs := sourceLabel.decodedLvcs.map fun label =>
              ⟨label.rows, label.points, label.claimedCoefficients⟩ }

def currentRoleLabels406 (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (role : Role) (advice : AllEarlierTables model role)
    (trace : Trace) : TypedPrefixLabel model.width :=
  .decoded statement (currentPrefixLabels406 model ns statement role
    (advice statement) trace)

def currentRoleLabelsFromBytes406 (model : RelationModel)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (role : Role) (advice : AllEarlierTables model role) (statementBytes : List Byte)
    (trace : Trace) : TypedPrefixLabel model.width :=
  match statementOfBytes? statementBytes with
  | none => .unavailable
  | some statement => currentRoleLabels406 model ns statement role advice trace

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentTracePrefixes406
