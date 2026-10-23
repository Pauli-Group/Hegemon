import HegemonCrypto.NativePrivateSpendQ58CurrentRecoveryGeometry
import HegemonCrypto.NativePrivateSpendQ58CurrentRoleClassifier

/-! Current source candidates from literal pre-PIOP-matrix material.
The root's current raw extraction trace, prior FPP raw input and DECS gamma
are the entire decoder label. No sampled DECS positions, PIOP matrix,
opening checks, supplied candidate or desired relation witness enters its
construction. Ordinary PCS execution derives equality with its calculated
source. Earlier-source timing is an explicit changed/missing-label outcome.
This source proposal has no compiler receipt and asserts no physical mass. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSourceCandidate

open Polynomial V8Smz9McaRecovery V8Smz9McaDecoder
open SmzaRp05ExecutableMerkleVerifier (Program Oracle Log)
open SmzaRp05ExecutableChallengeStage (FieldWord returnedWords scan)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRecordedTracePath (readPath RecordsCollisionFree)
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Wire DecodedFields Opening PcsOutput Transcript ExecutionStages
   gammaRows fieldKeys fieldXof pcsProgram canonicalOpening matrixProgram
   transcriptProgram verifierProgram reconstruct finalize finalInput
   accepted_execution_has_stages)
end E
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope
  (RawInput RawDigest Trace rawNext rawPayload)
end F
namespace L
export NativePrivateSpendQ58CurrentAcceptedLeafSupport
  (currentPoint priorLegacy priorData priorMasks actualCoefficients)
end L
namespace O
export NativePrivateSpendQ58CurrentOrdinaryRecovery (actualView pcs_current_point_injective)
end O
namespace R
export NativePrivateSpendQ58CurrentRecovery (SourceResponseView decoded support)
end R
namespace RR
export NativePrivateSpendQ58CurrentRetainedResponseReadback
  (Response priorInput priorResponseRule responseOfRaw priorResponse)
end RR
namespace G
export NativePrivateSpendQ58CurrentRecoveryGeometry (RecoveryGeometry MatrixBad SmallSupportBad pcs_execution_has_geometry_or_named_bad_event)
end G

abbrev Position := Fin 8388608
abbrev Source := DecodedSource Goldilocks (Fin 5) 140

/-- Complete current raw material needed by the calculated decoder.
The trace preserves every raw current leaf and its parse; responseInput is
an optional literal raw hash preimage. The coefficients are DECS gamma,
which belongs to another role when selecting either PIOP challenge. -/
structure SourceLabel where
  rootTrace : F.Trace
  responseInput : Option F.RawInput
  gamma : List (List FieldWord)

/-- Missing raw input has a total algebraic interpretation, retained as an
explicit event below. It is never interpreted as an available prior stage. -/
def labelLegacy (label : SourceLabel) (position : Position) : F.RawInput :=
  ((readPath (0 :: SmzaRp05FilteredReadback.indexPath position 23)
    label.rootTrace).bind fun raw =>
      (F.rawPayload raw).map fun payload => payload.bytes.drop 616).getD []

def labelData (label : SourceLabel) : Nat → Position → Goldilocks :=
  fun column position => if column < 140 then
    V8Smz9OracleExtraction.wordToGoldilocks
      (SmzaRp05TracePrefixes.fieldWordAt (labelLegacy label position) (14 + column))
  else 0

def labelMasks (label : SourceLabel) : Fin 5 → Position → Goldilocks :=
  fun row position => V8Smz9OracleExtraction.wordToGoldilocks
    (SmzaRp05TracePrefixes.fieldWordAt (labelLegacy label position) (155 + row.val))

def labelView (label : SourceLabel) : R.SourceResponseView Goldilocks where
  data := labelData label
  masks := labelMasks label
  response := fun _ => RR.responseOfRaw (label.responseInput.getD [])
  coefficients := L.actualCoefficients label.gamma

def calculatedCandidate (label : SourceLabel) : Option Source :=
  R.decoded L.currentPoint (labelView label)

def calculatedSupport (label : SourceLabel) : Finset Position :=
  R.support L.currentPoint (labelView label)

/-- Reading the committed source table and FPP response inspects no later
query. Root and FPP are literal digest targets, not candidate witnesses. -/
def labelFromInputs (records : RawRecords) (root fpp : F.RawDigest)
    (gamma : List (List FieldWord)) : SourceLabel where
  rootTrace := extract F.rawNext records 25 .root root
  responseInput := RR.priorInput records fpp
  gamma := gamma

/-- Literal-key agreement preserves the capped scan, including exhaustion
and every rejected field word. No successful-sampling premise is needed. -/
theorem scan_congr_on_keys (left right : Oracle) (requested : Nat)
    (accumulated : List FieldWord) (inputs : List F.RawInput)
    (same : ∀ input ∈ inputs, left input = right input) :
    scan left requested accumulated inputs = scan right requested accumulated inputs := by
  induction inputs generalizing accumulated with
  | nil => rfl
  | cons input rest ih =>
      by_cases enough : requested ≤ accumulated.length
      · simp only [scan, if_pos enough]
      · simp only [scan, if_neg enough]
        rw [same input (List.mem_cons_self)]
        exact ih _ (fun key member => same key (List.mem_cons_of_mem _ member))

/-- Actual other-role DECS sampling. Its result does not use a PCS opening,
DECS sample, reconstructed rows, PIOP matrix or accepted-proof premise. -/
def gammaAt (oracle : Oracle) (root : F.RawDigest) : List (List FieldWord) :=
  E.gammaRows (returnedWords 700 (scan oracle 700 [] (E.fieldKeys .decsMatrix 700 root)))

def labelAt (records : RawRecords) (oracle : Oracle) (root fpp : F.RawDigest) : SourceLabel :=
  labelFromInputs records root fpp (gammaAt oracle root)

theorem label_from_inputs_is_actual_view
    (records : RawRecords) (output : E.PcsOutput) :
    labelView (labelFromInputs records output.root output.hashFpp output.gamma) =
      O.actualView records output := rfl

/-- Only the actual92 capped DECS-matrix raw keys determine gamma.
The parent physical-fiber transport can derive this literal-key agreement
from fixed other-role vector cells. Unrecognized source-hash keys are not
included here and are not incorrectly declared fixed. -/
theorem gamma_at_congr_on_current_decs_keys (left right : Oracle) (root : F.RawDigest)
    (same : ∀ input ∈ E.fieldKeys .decsMatrix 700 root, left input = right input) :
    gammaAt left root = gammaAt right root := by
  unfold gammaAt
  rw [scan_congr_on_keys left right 700 [] (E.fieldKeys .decsMatrix 700 root) same]

/-- With literal raw source records held fixed, all selected PIOP oracle
answers may change while the candidate label remains identical, provided
only the92 other-role DECS keys agree. The source hashes themselves remain
live and are handled by the raw-record change event. -/
theorem label_at_congr_on_current_decs_keys
    (records : RawRecords) (left right : Oracle) (root fpp : F.RawDigest)
    (same : ∀ input ∈ E.fieldKeys .decsMatrix 700 root, left input = right input) :
    labelAt records left root fpp = labelAt records right root fpp := by
  unfold labelAt
  rw [gamma_at_congr_on_current_decs_keys left right root same]

/-- Equality is derived from the ordinary PCS program, including its actual
other-role field-XOF result. No view equality or candidate is a premise. -/
theorem pcs_execution_gamma_is_label_gamma
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace) (pending : Bool)
    (wire : E.Wire) (decoded : E.DecodedFields) (opening : E.Opening)
    (oracle : Oracle) (output : E.PcsOutput)
    (executed : (E.pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    gammaAt oracle output.root = output.gamma := by
  obtain ⟨_openingDigest, _sampledPending, sampled, _heads, _hash,
    _query, _points, _rows, _input, _merkle, gammaExecuted, gammaEq, _restore, _fpp, _pending⟩ :=
    NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts
      ns pending wire decoded opening oracle output executed
  have sampledEq : scan oracle 700 [] (E.fieldKeys .decsMatrix 700 output.root) = sampled :=
    Option.some.inj (by
      simpa only [E.fieldXof,
        SmzaRp05ExecutableChallengeStage.field_loop_executes_scan] using gammaExecuted)
  simpa only [gammaAt, sampledEq] using gammaEq

theorem pcs_execution_label_is_actual_view
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace) (pending : Bool)
    (wire : E.Wire) (decoded : E.DecodedFields) (opening : E.Opening)
    (oracle : Oracle) (output : E.PcsOutput) (records : RawRecords)
    (executed : (E.pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    labelView (labelAt records oracle output.root output.hashFpp) =
      O.actualView records output := by
  have gammaEq := pcs_execution_gamma_is_label_gamma ns pending wire decoded opening
    oracle output executed
  unfold labelAt
  rw [gammaEq]
  exact label_from_inputs_is_actual_view records output

/-- The actual current calculated decoder is precisely the candidate chosen
from the three literal label inputs. No final58 sample is needed to construct
this value; sampled readback is used elsewhere to justify acceptance support. -/
theorem pcs_execution_candidate_is_label_candidate
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace) (pending : Bool)
    (wire : E.Wire) (decoded : E.DecodedFields) (opening : E.Opening)
    (oracle : Oracle) (output : E.PcsOutput) (records : RawRecords)
    (executed : (E.pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    calculatedCandidate (labelAt records oracle output.root output.hashFpp) =
      R.decoded L.currentPoint (O.actualView records output) := by
  unfold calculatedCandidate
  rw [pcs_execution_label_is_actual_view ns pending wire decoded opening oracle output records executed]

theorem pcs_execution_support_is_label_support
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace) (pending : Bool)
    (wire : E.Wire) (decoded : E.DecodedFields) (opening : E.Opening)
    (oracle : Oracle) (output : E.PcsOutput) (records : RawRecords)
    (executed : (E.pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    calculatedSupport (labelAt records oracle output.root output.hashFpp) =
      R.support L.currentPoint (O.actualView records output) := by
  unfold calculatedSupport
  rw [pcs_execution_label_is_actual_view ns pending wire decoded opening oracle output records executed]

/-- Literal earlier cut and later readback disagree in exactly one or more
actual decoder inputs. This is an event to charge; it is not a fixed-table
hypothesis. Gamma remains explicit because raw source hashes are live under
current role conditioning even when DECS-vector cells are fixed. -/
def LabelChanged (earlier later : SourceLabel) : Prop :=
  earlier.rootTrace ≠ later.rootTrace ∨
  earlier.responseInput ≠ later.responseInput ∨ earlier.gamma ≠ later.gamma

def MissingResponse (label : SourceLabel) : Prop := label.responseInput = none

def MissingRoot (label : SourceLabel) : Prop := label.rootTrace = .missing

def SourceUnavailable (label : SourceLabel) : Prop :=
  MissingResponse label ∨ MissingRoot label

theorem equal_label_or_literal_input_change (earlier later : SourceLabel) :
    earlier = later ∨ LabelChanged earlier later := by
  by_cases root : earlier.rootTrace = later.rootTrace
  · by_cases response : earlier.responseInput = later.responseInput
    · by_cases gamma : earlier.gamma = later.gamma
      · left
        cases earlier; cases later
        simp_all
      · exact Or.inr (Or.inr (Or.inr gamma))
    · exact Or.inr (Or.inr (Or.inl response))
  · exact Or.inr (Or.inl root)

/-- The good arm binds the actual calculated source to the earlier literal
label. Missing stages and changed source material remain explicit outcomes.
The theorem has no pre-query candidate or whole-view binding callback. -/
theorem geometry_source_is_cut_candidate_or_named_label_event
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace) (pending : Bool)
    (wire : E.Wire) (decoded : E.DecodedFields) (opening : E.Opening)
    (oracle : Oracle) (output : E.PcsOutput) (later earlier : RawRecords)
    (cutOracle : Oracle)
    (executed : (E.pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (geometry : G.RecoveryGeometry ns wire decoded opening output later) :
    SourceUnavailable (labelAt earlier cutOracle output.root output.hashFpp) ∨
      LabelChanged (labelAt earlier cutOracle output.root output.hashFpp)
        (labelAt later oracle output.root output.hashFpp) ∨
      calculatedCandidate (labelAt earlier cutOracle output.root output.hashFpp) =
        some geometry.source := by
  by_cases unavailable : SourceUnavailable (labelAt earlier cutOracle output.root output.hashFpp)
  · exact Or.inl unavailable
  · rcases equal_label_or_literal_input_change
      (labelAt earlier cutOracle output.root output.hashFpp)
      (labelAt later oracle output.root output.hashFpp) with equal | changed
    · right; right
      rw [equal, pcs_execution_candidate_is_label_candidate ns pending wire decoded opening
        oracle output later executed]
      exact geometry.calculated
    · exact Or.inr (Or.inl changed)

/-- A common support larger than the degree identifies any bounded source
word uniquely. Different response supports need not identify the same source;
this theorem states the precise common-support law used by the decoder. -/
theorem bounded_source_components_unique_on_common_support
    (point : Position → Goldilocks) (injective : Function.Injective point)
    (support : Finset Position) (large : 13172 < support.card)
    (data : Nat → Position → Goldilocks) (masks : Fin 5 → Position → Goldilocks)
    (left right : Source)
    (leftMasks : ∀ row, (left.masks row).natDegree ≤ 13172)
    (leftData : ∀ column, (left.data column).natDegree ≤ 13172)
    (rightMasks : ∀ row, (right.masks row).natDegree ≤ 13172)
    (rightData : ∀ column, (right.data column).natDegree ≤ 13172)
    (leftAgrees : CandidateAgrees point support data masks left)
    (rightAgrees : CandidateAgrees point support data masks right) :
    (∀ row, left.masks row = right.masks row) ∧
      ∀ column, left.data column = right.data column := by
  constructor
  · intro row
    have first := decode_word_equals_any_codeword point injective 13172 support
      (masks row) large (left.masks row) (leftMasks row) (leftAgrees.1 row)
    have second := decode_word_equals_any_codeword point injective 13172 support
      (masks row) large (right.masks row) (rightMasks row) (rightAgrees.1 row)
    exact first.symm.trans second
  · intro column
    have first := decode_word_equals_any_codeword point injective 13172 support
      (data column.val) large (left.data column) (leftData column) (leftAgrees.2 column)
    have second := decode_word_equals_any_codeword point injective 13172 support
      (data column.val) large (right.data column) (rightData column) (rightAgrees.2 column)
    exact first.symm.trans second

/-- The actual verifier prefix ending at the completed PCS output. -/
def preMatrixLog (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle)
    (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire oracle transcript) : Log :=
  ((E.canonicalOpening pending nonce wire.hPiop).record oracle).2 ++
    ((E.pcsProgram ns stages.openingPending wire stages.decoded stages.opening).record oracle).2

/-- Successful stages reproduce the actual transcript execution. -/
theorem stages_transcript_execution
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle)
    (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire oracle transcript) :
    (E.transcriptProgram ns relation pending nonce wire).eval oracle = some transcript := by
  simp only [E.transcriptProgram, stages.decodedEq, Program.eval_bind,
    stages.openingExecuted, Option.bind_some, stages.pcsExecuted,
    stages.matrixExecuted, Program.eval]
  exact congrArg some stages.reconstructed

/-- Exact instrumentation places the literal pre-matrix prefix before the
same execution's matrix reads. No independent log is supplied. -/
theorem stages_transcript_has_pre_matrix_log
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle)
    (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire oracle transcript) :
    ((E.transcriptProgram ns relation pending nonce wire).record oracle).2 =
      preMatrixLog ns relation pending nonce wire oracle transcript stages ++
        ((E.matrixProgram stages.pcs.pending stages.pcs.hashFpp).record oracle).2 := by
  simp only [E.transcriptProgram, stages.decodedEq]
  rw [Program.record_bind_success oracle (E.canonicalOpening pending nonce wire.hPiop)
    _ (stages.opening, stages.openingPending) stages.openingExecuted]
  simp only []
  rw [Program.record_bind_success oracle
    (E.pcsProgram ns stages.openingPending wire stages.decoded stages.opening)
    _ stages.pcs stages.pcsExecuted]
  simp only []
  rw [Program.record_bind_success oracle
    (E.matrixProgram stages.pcs.pending stages.pcs.hashFpp)
    _ (stages.matrix, stages.finalPending) stages.matrixExecuted]
  simp only [Program.record, List.append_nil, preMatrixLog, List.append_assoc]

/-- The same literal prefix remains in the full ordinary verifier log.
This is verifier chronology, not a substitute for an earlier adversarial
selected-role cut; the latter keeps LabelChanged and missing-stage arms. -/
theorem stages_verifier_has_pre_matrix_log
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle)
    (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire oracle transcript) :
    ((E.verifierProgram ns relation pending nonce wire).record oracle).2 =
      preMatrixLog ns relation pending nonce wire oracle transcript stages ++
        (((E.matrixProgram stages.pcs.pending stages.pcs.hashFpp).record oracle).2 ++
          ((E.finalize wire.hPiop transcript).record oracle).2) := by
  have execution := stages_transcript_execution ns relation pending nonce wire oracle transcript stages
  unfold E.verifierProgram
  rw [Program.record_bind_success oracle
    (E.transcriptProgram ns relation pending nonce wire) (E.finalize wire.hPiop)
    transcript execution]
  simp only []
  rw [stages_transcript_has_pre_matrix_log ns relation pending nonce wire oracle transcript stages]
  exact List.append_assoc _ _ _

/-- The ordinary source inputs are fixed when the verifier reaches its own
PIOP matrix. This does not claim that a producer prefix precedes every earlier
adversarial role query. Those cuts use the literal event partition above. -/
theorem accepted_execution_has_pre_matrix_candidate
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire)
    (oracle : Oracle) (records : RawRecords)
    (accepted : (E.verifierProgram ns relation pending nonce wire).eval oracle = some ()) :
    ∃ transcript, ∃ stages : E.ExecutionStages ns relation pending nonce wire oracle transcript,
      transcript.pending = false ∧ oracle (E.finalInput transcript) = wire.hPiop ∧
      labelView (labelAt records oracle stages.pcs.root stages.pcs.hashFpp) =
        O.actualView records stages.pcs ∧
      calculatedCandidate (labelAt records oracle stages.pcs.root stages.pcs.hashFpp) =
        R.decoded L.currentPoint (O.actualView records stages.pcs) ∧
      (E.matrixProgram stages.pcs.pending stages.pcs.hashFpp).eval oracle =
        some (stages.matrix, stages.finalPending) := by
  obtain ⟨transcript, ⟨stages⟩, clean, finalHash, _⟩ :=
    E.accepted_execution_has_stages ns relation pending nonce wire oracle accepted
  exact ⟨transcript, stages, clean, finalHash,
    pcs_execution_label_is_actual_view ns stages.openingPending wire stages.decoded
      stages.opening oracle stages.pcs records stages.pcsExecuted,
    pcs_execution_candidate_is_label_candidate ns stages.openingPending wire stages.decoded
      stages.opening oracle stages.pcs records stages.pcsExecuted, stages.matrixExecuted⟩

/-- Ordinary acceptance, with no supplied recovery geometry or candidate,
derives either an actual earlier-cut source candidate or literal current
recovery/chronology failures. This is the interface for the parent selected-
role physical bound; it does not itself assign probability to any arm. -/
theorem accepted_current_execution_has_cut_candidate_or_named_current_event
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire)
    (oracle cutOracle : Oracle) (later earlier : RawRecords)
    (accepted : (E.verifierProgram ns relation pending nonce wire).eval oracle = some ()) :
    ∃ transcript, ∃ stages : E.ExecutionStages ns relation pending nonce wire oracle transcript,
      transcript.pending = false ∧ oracle (E.finalInput transcript) = wire.hPiop ∧
      (NativePrivateSpendQ58CurrentOrdinaryRecovery.PriorBad ns stages.decoded oracle
        stages.pcs later ∨
       G.MatrixBad later stages.pcs ∨ G.SmallSupportBad later stages.pcs ∨
       SourceUnavailable (labelAt earlier cutOracle stages.pcs.root stages.pcs.hashFpp) ∨
       LabelChanged (labelAt earlier cutOracle stages.pcs.root stages.pcs.hashFpp)
         (labelAt later oracle stages.pcs.root stages.pcs.hashFpp) ∨
       ∃ geometry : G.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs later,
         calculatedCandidate (labelAt earlier cutOracle stages.pcs.root stages.pcs.hashFpp) =
           some geometry.source) := by
  obtain ⟨transcript, ⟨stages⟩, clean, finalHash, _⟩ :=
    E.accepted_execution_has_stages ns relation pending nonce wire oracle accepted
  have pcsClean := NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
    ns relation pending nonce wire oracle transcript stages clean
  refine ⟨transcript, stages, clean, finalHash, ?_⟩
  rcases G.pcs_execution_has_geometry_or_named_bad_event ns stages.openingPending wire
      stages.decoded stages.opening oracle stages.pcs later stages.pcsExecuted pcsClean with
    priorBad | matrixBad | smallBad | ⟨geometry⟩
  · exact Or.inl priorBad
  · exact Or.inr (Or.inl matrixBad)
  · exact Or.inr (Or.inr (Or.inl smallBad))
  · rcases geometry with ⟨geometry⟩
    rcases geometry_source_is_cut_candidate_or_named_label_event ns stages.openingPending
        wire stages.decoded stages.opening oracle stages.pcs later earlier cutOracle
        stages.pcsExecuted geometry with unavailable | changed | candidate
    · exact Or.inr (Or.inr (Or.inr (Or.inl unavailable)))
    · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl changed))))
    · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr ⟨geometry, candidate⟩))))

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSourceCandidate
