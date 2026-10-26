import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedLeafSupport
import HegemonCrypto.NativePrivateSpendQ58CurrentPointGeometry
import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalCount
import SmzaRp05ExecutableMerklePaths

/-! Current ordinary PCS recovery from the literal executed program.
The earlier records are the actual producer record, never a certificate or
whole-view binding callback. Missing raw response/path preimages and collisions
remain named alternatives. This file proves deterministic inclusion and finite
current counts only; it does not silently assign mass to missing/late records.
SOURCE ONLY: compilation and physical mass qualification remain pending. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOrdinaryRecovery

open SmzaRp05ExecutableMerkleVerifier (Program Oracle Log)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree RecordedPath)
open NativePrivateSpendQ58CurrentExecutableVerifier
open V8Smz9McaRecovery V8Smz9McaDecoder NativeHtlcUniversalMatrix
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

namespace L
export NativePrivateSpendQ58CurrentAcceptedLeafSupport
  (currentPoint priorData priorMasks actualCoefficients merkle_input_actual_fields
   PriorSupportOutcome pcs_execution_has_prior_support_or_named_bad_arm
   accepted_current_execution_has_prior_support_or_named_bad_arm)
end L
namespace R
export NativePrivateSpendQ58CurrentRecovery
  (SourceResponseView support decoded WholeResponseRecovered)
end R
namespace RR
export NativePrivateSpendQ58CurrentRetainedResponseReadback
  (sourceHashProgram priorResponseRule)
end RR
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (rawNext)
end F
namespace M
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace encodeLeaf)
end M

abbrev Position := Fin 8388608

def actualView (prior : RawRecords) (output : PcsOutput) : R.SourceResponseView Goldilocks where
  data := L.priorData prior output.root
  masks := L.priorMasks prior output.root
  response := RR.priorResponseRule prior output.hashFpp
  coefficients := L.actualCoefficients output.gamma

def actualSample (coordinates : Fin 58 → Position)
    (distinct : Function.Injective coordinates) : QuerySample Position 58 :=
  ⟨Finset.univ.image coordinates, by
    rw [Finset.card_image_of_injective _ distinct, Finset.card_univ, Fintype.card_fin]⟩

/-- Literal failures produced by current raw readback. No premise discards
an unavailable stage or a path which was only hashed after its role cut. -/
def PriorBad (ns : M.Namespace) (decoded : DecodedFields) (oracle : Oracle)
    (output : PcsOutput) (prior : RawRecords) : Prop :=
  (¬ ∃ raw, (raw, output.hashFpp) ∈ prior) ∨
  (¬ RecordsCollisionFree (prior ∪
    ((RR.sourceHashProgram (SmzaRp05ExecutableChallengeStage.digestWords output.root)
      decoded.decs
      (output.rows.map fun values => values.map SmzaRp05ExecutableRestore.toWord)
      output.gamma (output.decsPoints.map SmzaRp05ExecutableRestore.toWord)
      (List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val)).record
        oracle).2.toFinset)) ∨
  (¬ RecordsCollisionFree prior) ∨
  ∃ coordinates : Fin 58 → Position,
    Function.Injective coordinates ∧
    (∀ j, (coordinates j).val = output.indexes.getD j.val 0) ∧
    ∃ j, ¬ RecordedPath F.rawNext prior .root output.root
      (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
      (M.encodeLeaf output.input.binding (output.input.payloads j))

/-- Success of the actual point-map supplies the current nonzero shift and
root-order geometry. No shift or point-injectivity law is an input. -/
theorem pcs_current_point_injective
    (ns : M.Namespace) (pending : Bool) (wire : Wire) (decoded : DecodedFields)
    (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (coordinates : Fin 58 → Position)
    (indicesEq : ∀ j, (coordinates j).val = output.indexes.getD j.val 0) :
    Function.Injective L.currentPoint := by
  obtain ⟨_, sampledPending, _, _, _, _, pointsEq, _, inputEq, _⟩ :=
    NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts
      ns pending wire decoded opening oracle output executed
  have shape := L.merkle_input_actual_fields wire.salt ns.binding sampledPending
    output.indexes output.rows decoded.decs.maskingEvals wire.tapes wire.paths
    output.input inputEq
  obtain ⟨_, pointAt⟩ := SmzaRp05ExecutablePcsClosureLvcsAlgebra.mapM_success_entry
    output.indexes (SmzaRp05DecsPointProjection.fieldPoint 13173)
    output.decsPoints 0 0 pointsEq
  have first := pointAt 0 (by rw [shape.2.2.1]; decide)
  have indexZero : (coordinates (0 : Fin 58)).val = output.indexes.getD 0 0 := indicesEq 0
  have firstAt : SmzaRp05DecsPointProjection.fieldPoint 13173 (coordinates 0).val =
      some (output.decsPoints.getD 0 0) :=
    (congrArg (SmzaRp05DecsPointProjection.fieldPoint 13173) indexZero).trans first
  exact NativePrivateSpendQ58CurrentPointGeometry.field_point_getter_injective_from_one_success
    (coordinates 0) (output.decsPoints.getD 0 0) firstAt

section SupportedSampleProof

attribute [local irreducible] Finset.univ Finset.filter V8Smz9McaRecovery.querySampleFintype

/-- The decoder is run on the computed current source/response view. This
uses no observed-view equality or accepted-query-binding callback. -/
theorem supported_sample_recovers_or_matrix_or_small_support
    (view : R.SourceResponseView Goldilocks)
    (injective : Function.Injective L.currentPoint)
    (coordinates : Fin 58 → Position) (distinct : Function.Injective coordinates)
    (supported : Finset.univ.image coordinates ⊆ R.support L.currentPoint view) :
    R.WholeResponseRecovered L.currentPoint view ∨
      BadMatrix L.currentPoint 13172 360448 view.data view.masks view.coefficients ∨
      ((R.support L.currentPoint view).card < 360448 ∧
        (actualSample coordinates distinct).val ⊆ R.support L.currentPoint view) := by
  cases result : R.decoded L.currentPoint view with
  | some candidate =>
      apply Or.inl
      have calculated : responseDecoder L.currentPoint 13172 view.data view.masks
          view.response view.coefficients = some candidate := result
      have recovered := decoded_source_agrees_and_has_bounded_degree L.currentPoint
        injective 13172 (R.support L.currentPoint view) view.data view.masks candidate calculated
      refine ⟨candidate, result, ?_, recovered.2.1, recovered.2.2.1,
        recovered.2.2.2, ?_⟩
      · exact interpolation_nodes_card 13172 _ recovered.1
      · intro row
        exact decoded_response_equals_projection L.currentPoint injective 13172
          view.data view.masks view.response view.coefficients candidate calculated row
  | none =>
      apply Or.inr
      have failure : actualSample coordinates distinct ∈
          decoderFailureEvent L.currentPoint 13172 58 view.data view.masks
            view.response view.coefficients := by
        change actualSample coordinates distinct ∈
          Finset.univ.filter (fun query : QuerySample Position 58 =>
            query.val ⊆ responseSupport L.currentPoint 13172 view.data view.masks
              view.response view.coefficients ∧
            responseDecoder L.currentPoint 13172 view.data view.masks
              view.response view.coefficients = none)
        exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, ⟨supported, result⟩⟩
      exact accepted_decoder_failure_implies_bad_matrix_or_small_support
        L.currentPoint injective 13172 360448 58 (by decide) view.data view.masks
        view.response view.coefficients (actualSample coordinates distinct) failure

end SupportedSampleProof

/-- Every ordinary PCS success has one exact current recovery or literal
bad alternative. All dimensions, tables, response, coefficients and query
positions come from this same execution and its raw readback. -/
theorem pcs_execution_recovers_or_named_current_event
    (ns : M.Namespace) (pending : Bool) (wire : Wire) (decoded : DecodedFields)
    (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (clean : output.pending = false) (prior : RawRecords) :
    PriorBad ns decoded oracle output prior ∨
    R.WholeResponseRecovered L.currentPoint (actualView prior output) ∨
    BadMatrix L.currentPoint 13172 360448
      (actualView prior output).data (actualView prior output).masks
      (actualView prior output).coefficients ∨
    ∃ coordinates : Fin 58 → Position, ∃ distinct : Function.Injective coordinates,
      (∀ j, (coordinates j).val = output.indexes.getD j.val 0) ∧
      (R.support L.currentPoint (actualView prior output)).card < 360448 ∧
      (actualSample coordinates distinct).val ⊆
        R.support L.currentPoint (actualView prior output) := by
  have outcome := L.pcs_execution_has_prior_support_or_named_bad_arm
    ns pending wire decoded opening oracle output executed clean prior
  rcases outcome with absent | collision | collision | ⟨coordinates, distinct, indicesEq, paths⟩
  · exact Or.inl (Or.inl absent)
  · exact Or.inl (Or.inr (Or.inl collision))
  · exact Or.inl (Or.inr (Or.inr (Or.inl collision)))
  · rcases paths with missing | supported
    · exact Or.inl (Or.inr (Or.inr (Or.inr ⟨coordinates, distinct, indicesEq, missing⟩)))
    · have injective := pcs_current_point_injective ns pending wire decoded opening
        oracle output executed coordinates indicesEq
      have result := supported_sample_recovers_or_matrix_or_small_support
        (actualView prior output) injective coordinates distinct supported
      rcases result with recovered | matrix | small
      · exact Or.inr (Or.inl recovered)
      · exact Or.inr (Or.inr (Or.inl matrix))
      · exact Or.inr (Or.inr (Or.inr ⟨coordinates, distinct, indicesEq, small⟩))

/-- This is an actual source prefix: the record of the producer which
created this wire, before the ordinary verifier. It contains failed raw
requests too and does not inspect an accepted witness or future query. -/
def producerPrior (producer : Program Wire) (oracle : Oracle) : RawRecords :=
  (producer.record oracle).2.toFinset

theorem producer_record_is_actual_prefix
    (producer : Program Wire) (oracle : Oracle) (wire : Wire)
    (success : producer.eval oracle = some wire)
    (continuation : Wire → Program Unit) :
    ((producer.bind continuation).record oracle).2 =
      (producer.record oracle).2 ++ ((continuation wire).record oracle).2 := by
  exact congrArg Prod.snd (Program.record_bind_success oracle producer continuation wire success)

/-- The producer and verifier run against the same oracle. Acceptance supplies
the wire and clean stages. No cut, stage record, whole-view equality, decoder
certificate or satisfying assignment occurs in this theorem's premises. -/
theorem accepted_producer_verifier_has_actual_prefix_and_current_recovery_event
    (producer : Program Wire) (ns : M.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (oracle : Oracle)
    (accepted : (producer.bind (verifierProgram ns relation pending nonce)).eval oracle = some ()) :
    ∃ wire, producer.eval oracle = some wire ∧
      ((producer.bind (verifierProgram ns relation pending nonce)).record oracle).2 =
        (producer.record oracle).2 ++
          ((verifierProgram ns relation pending nonce wire).record oracle).2 ∧
      ∃ transcript, ∃ stages : ExecutionStages ns relation pending nonce wire oracle transcript,
        transcript.pending = false ∧ oracle (finalInput transcript) = wire.hPiop ∧
        (PriorBad ns stages.decoded oracle stages.pcs (producerPrior producer oracle) ∨
         R.WholeResponseRecovered L.currentPoint (actualView (producerPrior producer oracle) stages.pcs) ∨
         BadMatrix L.currentPoint 13172 360448
           (actualView (producerPrior producer oracle) stages.pcs).data
           (actualView (producerPrior producer oracle) stages.pcs).masks
           (actualView (producerPrior producer oracle) stages.pcs).coefficients ∨
         ∃ coordinates : Fin 58 → Position, ∃ distinct : Function.Injective coordinates,
           (∀ j, (coordinates j).val = stages.pcs.indexes.getD j.val 0) ∧
           (R.support L.currentPoint (actualView (producerPrior producer oracle) stages.pcs)).card < 360448 ∧
           (actualSample coordinates distinct).val ⊆
             R.support L.currentPoint (actualView (producerPrior producer oracle) stages.pcs)) := by
  obtain ⟨wire, produced, verifierAccepted⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle producer
      (verifierProgram ns relation pending nonce) () accepted
  obtain ⟨transcript, ⟨stages⟩, clean, digestEq, _⟩ :=
    accepted_execution_has_stages ns relation pending nonce wire oracle verifierAccepted
  have pcsClean := NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
    ns relation pending nonce wire oracle transcript stages clean
  refine ⟨wire, produced, producer_record_is_actual_prefix producer oracle wire produced _,
    transcript, stages, clean, digestEq, ?_⟩
  exact pcs_execution_recovers_or_named_current_event ns stages.openingPending wire
    stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted pcsClean
    (producerPrior producer oracle)

section CurrentMatrixCountProof

attribute [local irreducible] NativeHtlcUniversalMatrix.badMatrices Finset.card Fintype.card

/-- Exact finite current matrix count. The prior tables may be arbitrary;
no polynomial source-validity premise or line-count callback is supplied. -/
theorem current_matrix_event_card
    (point : Position → Goldilocks) (injective : Function.Injective point)
    (data : Nat → Position → Goldilocks) (masks : Fin 5 → Position → Goldilocks) :
    (badMatrices point 13172 360448 data masks 140).card *
        Fintype.card (Fin 5 → Goldilocks) ≤
      Fintype.card (NativePrivateSpendQ58CurrentRecovery.Coefficients Goldilocks) *
        (140 * 16445033384594) := by
  have bound :
      (badMatrices point 13172 360448 data masks 140).card *
          Fintype.card (Fin 5 → Goldilocks) ≤
        Fintype.card (NativePrivateSpendQ58CurrentRecovery.Coefficients Goldilocks) *
          (140 * 16445033384594) :=
    NativePrivateSpendQ58CurrentGlobalCount.matrix_card_bound point injective data masks
  exact bound

end CurrentMatrixCountProof

/-- Exact without-replacement current sample count outside the matrix event. -/
theorem current_small_support_failure_card
    (point : Position → Goldilocks) (injective : Function.Injective point)
    (view : R.SourceResponseView Goldilocks)
    (notBad : ¬ BadMatrix point 13172 360448 view.data view.masks view.coefficients) :
    (decoderFailureEvent point 13172 58 view.data view.masks view.response
      view.coefficients).card ≤ Nat.choose 360447 58 :=
  NativePrivateSpendQ58CurrentRecovery.nonexceptional_q58_failure_card point injective view notBad

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentOrdinaryRecovery
