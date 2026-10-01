import SmzaRp05CurrentAcceptedFilteredClassification
import SmzaRp05CurrentAcceptedSameStageDecoder
import SmzaRp05CurrentAcceptedFilteredDecoder
import SmzaRp05CurrentAcceptedFilteredLabelReadback
import SmzaRp05CurrentAcceptedRelationWitness
import SmzaRp05CurrentPublicStatementTransport
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05GeneratedCertificates
import SmzaRp05Components
import SmzaRp05ChallengeRecordErasure
import SmzaRp05CurrentAcceptedCausalPayloads
import SmzaRp05CurrentGroupedVerifierReplay

/-! # Accepted branch classification on the filtered current statement

Compose the actual grouped-claims execution and its filtered decoder outcome
with current label/relation readback. Full relation satisfaction is eliminated
by the pinned current public admission theorem and the no-packed-witness
condition. The result retains the exact hash-stage call; it does not assert an
unproved inclusion in the full branch log.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSameStageClassification

open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentGroupedVerifierReplay (accepted_grouped_claims_supply_verifier_replay)
open SmzaRp05CurrentAcceptedFilteredDecoder
  (accepted_grouped_branch_supplies_statement_filtered_decoder)
open SmzaRp05CurrentAcceptedFilteredLabelReadback
  (actual_filtered_decoder_outcome_has_current_label_or_relation)
open SmzaRp05CurrentAcceptedRelationWitness
  (current_full_rows_yield_typed_accepted_witness)
open SmzaRp05GeneratedCertificates (currentDsl certificates)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05CurrentAcceptedCausalPayloads (Records)
open SmzaRp05CurrentMaxAgreementRecovery (Position Query Coefficients)
open SmzaRp05CurrentAcceptedQueryExtraction (CurrentDecoderOutcome)
open SmzaRp05CurrentRetainedQuerySupport (measuredDataTable measuredMaskTable)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05CurrentResponseInputDecoder (responseRuleOfRawInputSelection)
open SmzaRp05CurrentTwelveCalculated (currentStageTails)
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05CurrentTracePrefixes406 (currentSourceBad406 currentSourcePrefix406 currentSourceDecoder406)
open SmzaRp05TracePrefixes (rootOracle queryCoefficients)
open SmzaRp04ChronologicalAlgebra (claimedPolynomials piopMatrixBadEvent piopOpeningBadEvent)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext globalNormalizedPayload)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open SmzaRp05RelationRefinement (relationModel)
open SmzaRp05CurrentQueryEventCore (currentStageClaims)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaQ38LvcsOpening (rowCombination)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentAcceptedCausalPayloads
open V8Smz9PiopReconstruction (points)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open SmzaRp05GroupedSuffix (groupRepresentative groupZero GroupCounter)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open V8SmzaOracleParser (RawDigest RawInput)
open SmzaChallengeStageTargets (parseStageQuery)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1600000

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "Payload" => SmzaRp05TracePrefixes.Payload

open SmzaRp05CurrentAcceptedFilteredClassification (CurrentNoWitnessLabelOutcome)
open SmzaRp05CurrentAcceptedSameStageDecoder (accepted_grouped_branch_has_same_stage_decoder_outcome)

/-- Actual accepted grouped-claims branch classification under the current
modeled public admission and absence of a packed accepted witness. The hash
input is retained in the exact PCS hash-stage record and the outcome is on the
challenge-erased, one-statement-filtered source records. -/
theorem accepted_grouped_branch_has_same_stage_no_witness_classification
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (accepted : branchResult groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
      branch = some ())
    (database : Database
      (Key (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys (encode (producer.bind fun wire =>
          verifierProgram ns currentDsl statement pending nonce wire)) groupedDecode
          (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
          branch)
        (branchAnswers (encode (producer.bind fun wire =>
          verifierProgram ns currentDsl statement pending nonce wire)) groupedDecode
          (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
          branch)) database)
    (fallback : RawDigest) (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked
        (encodePublicStatement typed)
        packed)
    (fuel : Nat) (enough : 25 ≤ fuel) :
    let program := producer.bind fun wire =>
      verifierProgram ns currentDsl statement pending nonce wire
    let oracle := finiteGroupedDatabaseOracle program database fallback
    let erasedRecords := eraseChallengeRecords
      (rawRecords (fun key => groupRepresentative (included program key))
        (vectorOutputBytes groupZero) database)
    let filteredRecords := oneStatementFilter (globalLeafStatement ns)
      statement.toBytes erasedRecords
    ∃ wire transcript,
      producer.eval oracle = some wire ∧
      (verifierProgram ns currentDsl statement pending nonce wire).eval oracle = some () ∧
      (SmzaRp05ExecutablePcsClosure.transcriptProgram ns currentDsl statement pending
        statement.toBytes (statementBindingWords statement) nonce wire).eval oracle =
          some transcript ∧
      ∃ execution : ExecutionStages ns currentDsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire oracle transcript,
      ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
        (sameProofRows execution.middle.pcs execution.piop) execution.decs
        (List.ofFn fun j : Fin 6 => points execution.opening j)
        wire.salt statement.toBytes (statementBindingWords statement)
        wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending,
      ¬ SmzaRecordedTracePath.RecordsCollisionFree filteredRecords ∨
        ∃ coordinates : Fin 38 → Position,
          ∃ query : Query, ∃ input : RawInput,
            StrictMono coordinates ∧
            query.val = Finset.univ.image coordinates ∧
            (∀ j : Fin 38, (coordinates j).val = pcs.indexes.getD j.val 0) ∧
            (input, execution.hashFpp) ∈ filteredRecords ∧
            (input, execution.hashFpp) ∈ (pcs.hashProgram.record oracle).2 ∧
            CurrentDecoderOutcome
              (measuredDataTable ns filteredRecords fuel pcs.post.root)
              (measuredMaskTable ns filteredRecords fuel pcs.post.root)
              (responseRuleOfRawInputSelection (fun _ : Coefficients => input))
              (sampledCoefficients (gammaRows pcs.post)) pcs.heads
              (currentStageTails (sameProofRows execution.middle.pcs execution.piop))
              (fun opening => (List.ofFn fun j : Fin 6 =>
                points execution.opening j).getD opening.val 0) query ∧
            CurrentNoWitnessLabelOutcome ns statement pending nonce wire oracle
              transcript execution pcs
              erasedRecords fuel input query := by
  classical
  let program := producer.bind fun wire =>
    verifierProgram ns currentDsl statement pending nonce wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let erasedRecords := eraseChallengeRecords
    (rawRecords (fun key => groupRepresentative (included program key))
      (vectorOutputBytes groupZero) database)
  let filteredRecords := oneStatementFilter (globalLeafStatement ns)
    statement.toBytes erasedRecords
  have bindingLength : (statementBindingWords statement).length = 138 :=
    SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement
  obtain ⟨wire, transcript, producerSuccess, verifierAccepted, transcriptSuccess,
    execution, pcs, decoded⟩ :=
    accepted_grouped_branch_has_same_stage_decoder_outcome producer ns currentDsl
      statement pending nonce branch accepted database claims fallback fuel enough
      bindingLength
  rcases decoded with collision | ⟨coordinates, query, input, ordered, image,
      indices, inputMember, hashMember, outcome⟩
  · exact ⟨wire, transcript, producerSuccess, verifierAccepted, transcriptSuccess,
    execution, pcs, Or.inl collision⟩
  · have labelResult := actual_filtered_decoder_outcome_has_current_label_or_relation
      certificates execution pcs erasedRecords fuel enough input hashMember query outcome
    refine ⟨wire, transcript, producerSuccess, verifierAccepted, transcriptSuccess,
    execution, pcs, Or.inr ⟨coordinates, query, input,
      ordered, image, indices, inputMember, hashMember, outcome, ?_⟩⟩
    rcases labelResult with matrixBad | ⟨matrixGood, fpp, openingPayload,
        inputParsed, inputNormalized, inputSuffix, openingParsed, openingNormalized,
        claimsRead, labelOutcome⟩
    · exact Or.inl matrixBad
    · refine Or.inr ⟨matrixGood, fpp, openingPayload, inputParsed,
        inputNormalized, inputSuffix, openingParsed, openingNormalized, claimsRead, ?_⟩
      rcases labelOutcome with sourceBad | ⟨source, decodedSource, sourceClaims,
          relationOutcome⟩
      · exact Or.inl sourceBad
      · refine Or.inr ⟨source, decodedSource, sourceClaims, ?_⟩
        rcases relationOutcome with full | failure
        · have acceptedTyped := current_full_rows_yield_typed_accepted_witness
            statement typed parsed source.data full
          exact False.elim (noPackedWitness ⟨
            SmzaQ38Recovery.packedFromRows source.data, acceptedTyped.2⟩)
        · exact failure

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSameStageClassification
