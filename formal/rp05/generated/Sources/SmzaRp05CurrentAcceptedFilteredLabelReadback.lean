import SmzaRp05CurrentAcceptedLabelOutcome
import SmzaRp05CurrentAcceptedRelationOutcome
import SmzaRp04StatementRecordFilter
import SmzaRp05FilteredReadback

/-! # Filtered same-execution label and relation classification

Promote the actual generated-stage decoder outcome when its measured tables
and matrix/source oracle are built from the same one-statement-filtered
relation. The result is a current 406 source-bad label, or the exact decoded
source/claimed-family facts followed by the same execution's full-relation or
PIOP-bad alternative. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFilteredLabelReadback

open SmzaRp05CurrentAcceptedLabelOutcome
  (generated_stage_outcome_is_current_label_bad_or_exact)
open SmzaRp05CurrentAcceptedQueryExtraction (CurrentDecoderOutcome)
open SmzaRp05CurrentAcceptedRelationOutcome
  (exact_current_stage_source_outcome_is_full_or_piop_bad)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentMaxAgreementRecovery (Coefficients Query)
open SmzaRp05CurrentTracePrefixes406
  (currentSourceBad406 currentSourcePrefix406 currentSourceDecoder406)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05CurrentResponseInputDecoder (responseRuleOfRawInputSelection)
open SmzaRp05CurrentRetainedQuerySupport (measuredDataTable measuredMaskTable)
open SmzaRp05CurrentTwelveCalculated (currentStageTails)
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05TracePrefixes (rootOracle queryCoefficients)
open SmzaRp04ChronologicalAlgebra (piopMatrixBadEvent piopOpeningBadEvent)
open SmzaRp05FilteredDecoderInstability (RawRecords globalOnlineNext globalNormalizedPayload)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open SmzaRp05RelationRefinement (RelationDsl GeneratedCertificates relationModel)
open SmzaRp05CurrentQueryEventCore (currentStageClaims)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaQ38LvcsOpening (rowCombination)
open SmzaRp04ChronologicalAlgebra (claimedPolynomials)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords statement_binding_word_count)
open V8Smz9PiopReconstruction (points)
open SmzaRp05StatementNamespace (Statement)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9PiopSoundness (Opening)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)
open V8Smz9CoherentMerkleGeometry (extract)

set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1600000
noncomputable section

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "Payload" => SmzaRp05TracePrefixes.Payload

/-- A decoder outcome measured from this execution's current-statement
records produces the corrected source-bad label or an exact same-run source
and relation outcome. In particular, all root-table values in both branches
are computed on `oneStatementFilter records`. -/
theorem actual_filtered_decoder_outcome_has_current_label_or_relation
    {ns : SmzaRp05LeafNamespace.Namespace} {dsl : RelationDsl}
    {statement : Statement} {pending : Bool} {nonce : Fin (2 ^ 32)}
    {wire : ExistingProofFieldView} {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {transcript : ReconstructedTranscript}
    (certificates : GeneratedCertificates dsl)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    (sourceRecords : RawRecords) (fuel : Nat) (_enough : 25 ≤ fuel)
    (input : RawInput)
    (inputRecorded : (input, execution.hashFpp) ∈ (pcs.hashProgram.record oracle).2)
    (query : Query)
    (outcome : CurrentDecoderOutcome
      (measuredDataTable ns
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes sourceRecords)
        fuel pcs.post.root)
      (measuredMaskTable ns
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes sourceRecords)
        fuel pcs.post.root)
      (responseRuleOfRawInputSelection (fun _ : Coefficients => input))
      (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
      pcs.heads (currentStageTails
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop))
      (fun opening =>
        List.getD (List.ofFn fun j : Fin 6 =>
          V8Smz9PiopReconstruction.points execution.opening j) opening.val 0)
      query) :
    currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData
        (rootOracle ns (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes sourceRecords)
          fuel .root pcs.post.root)))
      (SmzaQ38McaSourceBinding.oracleMasks
        (rootOracle ns (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes sourceRecords)
          fuel .root pcs.post.root)))
      (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
    ∨ ∃ matrixGood : ¬ currentMatrixBad
        (SmzaQ38McaSourceBinding.oracleData
          (rootOracle ns (extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes sourceRecords)
            fuel .root pcs.post.root)))
        (SmzaQ38McaSourceBinding.oracleMasks
          (rootOracle ns (extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes sourceRecords)
            fuel .root pcs.post.root)))
        (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)),
      ∃ fpp openingPayload : Payload,
      V8SmzaOracleParser.parseFramed input =
        some (SmallWoodTranscript.piopInputDomain, fpp.bytes) ∧
      globalNormalizedPayload ns input = some ⟨.fpp, fpp.bytes⟩ ∧
      fpp.bytes.drop 16304 = statement.toBytes ∧
      V8SmzaOracleParser.parseFramed pcs.openingInput =
        some (SmallWoodTranscript.decsOpeningDomain, openingPayload.bytes) ∧
      globalNormalizedPayload ns pcs.openingInput = some ⟨.decs, openingPayload.bytes⟩ ∧
        claimedPolynomials (queryCoefficients openingPayload) =
        currentStageClaims pcs.heads
          (currentStageTails
            (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)) ∧
      ((currentSourceBad406
        (currentSourcePrefix406
          (rootOracle ns (extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes sourceRecords)
            fuel .root pcs.post.root))
          fpp (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
          (fun opening =>
            List.getD (List.ofFn fun j : Fin 6 =>
              V8Smz9PiopReconstruction.points execution.opening j) opening.val 0)
          (queryCoefficients openingPayload) matrixGood)
        query) ∨
      (∃ source : V8Smz9McaDecoder.DecodedSource
          HegemonCrypto.SmallWood.Goldilocks (Fin 5) 140,
        currentSourceDecoder406
          (rootOracle ns (extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes sourceRecords)
            fuel .root pcs.post.root)) fpp
          (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) = some source ∧
        (∀ combination,
          currentStageClaims pcs.heads
            (currentStageTails
              (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop))
            combination =
          SmzaQ38LvcsOpening.rowCombination source.data
            (baseOpeningPoints execution.opening.1) combination) ∧
        (HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
            ((relationModel dsl certificates).recoveredCandidate statement source.data).system ∨
          (¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
              ((relationModel dsl certificates).recoveredCandidate statement source.data).system ∧
            (execution.matrix ∈ piopMatrixBadEvent
                ((relationModel dsl certificates).recoveredCandidate statement source.data) ∨
              execution.opening ∈ piopOpeningBadEvent
                ((relationModel dsl certificates).recoveredCandidate statement source.data)
                execution.matrix (SmzaRp05TracePrefixes.piopResponse
                  ⟨.piop, SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩)))))) := by
  classical
  let records := oneStatementFilter (globalLeafStatement ns) statement.toBytes sourceRecords
  by_cases badMatrix : currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData
        (rootOracle ns (extract (globalOnlineNext ns) records fuel .root pcs.post.root)))
      (SmzaQ38McaSourceBinding.oracleMasks
        (rootOracle ns (extract (globalOnlineNext ns) records fuel .root pcs.post.root)))
      (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
  · exact Or.inl badMatrix
  · have matrixGood := badMatrix
    have bindingLength :
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement).length = 138 :=
      SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement
    obtain ⟨fpp, openingPayload, inputParsed, inputNormalized, inputSuffix,
        openingParsed, openingNormalized, claimsRead, labelOutcome⟩ :=
      generated_stage_outcome_is_current_label_bad_or_exact pcs records fuel bindingLength
        input inputRecorded matrixGood query outcome
    have inputSuffixStatement : fpp.bytes.drop 16304 = statement.toBytes := by
      rw [inputSuffix]
      exact SmzaRp05CurrentAcceptedOuterReadback.statement_binding_words_encode_exact
        statement
    rcases labelOutcome with bad | ⟨source, decoded, sourceClaims⟩
    · exact Or.inr ⟨matrixGood, fpp, openingPayload, inputParsed, inputNormalized, inputSuffixStatement,
        openingParsed, openingNormalized, claimsRead, Or.inl bad⟩
    · have pointsEq :
          (fun opening : Fin 6 =>
            (List.ofFn fun j : Fin 6 =>
              V8Smz9PiopReconstruction.points execution.opening j).getD opening.val 0) =
            baseOpeningPoints execution.opening.1 := by
        funext opening
        rw [List.getD_eq_getElem?_getD]
        simp only [List.getElem?_ofFn, dif_pos opening.isLt, Option.getD_some]
        rfl
      have sourceClaimsBase : ∀ combination,
          currentStageClaims pcs.heads
            (currentStageTails
              (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop))
            combination =
          SmzaQ38LvcsOpening.rowCombination source.data
            (baseOpeningPoints execution.opening.1) combination := by
        intro combination
        rw [← pointsEq]
        exact sourceClaims combination
      have relation := exact_current_stage_source_outcome_is_full_or_piop_bad
        dsl certificates statement transcript execution pcs openingPayload claimsRead
        source.data sourceClaimsBase
      exact Or.inr ⟨matrixGood, fpp, openingPayload, inputParsed, inputNormalized, inputSuffixStatement,
        openingParsed, openingNormalized, claimsRead,
        Or.inr ⟨source, decoded, sourceClaimsBase, relation⟩⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFilteredLabelReadback
