import SmzaRp05CurrentLabelReadback
import SmzaRp05CurrentFppFrameReadback
import SmzaRp05CurrentClaimCoefficientReadback
import SmzaRp05CurrentOutcomeLabelBridge
import SmzaRp05CurrentAcceptedQueryExtraction
import SmzaRp05PhysicalAcceptedCurrentExtraction
import SmzaRp05CurrentAcceptedOuterReadback

/-! # Same-stage current source-label outcome

Transport an actual accepted-stage decoder outcome to the literal current
406 source label.  The FPP frame is recovered from that stage's generated
response program, while the claimed polynomial family is recovered from its
generated DECS opening frame. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedLabelOutcome

open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedQueryExtraction
  (CurrentDecoderOutcome)
open HegemonCrypto.SmallWood.SmzaRp05CurrentRetainedQuerySupport
  (measuredDataTable measuredMaskTable)
open HegemonCrypto.SmallWood.SmzaRp05CurrentResponseInputDecoder
  (responseRuleOfRawInputSelection)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedQuerySupport
  (sampledCoefficients)
open HegemonCrypto.SmallWood.SmzaRp05CurrentTracePrefixes406
open HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementRecovery
  (Coefficients Query)
open HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureStages (PcsStages)
open HegemonCrypto.SmallWood.SmzaRp05ExecutableMerkleVerifier (Program ask)
open HegemonCrypto.SmallWood.SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement (RelationDsl)
open HegemonCrypto.SmallWood.SmzaRp05ExecutableChallengeStage (FieldWord)
open HegemonCrypto.SmallWood.SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open HegemonCrypto.SmallWood.SmzaRp05FilteredDecoderInstability
  (RawRecords globalNormalizedPayload globalOnlineNext)
open HegemonCrypto.SmallWood.SmzaRp05LeafNamespace (Namespace)
open HegemonCrypto.SmallWood.SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05TracePrefixes (Payload queryCoefficients)
open HegemonCrypto.CmsCompressedOracle (State Basis)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open V8SmzaOracleParser (RawInput RawDigest)

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
noncomputable section

attribute [local irreducible] V8Smz9McaRecovery.querySampleFintype
attribute [local irreducible]
  currentSourceDecoder406 currentSourcePrefix406 currentSourceBad406
  currentMatrixBad currentResponseRule406

/-- A successful generated FPP query, together with a current decoder outcome
on the exact selected input and the measured tables of the same record set,
has the source-label alternative (bad query) or exact twelve-check recovery.
The source payload and claimed coefficients are both read back from the same
`PcsStages`; neither is a caller-supplied equality witness. -/
theorem generated_stage_outcome_is_current_label_bad_or_exact
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : DecodedDecsResponseFields} {points : List HegemonCrypto.SmallWood.Goldilocks}
    {salt binding : List HegemonCrypto.CanonicalBytes.Byte}
    {statementBinding : List Nat} {tapes : List (List HegemonCrypto.CanonicalBytes.Byte)}
    {paths : List (List RawDigest)}
    {executionOracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : RawDigest} {finalPending : Bool}
    [digestDec : DecidableEq RawDigest]
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths executionOracle hashFpp finalPending)
    (records : RawRecords) (fuel : Nat)
    (bindingLength : statementBinding.length = 138)
    (input : RawInput)
    (inputRecorded : (input, hashFpp) ∈ (stages.hashProgram.record executionOracle).2)
    (matrixGood : ¬ currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData
        (SmzaRp05TracePrefixes.rootOracle ns
          (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records fuel
            .root stages.post.root)))
      (SmzaQ38McaSourceBinding.oracleMasks
        (SmzaRp05TracePrefixes.rootOracle ns
          (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records fuel
            .root stages.post.root)))
      (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)))
    (query : Query)
    (outcome : CurrentDecoderOutcome
      (measuredDataTable ns records fuel stages.post.root)
      (measuredMaskTable ns records fuel stages.post.root)
      (responseRuleOfRawInputSelection (fun _ : Coefficients => input))
      (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows stages.post))
      stages.heads
      (SmzaRp05CurrentTwelveCalculated.currentStageTails wire)
      (fun opening => points.getD opening.val 0) query) :
    ∃ fpp : Payload,
      ∃ openingPayload : Payload,
        V8SmzaOracleParser.parseFramed input =
          some (SmallWoodTranscript.piopInputDomain, fpp.bytes) ∧
        globalNormalizedPayload ns input = some ⟨.fpp, fpp.bytes⟩ ∧
        fpp.bytes.drop 16304 =
          statementBinding.flatMap (HegemonCrypto.CanonicalBytes.encodeLE 8) ∧
        V8SmzaOracleParser.parseFramed stages.openingInput =
          some (SmallWoodTranscript.decsOpeningDomain, openingPayload.bytes) ∧
        globalNormalizedPayload ns stages.openingInput =
          some ⟨.decs, openingPayload.bytes⟩ ∧
        SmzaRp04ChronologicalAlgebra.claimedPolynomials
            (queryCoefficients openingPayload) =
          SmzaRp05CurrentQueryEventCore.currentStageClaims stages.heads
            (SmzaRp05CurrentTwelveCalculated.currentStageTails wire) ∧
        (currentSourceBad406
          (currentSourcePrefix406
            (SmzaRp05TracePrefixes.rootOracle ns
              (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records fuel
                .root stages.post.root))
            fpp (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows stages.post))
            (fun opening => points.getD opening.val 0)
            (queryCoefficients openingPayload) matrixGood) query ∨
          ∃ source : V8Smz9McaDecoder.DecodedSource
              HegemonCrypto.SmallWood.Goldilocks (Fin 5) 140,
            currentSourceDecoder406
              (SmzaRp05TracePrefixes.rootOracle ns
                (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records fuel
                  .root stages.post.root)) fpp
              (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)) =
                some source ∧
          ∀ combination,
              SmzaRp05CurrentQueryEventCore.currentStageClaims stages.heads
                (SmzaRp05CurrentTwelveCalculated.currentStageTails wire) combination =
              SmzaQ38LvcsOpening.rowCombination source.data
                (fun opening => points.getD opening.val 0) combination) := by
  have digestDecEq : digestDec =
      (fun a b => Fintype.decidablePiFintype a b) := Subsingleton.elim _ _
  subst digestDec
  let rows := stages.rows.map
    (fun row => row.map SmzaRp05ExecutableRestore.toWord)
  let gamma := SmzaRp05PcsHashFppMiddle.gammaRows stages.post
  let evalPoints := stages.decsPoints.map SmzaRp05ExecutableRestore.toWord
  obtain ⟨responseInput, responseBytes, programEq, responseParsed,
      responseNormalized, _rootEdge, responseSuffix⟩ :=
    SmzaRp05CurrentFppFrameReadback.successful_response_program_has_current_fpp_edge
      ns stages.post.root decs rows gamma evalPoints statementBinding bindingLength
      stages.hashProgram stages.responseBuilt
  have recorded : (input, hashFpp) ∈
      ((ask responseInput).record executionOracle).2 := by
    simpa only [programEq] using inputRecorded
  have recordedPair : (input, hashFpp) =
      (responseInput, executionOracle responseInput) := by
    simpa [SmzaRp05ExecutableMerkleVerifier.Program.record,
      SmzaRp05ExecutableMerkleVerifier.ask] using recorded
  have inputEq : input = responseInput := congrArg Prod.fst recordedPair
  let fpp : Payload := ⟨.fpp, responseBytes⟩
  have parsedInput : V8SmzaOracleParser.parseFramed input =
      some (SmallWoodTranscript.piopInputDomain, fpp.bytes) := by
    rw [inputEq]
    exact responseParsed
  have normalizedInput : globalNormalizedPayload ns input =
      some ⟨.fpp, fpp.bytes⟩ := by
    rw [inputEq]
    exact responseNormalized
  have fppSuffix : fpp.bytes.drop 16304 =
      statementBinding.flatMap (HegemonCrypto.CanonicalBytes.encodeLE 8) :=
    responseSuffix
  obtain ⟨openingPayload, openingParsed, claimsRead⟩ :=
    SmzaRp05CurrentClaimCoefficientReadback.generated_opening_claim_coefficients_reconstruct_payload
      stages
  obtain ⟨openingRows, _openingRowsBuilt, constructorParsed,
      constructorNormalized, _openingRootEdge⟩ :=
    SmzaRp05CurrentDecsFrameReadback.current_decs_opening_edge406 ns hPiop
      stages.heads wire.pcs.rcombiTails stages.openingInput stages.openingBuilt
  have openingBytesEq : openingPayload.bytes =
      (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ openingRows).flatMap
        (HegemonCrypto.CanonicalBytes.encodeLE 8) := by
    have parsedEq := Option.some.inj (openingParsed.symm.trans constructorParsed)
    exact congrArg Prod.snd parsedEq
  have normalizedOpening : globalNormalizedPayload ns stages.openingInput =
      some ⟨.decs, openingPayload.bytes⟩ := by
    rw [openingBytesEq]
    exact constructorNormalized
  let rootOracle := SmzaRp05TracePrefixes.rootOracle ns
    (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records fuel
      .root stages.post.root)
  have dataEq : measuredDataTable ns records fuel stages.post.root =
      SmzaQ38McaSourceBinding.oracleData rootOracle := by
    funext column index
    simpa only [rootOracle] using
      SmzaRp05CurrentLabelReadback.measured_data_table_eq_extracted_root_oracle
        ns records fuel stages.post.root column index
  have masksEq : measuredMaskTable ns records fuel stages.post.root =
      SmzaQ38McaSourceBinding.oracleMasks rootOracle := by
    funext row index
    simpa only [rootOracle] using
      SmzaRp05CurrentLabelReadback.measured_mask_table_eq_extracted_root_oracle
        ns records fuel stages.post.root row index
  have responseEq : responseRuleOfRawInputSelection
      (fun _ : Coefficients => input) = currentResponseRule406 fpp :=
    SmzaRp05CurrentLabelReadback.constant_input_rule_eq_current406 input fpp
      SmallWoodTranscript.piopInputDomain parsedInput
  have sourceOutcome : CurrentDecoderOutcome
      (SmzaQ38McaSourceBinding.oracleData rootOracle)
      (SmzaQ38McaSourceBinding.oracleMasks rootOracle)
      (currentResponseRule406 fpp)
      (sampledCoefficients gamma) stages.heads
      (SmzaRp05CurrentTwelveCalculated.currentStageTails wire)
      (fun opening => points.getD opening.val 0) query := by
    simpa only [dataEq, masksEq, responseEq, gamma] using outcome
  have labelled :=
    SmzaRp05CurrentOutcomeLabelBridge.decoder_outcome_is_current_label_bad_or_exact
      rootOracle fpp (sampledCoefficients gamma)
      (fun opening => points.getD opening.val 0) stages.heads
      (SmzaRp05CurrentTwelveCalculated.currentStageTails wire)
      (queryCoefficients openingPayload) matrixGood
      query claimsRead sourceOutcome
  exact ⟨fpp, openingPayload, parsedInput, normalizedInput, fppSuffix,
    openingParsed, normalizedOpening, claimsRead, labelled⟩

set_option maxHeartbeats 4000000

/-- Lift the exact stage-label classification over the accepted physical
branch.  The selected response input is retained as a member of that very
stage's generated hash-program log; the DECS claimed family is decoded from
the same execution's opening input.  A bad matrix remains an explicit
alternative for the separate matrix-role event. -/
theorem accepted_physical_current_label_outcome
    {Key Phase Work : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype RawDigest] [DecidableEq RawDigest] [AddCommGroup RawDigest]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (encode : RawInput → Key) (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : SmzaRp05PhysicalAcceptedReplayLite.Branches
      (fun (_ : RawInput) (answer : RawDigest) => answer)
      (producer.bind fun wire =>
        SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wire))
    (state : State Key RawDigest Phase Work)
    (basis : Basis Key RawDigest Phase Work)
    (fallback : RawDigest)
    (nonzero : HegemonCrypto.CmsOracleSimulation.globalDecompress
      (SmzaRp05PhysicalAcceptedReplayLite.physicalRun encode
        (fun (_ : RawInput) (answer : RawDigest) => answer)
        (producer.bind fun wire =>
          SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
            pending nonce wire) branch state) basis ≠ 0)
    (accepted : SmzaRp05PhysicalAcceptedReplayLite.branchResult
      (fun (_ : RawInput) (answer : RawDigest) => answer)
      (producer.bind fun wire =>
        SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wire) branch = some ())
    (fuel : Nat) (enough : 25 ≤ fuel) :
    let decode : RawInput → RawDigest → RawDigest :=
      fun (_ : RawInput) (answer : RawDigest) => answer
    let oracle := SmzaRp05PhysicalAcceptedReplayLite.basisOracle
      encode decode basis fallback
    let program := producer.bind fun wire =>
      SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
        pending nonce wire
    let records : RawRecords :=
      (SmzaRp05PhysicalAcceptedReplayLite.rawLog decode program branch).toFinset
    ¬ SmzaRecordedTracePath.RecordsCollisionFree records ∨
      ∃ wire transcript,
        ∃ execution : SmzaRp05ExecutablePcsClosure.ExecutionStages ns dsl statement
          pending statement.toBytes
          (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
          nonce wire oracle transcript,
        ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
          (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
          execution.decs
          (List.ofFn fun j : Fin 6 =>
            V8Smz9PiopReconstruction.points execution.opening j)
          wire.salt statement.toBytes
          (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
          wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending,
        ∃ coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position,
          ∃ query : SmzaQ38McaSourceBinding.Query,
            ∃ input : RawInput,
              StrictMono coordinates ∧
              query.val = Finset.univ.image coordinates ∧
              (∀ j : Fin 38,
                (coordinates j).val = pcs.indexes.getD j.val 0) ∧
              (input, execution.hashFpp) ∈
                SmzaRp05PhysicalAcceptedReplayLite.rawLog decode program branch ∧
              (input, execution.hashFpp) ∈ (pcs.hashProgram.record oracle).2 ∧
              CurrentDecoderOutcome
                (measuredDataTable ns records fuel pcs.post.root)
                (measuredMaskTable ns records fuel pcs.post.root)
                (responseRuleOfRawInputSelection
                  (fun _ : Coefficients => input))
                (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
                pcs.heads
                (SmzaRp05CurrentTwelveCalculated.currentStageTails
                  (SmzaRp05PcsToFinalProgram.sameProofRows
                    execution.middle.pcs execution.piop))
                (fun opening =>
                  (List.ofFn fun j : Fin 6 =>
                    V8Smz9PiopReconstruction.points execution.opening j).getD
                      opening.val 0) query ∧
              (currentMatrixBad
                  (SmzaQ38McaSourceBinding.oracleData
                    (SmzaRp05TracePrefixes.rootOracle ns
                      (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                        records fuel .root pcs.post.root)))
                  (SmzaQ38McaSourceBinding.oracleMasks
                    (SmzaRp05TracePrefixes.rootOracle ns
                      (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                        records fuel .root pcs.post.root)))
                  (sampledCoefficients
                    (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) ∨
                ∃ matrixGood : ¬ currentMatrixBad
                    (SmzaQ38McaSourceBinding.oracleData
                      (SmzaRp05TracePrefixes.rootOracle ns
                        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                          records fuel .root pcs.post.root)))
                    (SmzaQ38McaSourceBinding.oracleMasks
                      (SmzaRp05TracePrefixes.rootOracle ns
                        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                          records fuel .root pcs.post.root)))
                    (sampledCoefficients
                      (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)),
                ∃ fpp openingPayload,
                  V8SmzaOracleParser.parseFramed input =
                    some (SmallWoodTranscript.piopInputDomain, fpp.bytes) ∧
                  globalNormalizedPayload ns input =
                    some ⟨.fpp, fpp.bytes⟩ ∧
                  fpp.bytes.drop 16304 = statement.toBytes ∧
                  V8SmzaOracleParser.parseFramed pcs.openingInput =
                    some (SmallWoodTranscript.decsOpeningDomain,
                      openingPayload.bytes) ∧
                  globalNormalizedPayload ns pcs.openingInput =
                    some ⟨.decs, openingPayload.bytes⟩ ∧
                  SmzaRp04ChronologicalAlgebra.claimedPolynomials
                    (queryCoefficients openingPayload) =
                      SmzaRp05CurrentQueryEventCore.currentStageClaims pcs.heads
                        (SmzaRp05CurrentTwelveCalculated.currentStageTails
                          (SmzaRp05PcsToFinalProgram.sameProofRows
                            execution.middle.pcs execution.piop)) ∧
                  (currentSourceBad406
                    (currentSourcePrefix406
                      (SmzaRp05TracePrefixes.rootOracle ns
                        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                          records fuel .root pcs.post.root))
                      fpp
                      (sampledCoefficients
                        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
                      (fun opening =>
                        (List.ofFn fun j : Fin 6 =>
                          V8Smz9PiopReconstruction.points execution.opening j).getD
                            opening.val 0)
                      (queryCoefficients openingPayload)
                      matrixGood) query ∨
                    ∃ source : V8Smz9McaDecoder.DecodedSource
                        HegemonCrypto.SmallWood.Goldilocks (Fin 5) 140,
                      currentSourceDecoder406
                        (SmzaRp05TracePrefixes.rootOracle ns
                          (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                            records fuel .root pcs.post.root)) fpp
                        (sampledCoefficients
                          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) =
                          some source ∧
                      ∀ combination,
                        SmzaRp05CurrentQueryEventCore.currentStageClaims pcs.heads
                          (SmzaRp05CurrentTwelveCalculated.currentStageTails
                            (SmzaRp05PcsToFinalProgram.sameProofRows
                              execution.middle.pcs execution.piop)) combination =
                        SmzaQ38LvcsOpening.rowCombination source.data
                          (fun opening =>
                            (List.ofFn fun j : Fin 6 =>
                              V8Smz9PiopReconstruction.points execution.opening j).getD
                                opening.val 0) combination)) := by
  classical
  let decode : RawInput → RawDigest → RawDigest :=
    fun (_ : RawInput) (answer : RawDigest) => answer
  let oracle := SmzaRp05PhysicalAcceptedReplayLite.basisOracle
    encode decode basis fallback
  let program := producer.bind fun wire =>
    SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
      pending nonce wire
  let records : RawRecords :=
    (SmzaRp05PhysicalAcceptedReplayLite.rawLog decode program branch).toFinset
  obtain collision | ⟨wire, transcript, execution, pcs,
      ⟨coordinates, query, input, ordered, image, coordinateIndex,
        inputLog, inputHashLog, currentOutcome⟩⟩ :=
    SmzaRp05PhysicalAcceptedCurrentExtraction.accepted_physical_current_decoder_outcome
      encode producer ns dsl statement pending nonce branch state basis fallback
      nonzero accepted fuel enough
  · exact Or.inl collision
  · refine Or.inr ⟨wire, transcript, execution, pcs, coordinates, query, input,
      ordered, image, coordinateIndex, inputLog, inputHashLog, currentOutcome, ?_⟩
    by_cases matrixBad : currentMatrixBad
        (SmzaQ38McaSourceBinding.oracleData
          (SmzaRp05TracePrefixes.rootOracle ns
            (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
              records fuel .root pcs.post.root)))
        (SmzaQ38McaSourceBinding.oracleMasks
          (SmzaRp05TracePrefixes.rootOracle ns
            (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
              records fuel .root pcs.post.root)))
        (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
    · exact Or.inl matrixBad
    · have goodMatrix : ¬ currentMatrixBad
          (SmzaQ38McaSourceBinding.oracleData
            (SmzaRp05TracePrefixes.rootOracle ns
              (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                records fuel .root pcs.post.root)))
          (SmzaQ38McaSourceBinding.oracleMasks
            (SmzaRp05TracePrefixes.rootOracle ns
              (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                records fuel .root pcs.post.root)))
          (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) := matrixBad
      have stageLabel := generated_stage_outcome_is_current_label_bad_or_exact
        (stages := pcs) (records := records) (fuel := fuel)
        (bindingLength :=
          SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
        (input := input) (inputRecorded := inputHashLog)
        (matrixGood := goodMatrix) (query := query) (outcome := currentOutcome)
      rcases stageLabel with ⟨fpp, openingPayload, parsedFpp, normalizedFpp,
          fppSuffix, parsedOpening, normalizedOpening, claimsRead, labelOutcome⟩
      have fppStatementSuffix : fpp.bytes.drop 16304 = statement.toBytes := by
        rw [fppSuffix]
        exact SmzaRp05CurrentAcceptedOuterReadback.statement_binding_words_encode_exact
          statement
      exact Or.inr ⟨goodMatrix, fpp, openingPayload, parsedFpp, normalizedFpp,
        fppStatementSuffix, parsedOpening, normalizedOpening, claimsRead, labelOutcome⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedLabelOutcome
