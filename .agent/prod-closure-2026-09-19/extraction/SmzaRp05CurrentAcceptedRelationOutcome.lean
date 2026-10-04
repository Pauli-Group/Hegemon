import SmzaRp05CurrentAcceptedLabelOutcome
import SmzaRp05CurrentAlgebraicClosure
import SmzaRp05CurrentAcceptedScalarReadback
import SmzaRp05CurrentPcsAggregateReadback

/-! # Actual accepted RP05 relation outcome

Compose the actual DECS payload readback with same-run reconstructed PCS
heads and scalar checks. This algebraic endpoint does not assume canonical
public words, which are checked by the frontend admission path rather than
the byte-framing namespace model.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRelationOutcome

open SmzaRp05CurrentAlgebraicClosure
open SmzaRp05CurrentAcceptedScalarReadback
open SmzaRp05RelationRefinement
open SmzaRp04ChronologicalAlgebra
open SmzaRp05CurrentAcceptedQueryExtraction (CurrentDecoderOutcome)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05CurrentResponseInputDecoder (responseRuleOfRawInputSelection)
open SmzaRp05CurrentTracePrefixes406
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05FilteredDecoderInstability (RawRecords globalNormalizedPayload globalOnlineNext)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentMaxAgreementRecovery (Coefficients)
open HegemonCrypto.CmsCompressedOracle (State Basis)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open SmzaQ38Recovery (RecoveredRows)
open SmzaQ38OpeningFieldReadback (ClaimedHeadsReconstructed)
open V8Smz9PiopSoundness (Opening)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05CurrentPcsOpeningView (sourcePcsViewOfDecoded)
open V8SmzaOracleParser (RawDigest)

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "RawInput" => V8SmzaOracleParser.RawInput
local notation "Payload" => SmzaRp05TracePrefixes.Payload

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
noncomputable section

attribute [local irreducible]
  currentSourceDecoder406 currentSourcePrefix406 currentSourceBad406
  currentMatrixBad currentResponseRule406

private def actualOpeningMessage (payload : Payload)
    (piop : SmzaRp05ExecutableReconstruction.DecodedPiopFields)
    (pcs : SmzaRp05PcsWireProjection.DecodedPcsFields) : OpeningMessage where
  witness := SmzaRp05ExecutableReconstruction.witness piop
  masks := SmzaRp05ExecutableReconstruction.masks piop
  partials := sourcePcsViewOfDecoded pcs
  nonlinearHigh := fun _ => 0
  linearHigh := fun _ => 0
  correction := fun _ => 0
  claimedCoefficients := SmzaRp05TracePrefixes.queryCoefficients payload

/-- An exact current twelve-identity decoder result on the actual generated
DECS payload entails full candidate satisfaction or the actual matrix /
opening PIOP bad events. Head binding and scalar checks come from this
execution's decoded proof fields and successful `PcsStages`; neither is an
assumed certificate. -/
theorem exact_current_stage_source_outcome_is_full_or_piop_bad
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool}
    {wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {binding : List HegemonCrypto.CanonicalBytes.Byte}
    {statementBinding : List Nat} {nonce : Fin (2 ^ 32)}
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl) (statement : Statement)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending binding statementBinding
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun opening : Fin 6 =>
        V8Smz9PiopReconstruction.points execution.opening opening)
      wire.salt binding statementBinding wire.tapes wire.paths oracle
      execution.hashFpp execution.pcsPending)
    (payload : Payload)
    (claimsRead : claimedPolynomials (SmzaRp05TracePrefixes.queryCoefficients payload) =
      SmzaRp05CurrentQueryEventCore.currentStageClaims pcs.heads
        (SmzaRp05CurrentTwelveCalculated.currentStageTails
          (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)))
    (rows : RecoveredRows)
    (sourceClaims : ∀ combination,
      SmzaRp05CurrentQueryEventCore.currentStageClaims pcs.heads
        (SmzaRp05CurrentTwelveCalculated.currentStageTails
          (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop))
          combination =
      SmzaQ38LvcsOpening.rowCombination rows (baseOpeningPoints execution.opening.1)
        combination) :
    HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
        ((relationModel dsl certificates).recoveredCandidate statement rows).system ∨
      (¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
          ((relationModel dsl certificates).recoveredCandidate statement rows).system ∧
        (execution.matrix ∈ piopMatrixBadEvent
            ((relationModel dsl certificates).recoveredCandidate statement rows) ∨
          execution.opening ∈ piopOpeningBadEvent
            ((relationModel dsl certificates).recoveredCandidate statement rows)
            execution.matrix (SmzaRp05TracePrefixes.piopResponse ⟨.piop,
              SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩))) := by
  classical
  let message := actualOpeningMessage payload execution.piop execution.middle.pcs
  have heads : ClaimedHeadsReconstructed (baseOpeningPoints execution.opening.1)
      message.claimed message.witness message.masks message.partials := by
    change ClaimedHeadsReconstructed (baseOpeningPoints execution.opening.1)
      (claimedPolynomials (SmzaRp05TracePrefixes.queryCoefficients payload))
      (SmzaRp05ExecutableReconstruction.witness execution.piop)
      (SmzaRp05ExecutableReconstruction.masks execution.piop)
      (sourcePcsViewOfDecoded execution.middle.pcs)
    rw [claimsRead]
    exact SmzaRp05CurrentPcsAggregateReadback.actual_stages_have_claimed_heads_reconstructed
      execution.middle.pcs execution.piop pcs
  have combinations : ∀ combination, message.claimed combination =
      SmzaQ38LvcsOpening.rowCombination rows
        (baseOpeningPoints execution.opening.1) combination := by
    intro combination
    change claimedPolynomials (SmzaRp05TracePrefixes.queryCoefficients payload)
      combination = _
    rw [claimsRead]
    exact sourceClaims combination
  have scalar : ScalarChecks dsl certificates statement rows execution.matrix
      (SmzaRp05TracePrefixes.piopResponse ⟨.piop,
        SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩)
      execution.opening message := by
    have scalarRows := execution_stages_supply_scalar_checks_for_opening_message
      ns dsl certificates statement pending binding statementBinding nonce wire oracle
      transcript execution message rfl rfl
    exact scalarRows rows
  by_cases satisfied : HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
      ((relationModel dsl certificates).recoveredCandidate statement rows).system
  · exact Or.inl satisfied
  · right
    refine ⟨satisfied, ?_⟩
    have columns := SmzaRp05AcceptedQ38AgreementBridge.current_heads_force_reconstructed_columns rows
      (baseOpeningPoints execution.opening.1) message.claimed message.witness
      message.masks message.partials heads combinations
    let refinement := relationRefinement dsl certificates
    have accepted := refinement.openingAcceptsOfReadback statement rows execution.matrix
      (SmzaRp05TracePrefixes.piopResponse ⟨.piop,
        SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩)
      execution.opening message columns scalar
    exact opening_acceptance_is_matrix_or_opening_bad
      ((relationModel dsl certificates).recoveredCandidate statement rows)
      execution.matrix
      (SmzaRp05TracePrefixes.piopResponse ⟨.piop,
        SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩)
      execution.opening accepted

/-- Refine the accepted physical branch's same-run source-label result. A
source prefix may be bad; otherwise the exact decoded rows satisfy the
relation's full PIOP system or the named actual matrix/opening bad events.
All FPP/DECS frames, claims, and decoder rows in the conclusion come from the
physical execution and its selected oracle inputs. -/
theorem accepted_physical_current_relation_outcome
    {Key Phase Work : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype RawDigest] [DecidableEq RawDigest] [AddCommGroup RawDigest]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (encode : RawInput → Key) (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (certificates : GeneratedCertificates dsl)
    (statement : Statement) (pending : Bool) (nonce : Fin (2 ^ 32))
    (branch : SmzaRp05PhysicalAcceptedReplayLite.Branches
      (fun (_ : RawInput) (answer : RawDigest) => answer)
      (producer.bind fun wire =>
        SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wire))
    (state : State Key RawDigest Phase Work)
    (basis : Basis Key RawDigest Phase Work) (fallback : RawDigest)
    (nonzero : globalDecompress
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
        ∃ execution : ExecutionStages ns dsl statement pending statement.toBytes
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
              (∀ j : Fin 38, (coordinates j).val = pcs.indexes.getD j.val 0) ∧
              (input, execution.hashFpp) ∈
                SmzaRp05PhysicalAcceptedReplayLite.rawLog decode program branch ∧
              (input, execution.hashFpp) ∈ (pcs.hashProgram.record oracle).2 ∧
              CurrentDecoderOutcome
                (SmzaRp05CurrentRetainedQuerySupport.measuredDataTable
                  ns records fuel pcs.post.root)
                (SmzaRp05CurrentRetainedQuerySupport.measuredMaskTable
                  ns records fuel pcs.post.root)
                (responseRuleOfRawInputSelection (fun _ : Coefficients => input))
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
                    globalNormalizedPayload ns input = some ⟨.fpp, fpp.bytes⟩ ∧
                    fpp.bytes.drop 16304 = statement.toBytes ∧
                    V8SmzaOracleParser.parseFramed pcs.openingInput =
                      some (SmallWoodTranscript.decsOpeningDomain,
                        openingPayload.bytes) ∧
                    globalNormalizedPayload ns pcs.openingInput =
                      some ⟨.decs, openingPayload.bytes⟩ ∧
                    claimedPolynomials
                      (SmzaRp05TracePrefixes.queryCoefficients openingPayload) =
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
                        (SmzaRp05TracePrefixes.queryCoefficients openingPayload)
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
                        (∀ combination,
                          SmzaRp05CurrentQueryEventCore.currentStageClaims pcs.heads
                            (SmzaRp05CurrentTwelveCalculated.currentStageTails
                              (SmzaRp05PcsToFinalProgram.sameProofRows
                                execution.middle.pcs execution.piop)) combination =
                          SmzaQ38LvcsOpening.rowCombination source.data
                            (baseOpeningPoints execution.opening.1) combination) ∧
                        (HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
                            ((relationModel dsl certificates).recoveredCandidate
                              statement source.data).system ∨
                          (¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
                              ((relationModel dsl certificates).recoveredCandidate
                                statement source.data).system ∧
                            (execution.matrix ∈ piopMatrixBadEvent
                                ((relationModel dsl certificates).recoveredCandidate
                                  statement source.data) ∨
                              execution.opening ∈ piopOpeningBadEvent
                                ((relationModel dsl certificates).recoveredCandidate
                                  statement source.data) execution.matrix
                                (SmzaRp05TracePrefixes.piopResponse ⟨.piop,
                                  SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩)))))) := by
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
        inputLog, inputHashLog, currentOutcome, labelClassification⟩⟩ :=
    SmzaRp05CurrentAcceptedLabelOutcome.accepted_physical_current_label_outcome
      encode producer ns dsl statement pending nonce branch state basis fallback
      nonzero accepted fuel enough
  · exact Or.inl collision
  · refine Or.inr ⟨wire, transcript, execution, pcs, coordinates, query, input,
      ordered, image, coordinateIndex, inputLog, inputHashLog, currentOutcome, ?_⟩
    rcases labelClassification with matrixBad |
      ⟨matrixGood, fpp, openingPayload, parsedFpp, normalizedFpp, fppSuffix,
        parsedOpening, normalizedOpening, claimsRead, labelOutcome⟩
    · exact Or.inl matrixBad
    · refine Or.inr ⟨matrixGood, fpp, openingPayload, parsedFpp, normalizedFpp,
        fppSuffix, parsedOpening, normalizedOpening, claimsRead, ?_⟩
      rcases labelOutcome with sourceBad | ⟨source, sourceDecoded, sourceClaims⟩
      · exact Or.inl sourceBad
      · have pointsEq :
            (fun opening : Fin 6 =>
              (List.ofFn fun j : Fin 6 =>
                V8Smz9PiopReconstruction.points execution.opening j).getD
                  opening.val 0) = baseOpeningPoints execution.opening.1 := by
          funext opening
          rw [List.getD_eq_getElem?_getD]
          simp only [List.getElem?_ofFn, dif_pos opening.isLt, Option.getD_some]
          rfl
        have sourceClaimsBase : ∀ combination,
            SmzaRp05CurrentQueryEventCore.currentStageClaims pcs.heads
              (SmzaRp05CurrentTwelveCalculated.currentStageTails
                (SmzaRp05PcsToFinalProgram.sameProofRows
                  execution.middle.pcs execution.piop)) combination =
            SmzaQ38LvcsOpening.rowCombination source.data
              (baseOpeningPoints execution.opening.1) combination := by
          intro combination
          rw [← pointsEq]
          exact sourceClaims combination
        have relationOutcome := exact_current_stage_source_outcome_is_full_or_piop_bad
          dsl certificates statement transcript execution pcs openingPayload claimsRead
          source.data sourceClaimsBase
        exact Or.inr ⟨source, sourceDecoded, sourceClaimsBase, relationOutcome⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRelationOutcome
