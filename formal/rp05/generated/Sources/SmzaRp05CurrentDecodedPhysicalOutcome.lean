import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05PhysicalHashFppRecordRetention
import SmzaRp05CurrentAcceptedQueryExtraction
import SmzaRp05CurrentAcceptedLabelOutcome
import SmzaRp05CurrentAcceptedRelationOutcome
import SmzaRp05ChallengeRecordErasure

/-!
# Generic decoded-output accepted physical replay

Connect the finite physical replay's arbitrary measured output type and
decoder to the same accepted verifier execution, oracle, PCS stages, and raw
log. This is the output-generic counterpart of the RawDigest/identity
specialization used by the current-label classifiers; it introduces no
separately selected execution or retention certificate.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentDecodedPhysicalOutcome

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsCompressedOracle (State Basis)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle recordedAttempt)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches physicalRun branchResult rawLog answerLog basisOracle
    accepted_branch_record_eq_physical_rawLog record_eq_of_branch_answers)
open SmzaRp05PhysicalPcsRecordRetention
  (pcs_merkle_records_retained execution_pcs_records_retained_in_verifier)
open SmzaRp05FilteredDecoderInstability (RawRecords globalOnlineNext)
open SmzaRp05CurrentAcceptedQueryExtraction (CurrentDecoderOutcome)
open SmzaRp05CurrentMaxAgreementRecovery (Position Query Coefficients)
open SmzaRp05CurrentRetainedQuerySupport
  (measuredDataTable measuredMaskTable)
open SmzaRecordedTracePath (RecordsCollisionFree)
open SmzaRp05CurrentQueryEventCore (authenticatedReadbackOracle)
open SmzaRp04ChronologicalAlgebra (piopMatrixBadEvent piopOpeningBadEvent)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open V8SmzaOracleParser (RawInput RawDigest)
open SmzaChallengeStageTargets (parseStageQuery)

noncomputable section
set_option autoImplicit false

private def actualDecodedRelationConclusion
    (dsl : RelationDsl) (certificates : SmzaRp05RelationRefinement.GeneratedCertificates dsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    (source : V8Smz9McaDecoder.DecodedSource
      HegemonCrypto.SmallWood.Goldilocks (Fin 5) 140)
    (matrix : V8Smz9PiopSoundness.Matrix (dsl.width statement))
    (opening : V8Smz9PiopSoundness.Opening)
    (response : V8Smz9PiopSoundness.ClaimedTranscript) : Prop :=
  HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
      ((SmzaRp05RelationRefinement.relationModel dsl certificates).recoveredCandidate
        statement source.data).system ∨
    (¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
        ((SmzaRp05RelationRefinement.relationModel dsl certificates).recoveredCandidate
          statement source.data).system ∧
      (matrix ∈ piopMatrixBadEvent
          ((SmzaRp05RelationRefinement.relationModel dsl certificates).recoveredCandidate
            statement source.data) ∨
        opening ∈ piopOpeningBadEvent
          ((SmzaRp05RelationRefinement.relationModel dsl certificates).recoveredCandidate
            statement source.data) matrix response))

/-! A tighter stage-level sibling follows below. The Merkle premise is
restricted to calls that the root decoder can actually select. Challenge
frames are inert for `globalOnlineNext`, so their absence from grouped
representative records is harmless. The hash-FPP call is handled separately
using its actual generated frame. -/

/-- Stage-level decoder outcome from same-run records with only nonchallenge
raw-log retention. Each relevant Merkle call is first shown to be a
nonchallenge input using the exact challenge erasure theorem. Hash-FPP calls
are the actual generated response frame, whose parser-normalized `.fpp`
payload is disjoint from the challenge-query language. `merkleInRawLog` and
`hashInRawLog` bind both sublogs to the caller's real log. -/
theorem accepted_stage_nonchallenge_log_decoder_outcome
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List HegemonCrypto.SmallWood.Goldilocks} {salt binding : List Byte}
    {statementBinding : List Nat} {tapes : List (List Byte)}
    {paths : List (List RawDigest)}
    {oracle : Oracle} {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (pointCount : points.length = 6) (clean : finalPending = false)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (statementBindingLength : statementBinding.length = 138)
    (records : RawRecords) (rawLog : List (RawInput × RawDigest))
    (rawLogNonchallengeRetained : ∀ call, call ∈ rawLog →
      parseStageQuery call.1 = none → call ∈ records)
    (merkleInRawLog : ∀ call,
      call ∈ (recordedAttempt ns oracle stages.merkleInput).2 → call ∈ rawLog)
    (hashInRawLog : ∀ call,
      call ∈ (stages.hashProgram.record oracle).2 → call ∈ rawLog) :
    ¬ RecordsCollisionFree records ∨
      ∃ coordinates : Fin 38 → Position,
        ∃ query : Query, ∃ input : RawInput,
          StrictMono coordinates ∧
          query.val = Finset.univ.image coordinates ∧
          (∀ j : Fin 38, (coordinates j).val = stages.indexes.getD j.val 0) ∧
          (input, hashFpp) ∈ records ∧
          (input, hashFpp) ∈ (stages.hashProgram.record oracle).2 ∧
          CurrentDecoderOutcome
            (measuredDataTable ns records fuel stages.post.root)
            (measuredMaskTable ns records fuel stages.post.root)
            (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
              (fun _ : Coefficients => input))
            (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
              (SmzaRp05PcsHashFppMiddle.gammaRows stages.post))
            stages.heads (SmzaRp05CurrentTwelveCalculated.currentStageTails wire)
            (fun opening => points.getD opening.val 0) query := by
  classical
  by_cases collisionFree : RecordsCollisionFree records
  · let hashLog := (stages.hashProgram.record oracle).2
    obtain ⟨selected, inputBytes, programEq, parsedInput, normalizedInput,
      _rootEdge, _suffix⟩ :=
      SmzaRp05CurrentFppFrameReadback.successful_response_program_has_current_fpp_edge
        ns stages.post.root decs
        (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
        (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
        statementBinding statementBindingLength stages.hashProgram stages.responseBuilt
    have parserNone : parseStageQuery selected = none := by
      cases parsed : parseStageQuery selected with
      | none => rfl
      | some query =>
          have payloadNone :=
            SmzaRp05ChallengeRecordErasure.parse_stage_query_global_payload_none
              ns selected query parsed
          rw [normalizedInput] at payloadNone
          cases payloadNone
    have oracleEq : oracle selected = hashFpp := by
      have executed := stages.hashExecuted
      rw [programEq, SmzaRp05ExecutableMerkleVerifier.Program.eval.eq_def] at executed
      exact Option.some.inj executed
    have hashLogEq : hashLog = [(selected, hashFpp)] := by
      change (stages.hashProgram.record oracle).2 = _
      rw [programEq]
      simp [SmzaRp05ExecutableMerkleVerifier.Program.record,
        SmzaRp05ExecutableMerkleVerifier.ask, oracleEq]
    have inputCall : (selected, hashFpp) ∈ hashLog := by
      change (selected, hashFpp) ∈ (stages.hashProgram.record oracle).2
      simp [programEq, SmzaRp05ExecutableMerkleVerifier.Program.record,
        SmzaRp05ExecutableMerkleVerifier.ask,
        oracleEq]
    have hashRetained : ∀ call,
        call ∈ (stages.hashProgram.record oracle).2 → call ∈ records := by
      intro call member
      have callEq : call = (selected, hashFpp) := by
        change call ∈ hashLog at member
        rw [hashLogEq] at member
        exact List.mem_singleton.mp member
      subst call
      exact rawLogNonchallengeRetained (selected, hashFpp)
        (hashInRawLog _ inputCall) parserNone
    have sub : (hashLog ++ hashLog).toFinset ⊆ records := by
      intro call member
      have inHash : call ∈ hashLog := by
        simpa only [List.mem_toFinset, List.mem_append, or_self] using member
      exact hashRetained call inHash
    have responseCollisionFree : RecordsCollisionFree (hashLog ++ hashLog).toFinset := by
      intro a b digest left right
      exact collisionFree a b digest (sub left) (sub right)
    have merkleRetainedRelevant : ∀ stage raw digest,
        (raw, digest) ∈ (recordedAttempt ns oracle stages.merkleInput).2 →
        (globalOnlineNext ns stage raw).isSome → (raw, digest) ∈ records := by
      intro stage raw digest member relevant
      have parserNone : parseStageQuery raw = none := by
        cases parsed : parseStageQuery raw with
        | none => rfl
        | some query =>
            have inert :=
              SmzaRp05ChallengeRecordErasure.parse_stage_query_global_next_none
                ns raw query parsed stage
            simp [inert] at relevant
      exact rawLogNonchallengeRetained (raw, digest)
        (merkleInRawLog _ member) parserNone
    obtain ⟨coordinates, query, claims, polynomials, input,
        ordered, image, coordinateIndex, inputMember, _restored, checks, accepted⟩ :=
      SmzaRp05CurrentRetainedQuerySupport.same_stage_measured_root_query_support
        stages pointCount clean hashLog ⟨selected, inputCall⟩ responseCollisionFree
        records merkleRetainedRelevant collisionFree fuel enough statementBindingLength
    have bindingAt := SmzaRp05CurrentRetainedQuerySupport.measured_tables_match_decoded_oracle
      claims collisionFree fuel enough coordinates image
    have dataBinding : ∀ column : Fin 140, ∀ index, index ∈ query.val →
        measuredDataTable ns records fuel stages.post.root column.val index =
          SmzaQ38OracleExtraction.committedColumnValue
            (authenticatedReadbackOracle claims) column index := by
      intro column index member
      rw [image, Finset.mem_image] at member
      obtain ⟨j, _member, indexEq⟩ := member
      subst index
      exact bindingAt.1 j column
    refine Or.inr ⟨coordinates, query, input, ordered, image, coordinateIndex,
      rawLogNonchallengeRetained (input, hashFpp)
        (hashInRawLog _ inputMember) (by
          have inputEq : input = selected := by
            have pairEq : (input, hashFpp) = (selected, hashFpp) :=
              List.mem_singleton.mp (hashLogEq ▸ inputMember)
            exact congrArg Prod.fst pairEq
          rw [inputEq]
          exact parserNone),
      inputMember, ?_⟩
    exact SmzaRp05CurrentRecoveredQueryBridge.accepted_current_checks_bad_or_recovered
      claims coordinates stages.heads (SmzaRp05CurrentTwelveCalculated.currentStageTails wire)
      (fun opening => points.getD opening.val 0) checks image
      (measuredDataTable ns records fuel stages.post.root)
      (measuredMaskTable ns records fuel stages.post.root)
      (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
        (fun _ : Coefficients => input))
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)) accepted dataBinding
  · exact Or.inl collisionFree

/-- An accepted nonzero decoded-output branch yields its actual assembled
execution and PCS-stage witnesses under the oracle determined by that same
physical basis. Every Merkle-attempt record is retained in the branch's
full decoded raw log. `Output` and `decode` are arbitrary: the branch need not
measure `RawDigest` directly or use the identity decoder. -/
theorem accepted_decoded_physical_run_merkle_records_in_raw_log
    {Key Output Phase Work : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches decode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
    (state : State Key Output Phase Work)
    (basis : Basis Key Output Phase Work) (fallback : RawDigest)
    (nonzero : globalDecompress
      (physicalRun encode decode
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        branch state) basis ≠ 0)
    (accepted : branchResult decode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
      branch = some ()) :
    ∃ wire transcript,
      ∃ execution : ExecutionStages ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire
        (basisOracle encode decode basis fallback) transcript,
      ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes (statementBindingWords statement)
        wire.tapes wire.paths (basisOracle encode decode basis fallback)
        execution.hashFpp execution.pcsPending,
      (verifierProgram ns dsl statement pending nonce wire).eval
        (basisOracle encode decode basis fallback) = some () ∧
      producer.eval (basisOracle encode decode basis fallback) = some wire ∧
      (transcriptProgram ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire).eval
        (basisOracle encode decode basis fallback) = some transcript ∧
      ∀ call, call ∈ (recordedAttempt ns
        (basisOracle encode decode basis fallback) pcs.merkleInput).2 →
        call ∈ rawLog decode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch := by
  let oracle : Oracle := basisOracle encode decode basis fallback
  let next := fun wire => verifierProgram ns dsl statement pending nonce wire
  let program := producer.bind next
  have branchRecord := accepted_branch_record_eq_physical_rawLog
    encode decode program branch state basis fallback nonzero accepted
  have acceptedEval : program.eval oracle = some () := by
    have resultEq := congrArg Prod.fst branchRecord
    simpa [oracle, Program.record_result] using resultEq
  have bindEval : (producer.eval oracle).bind (fun wire => (next wire).eval oracle) =
      some () := by
    simpa [program, Program.eval_bind] using acceptedEval
  cases producerResult : producer.eval oracle with
  | none => simp [producerResult] at bindEval
  | some wire =>
      have producerSuccess : producer.eval oracle = some wire := producerResult
      have verifierAccepted : (next wire).eval oracle = some () := by
        simpa [producerResult] using bindEval
      have recordSplit := Program.record_bind_success oracle producer next wire producerSuccess
      have rawSplit : rawLog decode program branch =
          (producer.record oracle).2 ++ ((next wire).record oracle).2 := by
        have logged : rawLog decode program branch = (program.record oracle).2 := by
          rw [branchRecord]
        calc
          rawLog decode program branch = (program.record oracle).2 := logged
          _ = (producer.record oracle).2 ++ ((next wire).record oracle).2 :=
            congrArg Prod.snd recordSplit
      have transcriptData :=
        SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript
          ns dsl statement pending statement.toBytes (statementBindingWords statement)
          nonce wire oracle verifierAccepted
      obtain ⟨transcript, transcriptSuccess, _clean, _rootEq, _rootRecord⟩ :=
        transcriptData
      obtain ⟨execution⟩ :=
        SmzaRp05ExecutablePcsClosure.transcript_execution_has_stages
          ns dsl statement pending statement.toBytes (statementBindingWords statement)
          nonce wire oracle transcript transcriptSuccess
      obtain ⟨pcs⟩ :=
        SmzaRp05ExecutablePcsClosureStages.pcs_execution_has_stages
          ns execution.openingPending wire.hPiop
          (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
          execution.decs
          (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
          wire.salt statement.toBytes (statementBindingWords statement)
          wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending
          execution.pcsExecuted
      have intoPcs := pcs_merkle_records_retained ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes (statementBindingWords statement)
        wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs
        execution.pcsExecuted
      have intoVerifier := execution_pcs_records_retained_in_verifier
        ns dsl statement pending nonce wire oracle transcript execution transcriptSuccess
      refine ⟨wire, transcript, execution, pcs, verifierAccepted, rfl,
        transcriptSuccess, ?_⟩
      intro call member
      have inPcs := intoPcs call.1 call.2 member
      have inVerifier := intoVerifier call inPcs
      change call ∈ rawLog decode program branch
      rw [rawSplit]
      exact List.mem_append.mpr (Or.inr inVerifier)

/-- Output-generic same-run current relation endpoint. In addition to the
actual stages and retained query result, this exposes the source-prefix bad
case or the exact same-stage decoded rows and full PIOP relation alternative.
It accepts a pure answer-to-oracle agreement relation and an explicit
same-run raw-log inclusion, so it can consume records from the actual CMS
database without identifying the measured output with a digest. -/
theorem accepted_decoded_relation_outcome_of_record
    (oracle : Oracle)
    [Fintype RawDigest] [DecidableEq RawDigest] [AddCommGroup RawDigest]
    {Key Output : Type} [Fintype Key] [DecidableEq Key]
      [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    (encode : RawInput → Key)
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (certificates : SmzaRp05RelationRefinement.GeneratedCertificates dsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (decode : RawInput → Output → RawDigest)
    (branch : Branches decode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
    (branchAccepted : branchResult decode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
      branch = some ())
    (answersAgree : ∀ call ∈ answerLog decode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch,
      decode call.1 call.2 = oracle call.1)
    (records : RawRecords)
    (rawLogNonchallengeRetained : ∀ call,
      call ∈ rawLog decode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch → parseStageQuery call.1 = none → call ∈ records)
    (fuel : Nat) (enough : 25 ≤ fuel) :
    let program := producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire
    ¬ SmzaRecordedTracePath.RecordsCollisionFree records ∨
      ∃ wire transcript,
        ∃ execution : ExecutionStages ns dsl statement pending statement.toBytes
          (statementBindingWords statement) nonce wire oracle transcript,
        ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
          (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
          execution.decs
          (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
          wire.salt statement.toBytes (statementBindingWords statement)
          wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending,
        ∃ coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position,
          ∃ query : SmzaQ38McaSourceBinding.Query,
            ∃ input : RawInput,
              StrictMono coordinates ∧
              query.val = Finset.univ.image coordinates ∧
              (∀ j : Fin 38, (coordinates j).val = pcs.indexes.getD j.val 0) ∧
              (input, execution.hashFpp) ∈ rawLog decode program branch ∧
              (input, execution.hashFpp) ∈ (pcs.hashProgram.record oracle).2 ∧
              CurrentDecoderOutcome
                (SmzaRp05CurrentRetainedQuerySupport.measuredDataTable ns records fuel pcs.post.root)
                (SmzaRp05CurrentRetainedQuerySupport.measuredMaskTable ns records fuel pcs.post.root)
                (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
                  (fun _ : SmzaRp05CurrentMaxAgreementRecovery.Coefficients => input))
                (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
                  (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
                pcs.heads
                (SmzaRp05CurrentTwelveCalculated.currentStageTails
                  (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop))
                (fun opening =>
                  (List.ofFn fun j : Fin 6 =>
                    V8Smz9PiopReconstruction.points execution.opening j).getD opening.val 0)
                query ∧
              (SmzaRp05CurrentUniversalMatrixLoss.currentMatrixBad
                  (SmzaQ38McaSourceBinding.oracleData
                    (SmzaRp05TracePrefixes.rootOracle ns
                      (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                        records fuel .root pcs.post.root)))
                  (SmzaQ38McaSourceBinding.oracleMasks
                    (SmzaRp05TracePrefixes.rootOracle ns
                      (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                        records fuel .root pcs.post.root)))
                  (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
                    (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) ∨
                ∃ fpp openingPayload,
                  V8SmzaOracleParser.parseFramed input =
                    some (SmallWoodTranscript.piopInputDomain, fpp.bytes) ∧
                  SmzaRp05FilteredDecoderInstability.globalNormalizedPayload ns input =
                    some ⟨.fpp, fpp.bytes⟩ ∧
                  V8SmzaOracleParser.parseFramed pcs.openingInput =
                    some (SmallWoodTranscript.decsOpeningDomain, openingPayload.bytes) ∧
                  SmzaRp05FilteredDecoderInstability.globalNormalizedPayload ns pcs.openingInput =
                    some ⟨.decs, openingPayload.bytes⟩ ∧
                  SmzaRp04ChronologicalAlgebra.claimedPolynomials
                    (SmzaRp05TracePrefixes.queryCoefficients openingPayload) =
                    SmzaRp05CurrentQueryEventCore.currentStageClaims pcs.heads
                      (SmzaRp05CurrentTwelveCalculated.currentStageTails
                        (SmzaRp05PcsToFinalProgram.sameProofRows
                          execution.middle.pcs execution.piop)) ∧
                  ∃ matrixGood : ¬ SmzaRp05CurrentUniversalMatrixLoss.currentMatrixBad
                    (SmzaQ38McaSourceBinding.oracleData
                      (SmzaRp05TracePrefixes.rootOracle ns
                        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                          records fuel .root pcs.post.root)))
                    (SmzaQ38McaSourceBinding.oracleMasks
                      (SmzaRp05TracePrefixes.rootOracle ns
                        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                          records fuel .root pcs.post.root)))
                    (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
                      (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)),
                  (SmzaRp05CurrentTracePrefixes406.currentSourceBad406
                    (SmzaRp05CurrentTracePrefixes406.currentSourcePrefix406
                      (SmzaRp05TracePrefixes.rootOracle ns
                        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                          records fuel .root pcs.post.root)) fpp
                      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
                        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
                      (fun opening =>
                        (List.ofFn fun j : Fin 6 =>
                          V8Smz9PiopReconstruction.points execution.opening j).getD
                            opening.val 0)
                      (SmzaRp05TracePrefixes.queryCoefficients openingPayload)
                      matrixGood) query ∨
                    ∃ source : V8Smz9McaDecoder.DecodedSource
                        HegemonCrypto.SmallWood.Goldilocks (Fin 5) 140,
                      SmzaRp05CurrentTracePrefixes406.currentSourceDecoder406
                        (SmzaRp05TracePrefixes.rootOracle ns
                          (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
                            records fuel .root pcs.post.root)) fpp
                        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
                          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) = some source ∧
                      (∀ combination,
                        SmzaRp05CurrentQueryEventCore.currentStageClaims pcs.heads
                          (SmzaRp05CurrentTwelveCalculated.currentStageTails
                            (SmzaRp05PcsToFinalProgram.sameProofRows
                              execution.middle.pcs execution.piop)) combination =
                        SmzaQ38LvcsOpening.rowCombination source.data
                          (baseOpeningPoints execution.opening.1) combination) ∧
                      actualDecodedRelationConclusion dsl certificates statement source
                        execution.matrix execution.opening
                        (SmzaRp05TracePrefixes.piopResponse ⟨.piop,
                          SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩))) := by
  classical
  let program := producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire
  have branchRecord := record_eq_of_branch_answers encode decode program branch oracle answersAgree
  have acceptedEval : program.eval oracle = some () := by
    have resultEq := congrArg Prod.fst branchRecord
    calc
      program.eval oracle = (program.record oracle).1 := by simp [Program.record_result]
      _ = (branchResult decode program branch) := resultEq
      _ = some () := branchAccepted
  obtain ⟨wire, producerSuccess, verifierAccepted⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle producer
      (fun wire => verifierProgram ns dsl statement pending nonce wire) () acceptedEval
  have recordSplit := Program.record_bind_success oracle producer
    (fun wire => verifierProgram ns dsl statement pending nonce wire) wire producerSuccess
  have rawSplit : rawLog decode program branch =
      (producer.record oracle).2 ++
        ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 := by
    calc
      rawLog decode program branch = (program.record oracle).2 := by rw [branchRecord]
      _ = (producer.record oracle).2 ++
          ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 :=
        congrArg Prod.snd recordSplit
  obtain ⟨transcript, transcriptSuccess, transcriptClean, _rootEq, _rootRecord⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle verifierAccepted
  obtain ⟨execution⟩ :=
    SmzaRp05ExecutablePcsClosure.transcript_execution_has_stages ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle
      transcript transcriptSuccess
  obtain ⟨pcs⟩ :=
    SmzaRp05ExecutablePcsClosureStages.pcs_execution_has_stages
      ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending
      execution.pcsExecuted
  have cleanStages :=
    SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle
      transcript execution transcriptClean
  have pointCount :
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j).length = 6 :=
    SmzaRp05CurrentTwelveCalculated.generated_opening_points_length execution.opening
  have bindingLength : (statementBindingWords statement).length = 138 :=
    SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement
  have intoPcs := pcs_merkle_records_retained ns execution.openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes (statementBindingWords statement)
    wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs
    execution.pcsExecuted
  have pcsToVerifier := execution_pcs_records_retained_in_verifier
    ns dsl statement pending nonce wire oracle transcript execution transcriptSuccess
  have hashToVerifier :=
    SmzaRp05PhysicalHashFppRecordRetention.execution_hash_fpp_records_retained_in_verifier
      ns dsl statement pending nonce wire oracle transcript execution pcs transcriptSuccess
  obtain collision | source :=
    accepted_stage_nonchallenge_log_decoder_outcome pcs pointCount cleanStages.1 fuel enough
      bindingLength records (rawLog decode program branch) rawLogNonchallengeRetained
      (by
        intro call member
        rw [rawSplit]
        exact List.mem_append.mpr
          (Or.inr (pcsToVerifier call (intoPcs call.1 call.2 member))))
      (by
        intro call member
        rw [rawSplit]
        exact List.mem_append.mpr (Or.inr (hashToVerifier call member)))
  · exact Or.inl collision
  · rcases source with ⟨coordinates, query, input, ordered, image, coordinateIndex,
      inputMember, inputHashMember, currentOutcome⟩
    have inputInLog : (input, execution.hashFpp) ∈ rawLog decode program branch := by
      rw [rawSplit]
      exact List.mem_append.mpr (Or.inr (hashToVerifier _ inputHashMember))
    by_cases matrixBad : SmzaRp05CurrentUniversalMatrixLoss.currentMatrixBad
        (SmzaQ38McaSourceBinding.oracleData
          (SmzaRp05TracePrefixes.rootOracle ns
            (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
              records fuel .root pcs.post.root)))
        (SmzaQ38McaSourceBinding.oracleMasks
          (SmzaRp05TracePrefixes.rootOracle ns
            (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
              records fuel .root pcs.post.root)))
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
    · exact Or.inr ⟨wire, transcript, execution, pcs,
        coordinates, query, input, ordered, image, coordinateIndex, inputInLog,
        inputHashMember, currentOutcome, Or.inl matrixBad⟩
    · have matrixGood := matrixBad
      have label :=
        SmzaRp05CurrentAcceptedLabelOutcome.generated_stage_outcome_is_current_label_bad_or_exact
          (stages := pcs) (records := records) (fuel := fuel)
          (bindingLength := bindingLength) (input := input)
          (inputRecorded := inputHashMember) (matrixGood := matrixGood)
          (query := query) (outcome := currentOutcome)
      rcases label with ⟨fpp, openingPayload, parsedFpp, normalizedFpp, _suffix,
          parsedOpening, normalizedOpening, claimsRead, labelOutcome⟩
      refine Or.inr ⟨wire, transcript, execution, pcs,
        coordinates, query, input, ordered, image, coordinateIndex, inputInLog,
        inputHashMember, currentOutcome, Or.inr ?_⟩
      refine ⟨fpp, openingPayload, parsedFpp, normalizedFpp,
        parsedOpening, normalizedOpening, claimsRead, matrixGood, ?_⟩
      rcases labelOutcome with sourceBad |
        ⟨sourceDecoded, recoveredEq, sourceClaims⟩
      · exact Or.inl sourceBad
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
          SmzaRp05CurrentQueryEventCore.currentStageClaims pcs.heads
            (SmzaRp05CurrentTwelveCalculated.currentStageTails
              (SmzaRp05PcsToFinalProgram.sameProofRows
                execution.middle.pcs execution.piop)) combination =
          SmzaQ38LvcsOpening.rowCombination sourceDecoded.data
            (baseOpeningPoints execution.opening.1) combination := by
          intro combination
          rw [← pointsEq]
          exact sourceClaims combination
        have relationOutcome :=
          SmzaRp05CurrentAcceptedRelationOutcome.exact_current_stage_source_outcome_is_full_or_piop_bad
            dsl certificates statement transcript execution pcs openingPayload claimsRead
            sourceDecoded.data sourceClaimsBase
        exact Or.inr ⟨sourceDecoded, recoveredEq, sourceClaimsBase, relationOutcome⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentDecodedPhysicalOutcome
