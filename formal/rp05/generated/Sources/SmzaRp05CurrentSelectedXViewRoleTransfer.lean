import SmzaRp05CurrentAcceptedXViewRoleCoverage
import SmzaRp05CurrentSelectedXViewClaims
import SmzaRp05CurrentAcceptedStageReplay
import SmzaRp05CurrentBranchOracleAgreement
import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05PhysicalHashFppRecordRetention
import SmzaRp05CurrentNonchallengeRecordView
import SmzaRp05ExecutableMerklePaths

/-! # Transfer selected X-view role evidence to its mixed completion

The accepted-classifier evidence is evaluated under a claims-completing
database.  This module transports its exact execution and PCS records to the
literal fixed/active completion from the selected mixed support.  Both tables
satisfy the same branch claims, so their program reads and verifier transcript
are stable; equality of the nonchallenge views preserves the filtered source
records used by the current decoder.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedXViewRoleTransfer

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.CmsCompressedOracle (Basis)
open SmzaRoleDomainConditioning (ActiveKey)
open SmzaRp05ConditionedExecution
  (ActiveState ActiveMemory FixedTable XKey xView activeXView
    mergeFixedActive)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05CurrentSelectedChallengeClaims
  (SelectedWork nonchallengeRawKeySet recognizedActiveChallengeClaims
    branchXRoleSelector)
open SmzaRp05CurrentSelectedXViewClaims (selected_support_supplies_full_branch_claims)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentAcceptedXViewRoleCoverage
  (currentAcceptedXViewRoleSelector grouped_filtered_records_eq_of_same_xview)
open SmzaRp05CurrentAcceptedStageReplay
  (replay_execution_stages_of_verifier_record_eq
    replay_pcs_stages_of_verifier_record_eq execution_transcript_success)
open SmzaRp05CurrentBranchOracleAgreement
  (record_eq_of_agrees_on_left_reads eval_eq_of_agrees_on_left_reads
    same_branch_claims_agree_on_record_reads)
open SmzaRp05CurrentNonchallengeRecordView
  (grouped_erased_raw_records_eq_of_nonchallenge_key_agreement)
open SmzaRp05PhysicalPcsRecordRetention
  (execution_pcs_records_retained_in_verifier)
open SmzaRp05PhysicalHashFppRecordRetention (pcs_hash_fpp_records_retained)
open SmzaRp05ExecutableMerkleVerifier (Program.bind_log_left Program.bind_log_right)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05PhysicalAcceptedReplayLite (Branches)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05CurrentAcceptedFilteredClassification (CurrentNoWitnessLabelOutcome)
open SmzaRp05CurrentAcceptedQueryExtraction (CurrentDecoderOutcome)
open SmzaRp05CurrentRetainedQuerySupport (measuredDataTable measuredMaskTable)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05CurrentTwelveCalculated (currentStageTails)
open SmzaRp05CurrentResponseInputDecoder (responseRuleOfRawInputSelection)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaChallengeStageTargets (Role)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05CurrentMaxAgreementRecovery (Query Coefficients)
open SmzaRp05TracePrefixes (rootOracle)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
  (V8PublicStatement encodePublicStatement)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open SmzaRp05GroupedSuffix (GroupCounter groupZero)
open V8Smz9CoherentMerkleInstrument (rawRecords)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 30000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

local instance : DecidableEq RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl
  HegemonCrypto.SmallWood.SmzaRp05RelationRefinement.relationModel
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/-- Concrete accepted-stage evidence over one specified grouped database.
Unlike an X-view selector, this predicate names the exact database whose
oracle produced the query, retained hash call, and role-failure witness. -/
def CurrentAcceptedXViewRoleEvidence
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest) (fuel : Nat) (role : Role)
    (database : Database (Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (VectorOutput GroupCounter)) : Prop :=
  let program := producer.bind fun wire =>
    verifierProgram ns currentDsl statement pending nonce wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let erasedRecords := SmzaRp05ChallengeRecordErasure.eraseChallengeRecords
    (rawRecords (fun key => SmzaRp05GroupedSuffix.groupRepresentative
      (included program key)) (vectorOutputBytes groupZero) database)
  let filteredRecords := SmzaRp04StatementRecordFilter.oneStatementFilter
    (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes erasedRecords
  SmzaRecordedTracePath.RecordsCollisionFree filteredRecords ∧
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
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes
      wire.paths oracle execution.hashFpp execution.pcsPending,
    ∃ coordinates : Fin 38 → SmzaRp05CurrentMaxAgreementRecovery.Position,
      ∃ query : Query, ∃ input : RawInput,
        StrictMono coordinates ∧ query.val = Finset.univ.image coordinates ∧
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
            V8Smz9PiopReconstruction.points execution.opening j).getD opening.val 0)
          query ∧
        CurrentNoWitnessLabelOutcome ns statement pending nonce wire oracle transcript
          execution pcs erasedRecords fuel input query ∧
        SmzaRp05CurrentAcceptedXViewRoleCoverage.noWitnessRoleFailure role ns
          statement pending nonce wire oracle transcript execution pcs erasedRecords
          fuel input query

/-- Same-branch X-view evidence transfers to the literal merged completion.
The completed database may differ on recognized challenge coordinates; exact
branch claims force identical recorded answers and the source-stage replay
rebuilds its dependent witnesses under the merged database's oracle. -/
theorem selected_xview_role_replays_on_completion
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked
        (Hegemon.Transaction.Poseidon2V8SemanticSpecification.encodePublicStatement typed) packed)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (ctx : Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (keyBytesExact : ∀ key, ctx.keyBytes key =
      SmzaRp05GroupedSuffix.groupRepresentative (included
        (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
        key))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (fixed : FixedTable ctx blockCap)
    (initial : ActiveState ctx blockCap)
    (basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter) (ActiveMemory ctx))
    (challengeClaims : ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims ctx blockCap
        (encode (producer.bind fun wire =>
          verifierProgram ns currentDsl statement pending nonce wire)) groupedDecode
        (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
        branch) basis.database)
    (selectorSupport : selectedRoleState ctx blockCap
      (encode (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire)) groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
      branch fixed initial
      (fun view work => currentAcceptedXViewRoleSelector producer ns statement pending
        nonce fallback typed parsed noPackedWitness fuel enough ctx keyBytesExact
        ctx.role branch view work) basis ≠ 0) :
    CurrentAcceptedXViewRoleEvidence producer ns statement pending nonce fallback fuel
      ctx.role (mergeFixedActive ctx blockCap fixed basis.database) := by
  classical
  let program := producer.bind fun wire =>
    verifierProgram ns currentDsl statement pending nonce wire
  let select := fun (view : XKey (nonchallengeRawKeySet ctx) →
      Option (VectorOutput GroupCounter)) (work : Work (Counter := GroupCounter)
      (BaseWork := BaseWork)) =>
    currentAcceptedXViewRoleSelector producer ns statement pending nonce fallback
      typed parsed noPackedWitness fuel enough ctx keyBytesExact ctx.role branch view work
  let merged := mergeFixedActive ctx blockCap fixed basis.database
  let keys := nonchallengeRawKeySet ctx
  let unrecognized := SmzaRp05CurrentSelectedChallengeClaims.nonchallenge_raw_key_set_unrecognized ctx
  have selectedJoin := selected_support_supplies_full_branch_claims ctx blockCap
    (encode program) groupedDecode program branch fixed initial select basis
    selectorSupport challengeClaims
  have branchSelector := selectedJoin.1
  have mergedClaims := selectedJoin.2.1
  have mergedView := selectedJoin.2.2
  have selectorOnActive := branchSelector.1
  have selectorAtView : currentAcceptedXViewRoleSelector producer ns statement pending
      nonce fallback typed parsed noPackedWitness fuel enough ctx keyBytesExact
      ctx.role branch
      (activeXView ctx blockCap keys unrecognized basis.database)
      basis.workspace.original.2.2 := by
    exact selectorOnActive
  dsimp only [currentAcceptedXViewRoleSelector] at selectorAtView
  rcases selectorAtView with ⟨completion, completionView, completionClaims,
    completionEvidence⟩
  let completionViewFn := xView keys completion
  have completionViewEq : completionViewFn =
      activeXView ctx blockCap keys unrecognized basis.database := by
    funext key
    exact completionView key.val key.property
  have completionMergedView : xView keys completion = xView keys merged := by
    calc
      xView keys completion = activeXView ctx blockCap keys unrecognized basis.database :=
        completionViewEq
      _ = xView keys merged := mergedView.symm
  let leftOracle := finiteGroupedDatabaseOracle program completion fallback
  let rightOracle := finiteGroupedDatabaseOracle program merged fallback
  rcases completionEvidence with ⟨completionGood, completionEvidence⟩
  rcases completionEvidence with ⟨completionOracle, oracleEq, wire, transcript,
    producerOk, verifierOk, transcriptOk, execution, pcs, coordinates, query,
    input, ordered, image, indexes, inputMember, hashMember, currentOutcome,
    labelOutcome, roleFailure⟩
  have oracleSame : completionOracle = leftOracle := by exact oracleEq
  subst completionOracle
  have agrees := same_branch_claims_agree_on_record_reads program branch
    completion merged completionClaims mergedClaims fallback fallback
  have producerReadAgree : ∀ raw, (raw, leftOracle raw) ∈
      (producer.record leftOracle).2 → leftOracle raw = rightOracle raw := by
    intro raw member
    have included := Program.bind_log_left leftOracle producer
      (fun output => verifierProgram ns currentDsl statement pending nonce output)
      wire producerOk member
    exact agrees raw included
  have verifierReadAgree : ∀ raw, (raw, leftOracle raw) ∈
      ((verifierProgram ns currentDsl statement pending nonce wire).record leftOracle).2 →
        leftOracle raw = rightOracle raw := by
    intro raw member
    have included := Program.bind_log_right leftOracle producer
      (fun output => verifierProgram ns currentDsl statement pending nonce output)
      wire producerOk member
    exact agrees raw included
  have producerEvalEq := eval_eq_of_agrees_on_left_reads producer leftOracle rightOracle
    producerReadAgree
  have producerRight : producer.eval rightOracle = some wire :=
    producerEvalEq.symm.trans producerOk
  have verifierRecordEq := record_eq_of_agrees_on_left_reads
    (verifierProgram ns currentDsl statement pending nonce wire) leftOracle rightOracle
    (by
      intro raw member
      have included := Program.bind_log_right leftOracle producer
        (fun output => verifierProgram ns currentDsl statement pending nonce output)
        wire producerOk member
      exact agrees raw included)
  have verifierEvalEq := eval_eq_of_agrees_on_left_reads
    (verifierProgram ns currentDsl statement pending nonce wire) leftOracle rightOracle
    (by
      intro raw member
      have included := Program.bind_log_right leftOracle producer
        (fun output => verifierProgram ns currentDsl statement pending nonce output)
        wire producerOk member
      exact agrees raw included)
  have verifierRight : (verifierProgram ns currentDsl statement pending nonce wire).eval
      rightOracle = some () := verifierEvalEq.symm.trans verifierOk
  let executionRight := replay_execution_stages_of_verifier_record_eq ns currentDsl
    statement pending nonce wire leftOracle rightOracle transcript execution verifierRecordEq
  let pcsRight := replay_pcs_stages_of_verifier_record_eq ns currentDsl statement
    pending nonce wire leftOracle rightOracle transcript execution pcs verifierRecordEq
  have transcriptRight := execution_transcript_success ns currentDsl statement pending
    nonce wire rightOracle transcript executionRight
  let erasedRight := SmzaRp05ChallengeRecordErasure.eraseChallengeRecords
    (rawRecords
      (fun key => SmzaRp05GroupedSuffix.groupRepresentative (included program key))
      (vectorOutputBytes groupZero) merged)
  let filteredRight := SmzaRp04StatementRecordFilter.oneStatementFilter
    (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes erasedRight
  have filteredEq := grouped_filtered_records_eq_of_same_xview producer ns statement
    pending nonce ctx keyBytesExact completion merged completionMergedView
  have erasedEq : SmzaRp05ChallengeRecordErasure.eraseChallengeRecords
      (rawRecords (fun key => SmzaRp05GroupedSuffix.groupRepresentative
        (included program key)) (vectorOutputBytes groupZero) completion) = erasedRight := by
    exact grouped_erased_raw_records_eq_of_nonchallenge_key_agreement program
      completion merged (by
        intro key nonchallenge
        have ctxNonchallenge : SmzaChallengeStageTargets.parseStageQuery
            (ctx.keyBytes key) = none := by
          rw [keyBytesExact]
          exact nonchallenge
        have member : key ∈ keys :=
          Finset.mem_filter.mpr ⟨Finset.mem_univ _, ctxNonchallenge⟩
        have sameCell := congrFun completionMergedView ⟨key, member⟩
        simpa [xView] using sameCell)
  have postRootEq : pcsRight.post.root = pcs.post.root := rfl
  have gammaRowsEq : gammaRows pcsRight.post = gammaRows pcs.post := rfl
  have headsEq : pcsRight.heads = pcs.heads := rfl
  have tailsEq : currentStageTails
      (sameProofRows executionRight.middle.pcs executionRight.piop) =
      currentStageTails (sameProofRows execution.middle.pcs execution.piop) := rfl
  have pointsEq : (fun opening : Fin 6 => (List.ofFn fun j : Fin 6 =>
      V8Smz9PiopReconstruction.points executionRight.opening j).getD opening.val 0) =
      (fun opening : Fin 6 => (List.ofFn fun j : Fin 6 =>
      V8Smz9PiopReconstruction.points execution.opening j).getD opening.val 0) := rfl
  have openingInputEq : pcsRight.openingInput = pcs.openingInput := rfl
  have matrixEq : executionRight.matrix = execution.matrix := rfl
  have openingEq : executionRight.opening = execution.opening := rfl
  have currentOutcomeRight : CurrentDecoderOutcome
      (measuredDataTable ns filteredRight fuel pcsRight.post.root)
      (measuredMaskTable ns filteredRight fuel pcsRight.post.root)
      (responseRuleOfRawInputSelection (fun _ : Coefficients => input))
      (sampledCoefficients (gammaRows pcsRight.post)) pcsRight.heads
      (currentStageTails (sameProofRows executionRight.middle.pcs executionRight.piop))
      (fun opening => (List.ofFn fun j : Fin 6 =>
        V8Smz9PiopReconstruction.points executionRight.opening j).getD opening.val 0)
      query := by
    simpa only [filteredEq, postRootEq, gammaRowsEq, headsEq, tailsEq, pointsEq]
      using currentOutcome
  have labelOutcomeRight : CurrentNoWitnessLabelOutcome ns statement pending nonce wire
      rightOracle transcript executionRight pcsRight erasedRight fuel input query := by
    change CurrentNoWitnessLabelOutcome ns statement pending nonce wire
      leftOracle transcript execution pcs erasedRight fuel input query
    exact (congrArg (fun records => CurrentNoWitnessLabelOutcome ns statement pending
      nonce wire leftOracle transcript execution pcs records fuel input query)
      erasedEq).mp labelOutcome
  have roleFailureRight :
      SmzaRp05CurrentAcceptedXViewRoleCoverage.noWitnessRoleFailure ctx.role ns
        statement pending nonce wire rightOracle transcript executionRight pcsRight
        erasedRight fuel input query := by
    change SmzaRp05CurrentAcceptedXViewRoleCoverage.noWitnessRoleFailure ctx.role ns
      statement pending nonce wire leftOracle transcript execution pcs
      erasedRight fuel input query
    exact (congrArg (fun records =>
      SmzaRp05CurrentAcceptedXViewRoleCoverage.noWitnessRoleFailure ctx.role ns
        statement pending nonce wire leftOracle transcript execution pcs
        records fuel input query) erasedEq).mp roleFailure
  have filteredGoodRight : SmzaRecordedTracePath.RecordsCollisionFree filteredRight := by
    simpa only [filteredEq] using completionGood
  have inputMemberRight : (input, execution.hashFpp) ∈ filteredRight := by
    simpa only [filteredEq] using inputMember
  have hashRecordEq :
      (pcs.hashProgram.record leftOracle).2 =
        (pcs.hashProgram.record rightOracle).2 := by
    apply congrArg Prod.snd
    apply record_eq_of_agrees_on_left_reads pcs.hashProgram leftOracle rightOracle
    intro raw member
    have intoPcs := pcs_hash_fpp_records_retained ns execution.openingPending
      wire.hPiop (sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes
      wire.paths leftOracle execution.hashFpp execution.pcsPending pcs
      execution.pcsExecuted raw (leftOracle raw) member
    have transcriptSuccess := execution_transcript_success ns currentDsl statement
      pending nonce wire leftOracle transcript execution
    have intoVerifier := execution_pcs_records_retained_in_verifier ns currentDsl
      statement pending nonce wire leftOracle transcript execution transcriptSuccess
    exact agrees raw (Program.bind_log_right leftOracle producer
      (fun output => verifierProgram ns currentDsl statement pending nonce output)
      wire producerOk (intoVerifier (raw, leftOracle raw) intoPcs))
  have hashProgramRight : pcsRight.hashProgram = pcs.hashProgram := rfl
  have hashFppRight : executionRight.hashFpp = execution.hashFpp := rfl
  have hashMemberRight : (input, executionRight.hashFpp) ∈
      (pcsRight.hashProgram.record rightOracle).2 := by
    rw [hashProgramRight, hashFppRight, ← hashRecordEq]
    exact hashMember
  dsimp only [CurrentAcceptedXViewRoleEvidence]
  exact ⟨filteredGoodRight, ⟨wire, transcript, producerRight, verifierRight, transcriptRight,
    executionRight, pcsRight, coordinates, query, input, ordered, image, indexes,
    inputMemberRight, hashMemberRight, currentOutcomeRight, labelOutcomeRight,
    roleFailureRight⟩⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedXViewRoleTransfer
