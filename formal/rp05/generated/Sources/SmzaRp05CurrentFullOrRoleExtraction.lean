import SmzaRp05CurrentAcceptedFilteredClassification
import SmzaRp05CurrentAcceptedXViewRoleCoverage
import SmzaRp05CurrentAcceptedRelationWitness
import SmzaRp05CurrentAcceptedFilteredLabelReadback
import SmzaRp05CurrentAcceptedFilteredDecoder
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05ChallengeRecordErasure
import SmzaRp05CurrentGroupedVerifierReplay

/-! Current 406-map accepted-execution classification without a global
no-packed-witness assumption. The full arm preserves the same decoder output
and yields its exact typed accepted packed witness; the other arm retains the
existing role-failure classification. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFullOrRoleExtraction

open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8PublicDecoder
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
open SmzaRp05CurrentAcceptedXViewRoleCoverage
  (noWitnessRoleFailure no_witness_label_has_role_failure
    currentAcceptedXViewRoleSelector)
open SmzaRp05CurrentAcceptedFilteredClassification (CurrentNoWitnessLabelOutcome)
open SmzaRp05CurrentMaxAgreementRecovery (Position Query Coefficients)
open SmzaRp05CurrentAcceptedQueryExtraction (CurrentDecoderOutcome)
open SmzaRp05CurrentResponseInputDecoder (responseRuleOfRawInputSelection)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05CurrentTwelveCalculated (currentStageTails)
open SmzaRp05CurrentTracePrefixes406
  (currentSourceBad406 currentSourcePrefix406 currentSourceDecoder406)
open SmzaRp05TracePrefixes (rootOracle queryCoefficients)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext globalNormalizedPayload)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open SmzaRp05RelationRefinement (relationModel)
open SmzaRp05CurrentQueryEventCore (currentStageClaims)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentAcceptedCausalPayloads (Records)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open SmzaRp05GroupedSuffix (groupRepresentative groupZero GroupCounter)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open V8Smz9PiopReconstruction (points)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8SmzaOracleParser (RawDigest RawInput)
open SmzaChallengeStageTargets (parseStageQuery)
open SmzaRp05CurrentPublicStatementTransport
  (parseCurrentPublicStatement? rustV8SemanticPrimitives)
open SmzaRp05GeneratedCertificates (currentDsl certificates)
open SmzaRp04ChronologicalAlgebra (claimedPolynomials piopMatrixBadEvent piopOpeningBadEvent)
open SmzaQ38LvcsOpening (rowCombination)
open SmzaQ38Recovery (packedFromRows)
open V8Smz9McaDecoder (DecodedSource)
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "Payload" => SmzaRp05TracePrefixes.Payload

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 30000
set_option maxHeartbeats 1600000

attribute [local irreducible]
  SmzaRp05GeneratedCertificates.currentDsl
  SmzaRp05RelationRefinement.candidate
  HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied

/-- Same-run full-or-role branch after actual filtered decoder readback. -/
def CurrentFullOrRoleOutcome
    (ns : SmzaRp05LeafNamespace.Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns currentDsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    (records : Records) (fuel : Nat) (input : RawInput) (query : Query)
    (typed : V8PublicStatement) : Prop :=
  (CurrentNoWitnessLabelOutcome ns statement pending nonce wire oracle transcript
      execution pcs records fuel input query ∧
    ∃ role, noWitnessRoleFailure role ns statement pending nonce wire oracle
      transcript execution pcs records fuel input query) ∨
  ∃ _matrixGood : ¬ currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData (rootOracle ns
        (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
          fuel .root pcs.post.root)))
      (SmzaQ38McaSourceBinding.oracleMasks (rootOracle ns
        (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
          fuel .root pcs.post.root))) (sampledCoefficients (gammaRows pcs.post)),
    ∃ fpp openingPayload : Payload,
      V8SmzaOracleParser.parseFramed input =
        some (SmallWoodTranscript.piopInputDomain, fpp.bytes) ∧
      globalNormalizedPayload ns input = some ⟨.fpp, fpp.bytes⟩ ∧
      fpp.bytes.drop 16304 = statement.toBytes ∧
      V8SmzaOracleParser.parseFramed pcs.openingInput =
        some (SmallWoodTranscript.decsOpeningDomain, openingPayload.bytes) ∧
      globalNormalizedPayload ns pcs.openingInput =
        some ⟨.decs, openingPayload.bytes⟩ ∧
      claimedPolynomials (queryCoefficients openingPayload) =
        currentStageClaims pcs.heads (currentStageTails
          (sameProofRows execution.middle.pcs execution.piop)) ∧
      ∃ source : DecodedSource Goldilocks (Fin 5) 140,
        currentSourceDecoder406 (rootOracle ns
          (extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
            fuel .root pcs.post.root)) fpp
          (sampledCoefficients (gammaRows pcs.post)) = some source ∧
        (∀ combination, currentStageClaims pcs.heads (currentStageTails
          (sameProofRows execution.middle.pcs execution.piop)) combination =
          rowCombination source.data (baseOpeningPoints execution.opening.1)
            combination) ∧
        HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
          ((relationModel currentDsl certificates).recoveredCandidate
            statement source.data).system ∧
        CanonicalPublicStatement rustV8SemanticPrimitives typed ∧
        SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed)
          (packedFromRows source.data)

/-- Role-selected variant used by the X-view selector. Its no-witness arm is
fixed to the selected role; a full designated source remains an independent
successful extraction arm. -/
def CurrentFullOrRoleSelectedOutcome
    (ns : SmzaRp05LeafNamespace.Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns currentDsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    (records : Records) (fuel : Nat) (input : RawInput) (query : Query)
    (role : SmzaChallengeStageTargets.Role) (typed : V8PublicStatement) : Prop :=
  (CurrentNoWitnessLabelOutcome ns statement pending nonce wire oracle transcript
      execution pcs records fuel input query ∧
    noWitnessRoleFailure role ns statement pending nonce wire oracle transcript
      execution pcs records fuel input query) ∨
  ∃ _matrixGood : ¬ currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData (rootOracle ns
        (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
          fuel .root pcs.post.root)))
      (SmzaQ38McaSourceBinding.oracleMasks (rootOracle ns
        (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
          fuel .root pcs.post.root))) (sampledCoefficients (gammaRows pcs.post)),
    ∃ fpp openingPayload : Payload,
      V8SmzaOracleParser.parseFramed input =
        some (SmallWoodTranscript.piopInputDomain, fpp.bytes) ∧
      globalNormalizedPayload ns input = some ⟨.fpp, fpp.bytes⟩ ∧
      fpp.bytes.drop 16304 = statement.toBytes ∧
      V8SmzaOracleParser.parseFramed pcs.openingInput =
        some (SmallWoodTranscript.decsOpeningDomain, openingPayload.bytes) ∧
      globalNormalizedPayload ns pcs.openingInput =
        some ⟨.decs, openingPayload.bytes⟩ ∧
      claimedPolynomials (queryCoefficients openingPayload) =
        currentStageClaims pcs.heads (currentStageTails
          (sameProofRows execution.middle.pcs execution.piop)) ∧
      ∃ source : DecodedSource Goldilocks (Fin 5) 140,
        currentSourceDecoder406 (rootOracle ns
          (extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
            fuel .root pcs.post.root)) fpp
          (sampledCoefficients (gammaRows pcs.post)) = some source ∧
        (∀ combination, currentStageClaims pcs.heads (currentStageTails
          (sameProofRows execution.middle.pcs execution.piop)) combination =
          rowCombination source.data (baseOpeningPoints execution.opening.1)
            combination) ∧
        HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
          ((relationModel currentDsl certificates).recoveredCandidate
            statement source.data).system ∧
        CanonicalPublicStatement rustV8SemanticPrimitives typed ∧
        SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed)
          (packedFromRows source.data)

/-- Guard-free selected-role body. It retains the exact same X-view
completion, branch claims, accepted verifier replay, PCS stages, sampled
query, and current decoder outcome as the previous selector. Only its final
classification is generalized to preserve a full designated extraction. -/
def currentAcceptedXViewFailureRoleSelector
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (fuel : Nat)
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (role : SmzaChallengeStageTargets.Role)
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (view : SmzaRp05ConditionedExecution.XKey
      (SmzaRp05CurrentSelectedChallengeClaims.nonchallengeRawKeySet ctx) →
        Option (VectorOutput GroupCounter)) : Prop :=
  let actualProgram := producer.bind fun wire =>
    verifierProgram ns currentDsl statement pending nonce wire
  ∃ database : Database (Key actualProgram) (VectorOutput GroupCounter),
    (∀ key (member : key ∈
        SmzaRp05CurrentSelectedChallengeClaims.nonchallengeRawKeySet ctx),
      database key = view ⟨key, member⟩) ∧
    ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode actualProgram) groupedDecode actualProgram branch)
        (branchAnswers (encode actualProgram) groupedDecode actualProgram branch)) database ∧
    (let erasedRecords := eraseChallengeRecords (rawRecords
       (fun key => groupRepresentative (included actualProgram key))
       (vectorOutputBytes groupZero) database)
     let filteredRecords := oneStatementFilter (globalLeafStatement ns)
       statement.toBytes erasedRecords
     SmzaRecordedTracePath.RecordsCollisionFree filteredRecords ∧
     ∃ oracle : SmzaRp05ExecutableMerkleVerifier.Oracle,
      oracle = finiteGroupedDatabaseOracle actualProgram database fallback ∧
      ∃ wire transcript, producer.eval oracle = some wire ∧
        (verifierProgram ns currentDsl statement pending nonce wire).eval oracle = some () ∧
        (SmzaRp05ExecutablePcsClosure.transcriptProgram ns currentDsl statement pending
          statement.toBytes (statementBindingWords statement) nonce wire).eval oracle =
          some transcript ∧
        ∃ execution : ExecutionStages ns currentDsl statement pending statement.toBytes
          (statementBindingWords statement) nonce wire oracle transcript,
        ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
          (sameProofRows execution.middle.pcs execution.piop) execution.decs
          (List.ofFn fun j : Fin 6 => points execution.opening j)
          wire.salt statement.toBytes (statementBindingWords statement) wire.tapes
          wire.paths oracle execution.hashFpp execution.pcsPending,
        ∃ coordinates : Fin 38 → Position, ∃ query : Query, ∃ input : RawInput,
          StrictMono coordinates ∧ query.val = Finset.univ.image coordinates ∧
          (∀ j : Fin 38, (coordinates j).val = pcs.indexes.getD j.val 0) ∧
          (input, execution.hashFpp) ∈ filteredRecords ∧
          (input, execution.hashFpp) ∈ (pcs.hashProgram.record oracle).2 ∧
          CurrentDecoderOutcome
            (SmzaRp05CurrentRetainedQuerySupport.measuredDataTable ns filteredRecords
              fuel pcs.post.root)
            (SmzaRp05CurrentRetainedQuerySupport.measuredMaskTable ns filteredRecords
              fuel pcs.post.root)
            (responseRuleOfRawInputSelection (fun _ : Coefficients => input))
            (sampledCoefficients (gammaRows pcs.post)) pcs.heads
            (currentStageTails (sameProofRows execution.middle.pcs execution.piop))
            (fun opening => (List.ofFn fun j : Fin 6 => points execution.opening j).getD
              opening.val 0) query ∧
          CurrentNoWitnessLabelOutcome ns statement pending nonce wire oracle transcript
            execution pcs erasedRecords fuel input query ∧
          noWitnessRoleFailure role ns statement pending nonce wire oracle transcript
            execution pcs erasedRecords fuel input query)

/-- Under the former no-packed-witness condition, the retained full arm is
impossible; the new outcome then reduces to the old no-witness label plus its
role failure. -/
theorem currentFullOrRoleOutcome_iff_noPacked_label
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns currentDsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    (records : Records) (fuel : Nat) (input : RawInput) (query : Query)
    (typed : V8PublicStatement)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed) packed) :
    CurrentFullOrRoleOutcome ns statement pending nonce wire oracle transcript
        execution pcs records fuel input query typed ↔
      CurrentNoWitnessLabelOutcome ns statement pending nonce wire oracle transcript
        execution pcs records fuel input query ∧
        ∃ role, noWitnessRoleFailure role ns statement pending nonce wire oracle
          transcript execution pcs records fuel input query := by
  constructor
  · intro outcome
    rcases outcome with noWitness | full
    · exact noWitness
    · rcases full with ⟨matrixGood, fpp, openingPayload, inputParsed,
        inputNormalized, inputSuffix, openingParsed, openingNormalized,
        claimsRead, source, decodedSource, sourceClaims, satisfied,
        canonical, accepted⟩
      exact False.elim (noPackedWitness ⟨packedFromRows source.data, accepted⟩)
  · intro noWitness
    exact Or.inl noWitness

/-- Fixed-role specialization of the generalized selector outcome. -/
theorem currentFullOrRoleSelectedOutcome_iff_noPacked_label
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns currentDsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    (records : Records) (fuel : Nat) (input : RawInput) (query : Query)
    (role : SmzaChallengeStageTargets.Role) (typed : V8PublicStatement)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed) packed) :
    CurrentFullOrRoleSelectedOutcome ns statement pending nonce wire oracle transcript
        execution pcs records fuel input query role typed ↔
      CurrentNoWitnessLabelOutcome ns statement pending nonce wire oracle transcript
        execution pcs records fuel input query ∧
      noWitnessRoleFailure role ns statement pending nonce wire oracle transcript
        execution pcs records fuel input query := by
  constructor
  · intro outcome
    rcases outcome with noWitness | full
    · exact noWitness
    · rcases full with ⟨matrixGood, fpp, openingPayload, inputParsed,
        inputNormalized, inputSuffix, openingParsed, openingNormalized,
        claimsRead, source, decodedSource, sourceClaims, satisfied,
        canonical, accepted⟩
      exact False.elim (noPackedWitness ⟨packedFromRows source.data, accepted⟩)
  · intro noWitness
    exact Or.inl noWitness

/-- The guard-free selected-role body equals the historical selector under
its original hypotheses. The only eliminated data is the full witness arm. -/
theorem currentAcceptedXViewFailureRoleSelector_iff_old
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest) (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed) packed)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (keyBytesExact : ∀ key, ctx.keyBytes key = groupRepresentative
      (included (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire) key))
    (role : SmzaChallengeStageTargets.Role)
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (view : SmzaRp05ConditionedExecution.XKey
      (SmzaRp05CurrentSelectedChallengeClaims.nonchallengeRawKeySet ctx) →
        Option (VectorOutput GroupCounter))
    (work : SmzaRp05CurrentAdaptiveExecution.Work
      (Counter := GroupCounter) (BaseWork := BaseWork)) :
    currentAcceptedXViewFailureRoleSelector producer ns statement pending nonce
      fallback fuel ctx role branch view ↔
    currentAcceptedXViewRoleSelector producer ns statement pending nonce fallback
      typed parsed noPackedWitness fuel enough ctx keyBytesExact role branch view work := by
  unfold currentAcceptedXViewFailureRoleSelector
  unfold currentAcceptedXViewRoleSelector
  rfl

set_option maxHeartbeats 4000000 in
/-- Direct current extraction/classification on the same successful physical
grouped branch. Unlike the no-witness specialization this preserves the full
current 406-map source arm. -/
theorem accepted_grouped_branch_has_current_full_or_role_extraction
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace) (statement : Statement) (pending : Bool)
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
              (SmzaRp05CurrentRetainedQuerySupport.measuredDataTable ns filteredRecords
                fuel pcs.post.root)
              (SmzaRp05CurrentRetainedQuerySupport.measuredMaskTable ns filteredRecords
                fuel pcs.post.root)
              (responseRuleOfRawInputSelection (fun _ : Coefficients => input))
              (sampledCoefficients (gammaRows pcs.post)) pcs.heads
              (currentStageTails (sameProofRows execution.middle.pcs execution.piop))
              (fun opening => (List.ofFn fun j : Fin 6 =>
                points execution.opening j).getD opening.val 0) query ∧
            CurrentFullOrRoleOutcome ns statement pending nonce wire oracle transcript
              execution pcs erasedRecords fuel input query typed := by
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
  obtain ⟨wire, transcript, execution, pcs, decoded⟩ :=
    accepted_grouped_branch_supplies_statement_filtered_decoder producer ns currentDsl
      statement pending nonce branch accepted database claims fallback fuel enough
      bindingLength
  rcases decoded with collision | ⟨coordinates, query, input, ordered, image,
      indices, inputMember, hashMember, outcome⟩
  · exact ⟨wire, transcript, execution, pcs, Or.inl collision⟩
  · have labelResult := actual_filtered_decoder_outcome_has_current_label_or_relation
      certificates execution pcs erasedRecords fuel enough input hashMember query outcome
    refine ⟨wire, transcript, execution, pcs, Or.inr ⟨coordinates, query, input,
      ordered, image, indices, inputMember, hashMember, outcome, ?_⟩⟩
    rcases labelResult with matrixBad | ⟨matrixGood, fpp, openingPayload,
        inputParsed, inputNormalized, inputSuffix, openingParsed, openingNormalized,
        claimsRead, labelOutcome⟩
    · have noWitness : CurrentNoWitnessLabelOutcome ns statement pending nonce wire
        oracle transcript execution pcs erasedRecords fuel input query := Or.inl matrixBad
      obtain ⟨role, roleFailure⟩ := no_witness_label_has_role_failure ns statement
        pending nonce wire oracle transcript execution pcs erasedRecords fuel input
        query noWitness
      exact Or.inl ⟨noWitness, ⟨role, roleFailure⟩⟩
    · rcases labelOutcome with sourceBad | ⟨source, decodedSource, sourceClaims,
        relationOutcome⟩
      · have noWitness : CurrentNoWitnessLabelOutcome ns statement pending nonce wire
          oracle transcript execution pcs erasedRecords fuel input query := by
          exact Or.inr ⟨matrixGood, fpp, openingPayload, inputParsed,
            inputNormalized, inputSuffix, openingParsed, openingNormalized,
            claimsRead, Or.inl sourceBad⟩
        obtain ⟨role, roleFailure⟩ := no_witness_label_has_role_failure ns statement
          pending nonce wire oracle transcript execution pcs erasedRecords fuel input
          query noWitness
        exact Or.inl ⟨noWitness, ⟨role, roleFailure⟩⟩
      · rcases relationOutcome with full | failure
        · have acceptedTyped := current_full_rows_yield_typed_accepted_witness
            statement typed parsed source.data full
          exact Or.inr ⟨matrixGood, fpp, openingPayload, inputParsed,
            inputNormalized, inputSuffix, openingParsed, openingNormalized,
            claimsRead, source, decodedSource, sourceClaims, full,
            acceptedTyped.1, acceptedTyped.2⟩
        · have noWitness : CurrentNoWitnessLabelOutcome ns statement pending nonce wire
            oracle transcript execution pcs erasedRecords fuel input query := by
            exact Or.inr ⟨matrixGood, fpp, openingPayload, inputParsed,
              inputNormalized, inputSuffix, openingParsed, openingNormalized,
              claimsRead, Or.inr ⟨source, decodedSource, sourceClaims, failure⟩⟩
          obtain ⟨role, roleFailure⟩ := no_witness_label_has_role_failure ns statement
            pending nonce wire oracle transcript execution pcs erasedRecords fuel input
            query noWitness
          exact Or.inl ⟨noWitness, ⟨role, roleFailure⟩⟩

end
