import SmzaRp05CurrentAcceptedSameStageClassification
import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05CurrentNonchallengeRecordView
import SmzaRp05CurrentGroupedContext

/-! # X-view selectors for accepted no-witness branches

The selected predicate is defined by a grouped database completion which
matches the nonchallenge X-view and the literal branch claims.  The accepted
classifier is therefore evaluated on the same branch answers; only its
challenge-erased, statement-filtered records are X-view-dependent.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedXViewRoleCoverage

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentGroupedClaimRetention (claims_supply_grouped_oracle_answers)
open SmzaRp05CurrentNonchallengeRecordView
  (grouped_one_statement_view_eq_of_nonchallenge_key_agreement)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05CurrentAcceptedSameStageClassification
  (accepted_grouped_branch_has_same_stage_no_witness_classification)
open SmzaRp05CurrentAcceptedFilteredClassification (CurrentNoWitnessLabelOutcome)
open SmzaRp05CurrentMaxAgreementRecovery (Position Query Coefficients)
open SmzaRp05CurrentAcceptedQueryExtraction (CurrentDecoderOutcome)
open SmzaRp05CurrentResponseInputDecoder (responseRuleOfRawInputSelection)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05CurrentTwelveCalculated (currentStageTails)
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05CurrentTracePrefixes406
  (currentSourceBad406 currentSourcePrefix406 currentSourceDecoder406)
open SmzaRp05CurrentQueryEventCore (currentStageClaims)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05CurrentAcceptedCausalPayloads (Records)
open SmzaRp05GeneratedCertificates (currentDsl certificates)
open SmzaRp05RelationRefinement (relationModel)
open SmzaRp05TracePrefixes (rootOracle queryCoefficients)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext globalNormalizedPayload)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open SmzaRp04ChronologicalAlgebra (claimedPolynomials piopMatrixBadEvent piopOpeningBadEvent)
open SmzaQ38LvcsOpening (rowCombination)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05GroupedSuffix (groupRepresentative groupZero GroupCounter)
open SmzaQ38McaSourceBinding (oracleData oracleMasks)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution (XKey xView)
open SmzaChallengeStageTargets (Role parseStageQuery)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8SmzaOracleParser (RawInput RawDigest)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open HegemonCrypto.SmallWoodTranscript (piopInputDomain decsOpeningDomain)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 30000
set_option linter.unusedSectionVars false

local instance : DecidableEq RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "Payload" => SmzaRp05TracePrefixes.Payload

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/- The four tags keep the accepted classifier's disjunction role-specific.
The matrix and source arms are the DECS roles; the final decoded-source arm
retains the exact PIOP matrix/opening witness from that same execution. -/
def noWitnessRoleFailure
    (role : Role) (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns currentDsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes
      wire.paths oracle execution.hashFpp execution.pcsPending)
    (records : Records) (fuel : Nat) (input : RawInput) (query : Query) : Prop :=
  let root := rootOracle ns
    (extract (globalOnlineNext ns)
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
      fuel .root pcs.post.root)
  let data := oracleData root
  let masks := oracleMasks root
  let coeff := sampledCoefficients (gammaRows pcs.post)
  let sampledPoints := fun opening =>
    ((List.ofFn fun j : Fin 6 =>
      V8Smz9PiopReconstruction.points execution.opening j)).getD opening.val 0
  match role with
  | .decsMatrix => currentMatrixBad data masks coeff
  | .decsSample =>
      ∃ matrixGood : ¬ currentMatrixBad data masks coeff,
        ∃ fpp openingPayload : Payload,
          V8SmzaOracleParser.parseFramed input =
            some (piopInputDomain, fpp.bytes) ∧
          globalNormalizedPayload ns input = some ⟨.fpp, fpp.bytes⟩ ∧
          fpp.bytes.drop 16304 = statement.toBytes ∧
          V8SmzaOracleParser.parseFramed pcs.openingInput =
            some (decsOpeningDomain, openingPayload.bytes) ∧
          globalNormalizedPayload ns pcs.openingInput =
            some ⟨.decs, openingPayload.bytes⟩ ∧
          claimedPolynomials (queryCoefficients openingPayload) =
            currentStageClaims pcs.heads (currentStageTails (sameProofRows
              execution.middle.pcs execution.piop)) ∧
          currentSourceBad406
            (currentSourcePrefix406 root fpp coeff sampledPoints
              (queryCoefficients openingPayload) matrixGood) query
  | .piopMatrix =>
      ∃ _matrixGood : ¬ currentMatrixBad data masks coeff,
        ∃ fpp openingPayload : Payload,
          V8SmzaOracleParser.parseFramed input =
            some (piopInputDomain, fpp.bytes) ∧
          globalNormalizedPayload ns input = some ⟨.fpp, fpp.bytes⟩ ∧
          fpp.bytes.drop 16304 = statement.toBytes ∧
          V8SmzaOracleParser.parseFramed pcs.openingInput =
            some (decsOpeningDomain, openingPayload.bytes) ∧
          globalNormalizedPayload ns pcs.openingInput =
            some ⟨.decs, openingPayload.bytes⟩ ∧
          claimedPolynomials (queryCoefficients openingPayload) =
            currentStageClaims pcs.heads (currentStageTails (sameProofRows
              execution.middle.pcs execution.piop)) ∧
          ∃ source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140,
            currentSourceDecoder406 root fpp coeff = some source ∧
            (∀ combination, currentStageClaims pcs.heads (currentStageTails
              (sameProofRows execution.middle.pcs execution.piop)) combination =
              rowCombination source.data (baseOpeningPoints execution.opening.1)
                combination) ∧
            ¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
              ((relationModel currentDsl certificates).recoveredCandidate
                statement source.data).system ∧
            execution.matrix ∈ piopMatrixBadEvent
              ((relationModel currentDsl certificates).recoveredCandidate
                statement source.data)
  | .piopOpening =>
      ∃ _matrixGood : ¬ currentMatrixBad data masks coeff,
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
            currentStageClaims pcs.heads (currentStageTails (sameProofRows
              execution.middle.pcs execution.piop)) ∧
          ∃ source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140,
            currentSourceDecoder406 root fpp coeff = some source ∧
            (∀ combination, currentStageClaims pcs.heads (currentStageTails
              (sameProofRows execution.middle.pcs execution.piop)) combination =
              rowCombination source.data (baseOpeningPoints execution.opening.1)
                combination) ∧
            ¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
              ((relationModel currentDsl certificates).recoveredCandidate
                statement source.data).system ∧
            execution.opening ∈ piopOpeningBadEvent
              ((relationModel currentDsl certificates).recoveredCandidate
                statement source.data) execution.matrix
              (SmzaRp05TracePrefixes.piopResponse
                ⟨.piop, SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩)

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl
  HegemonCrypto.SmallWood.SmzaRp05RelationRefinement.relationModel
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent

theorem no_witness_label_has_role_failure
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns currentDsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes
      wire.paths oracle execution.hashFpp execution.pcsPending)
    (records : Records) (fuel : Nat) (input : RawInput) (query : Query)
    (outcome : CurrentNoWitnessLabelOutcome ns statement pending nonce wire oracle
      transcript execution pcs records fuel input query) :
    ∃ role, noWitnessRoleFailure role ns statement pending nonce wire oracle
      transcript execution pcs records fuel input query := by
  dsimp only [CurrentNoWitnessLabelOutcome] at outcome
  rcases outcome with matrixFailure | ⟨matrixGood, fpp, openingPayload, parsedInput,
      normalizedInput, inputSuffix, parsedOpening, normalizedOpening, claimsRead,
      sourceBad | ⟨source, decodedSource, rows, notFull, pioPBad⟩⟩
  · exact ⟨.decsMatrix, matrixFailure⟩
  · exact ⟨.decsSample,
      ⟨matrixGood, fpp, openingPayload, parsedInput, normalizedInput, inputSuffix,
        parsedOpening, normalizedOpening, claimsRead, sourceBad⟩⟩
  · rcases pioPBad with matrixFailure | openingFailure
    · refine ⟨.piopMatrix, ?_⟩
      dsimp only [noWitnessRoleFailure]
      exact ⟨matrixGood, fpp, openingPayload, parsedInput, normalizedInput,
        inputSuffix, parsedOpening, normalizedOpening, claimsRead,
        ⟨source, decodedSource, rows, notFull, matrixFailure⟩⟩
    · refine ⟨.piopOpening, ?_⟩
      dsimp only [noWitnessRoleFailure]
      exact ⟨matrixGood, fpp, openingPayload, parsedInput, normalizedInput,
        inputSuffix, parsedOpening, normalizedOpening, claimsRead,
        ⟨source, decodedSource, rows, notFull, openingFailure⟩⟩

/-! Selector witness: every completed table matches the entire supplied X
restriction and realizes the same branch claims. Thus branch-stage values are
not postulated independently of the verifier execution. -/
def currentAcceptedXViewRoleSelector
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest) (typed : V8PublicStatement)
    (_parsed : SmzaRp05CurrentPublicStatementTransport.parseCurrentPublicStatement?
      statement = some typed)
    (_noPackedWitness : ¬ ∃ packed,
      SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed) packed)
    (fuel : Nat) (_enough : 25 ≤ fuel)
    (ctx : Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (_keyBytesExact : ∀ key, ctx.keyBytes key = groupRepresentative
      (included (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire) key))
    (role : Role)
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (view : XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput GroupCounter))
    (_work : Work (Counter := GroupCounter) (BaseWork := BaseWork)) : Prop :=
  let actualProgram := producer.bind fun wire =>
    verifierProgram ns currentDsl statement pending nonce wire
  ∃ database : Database (Key
      actualProgram)
      (VectorOutput GroupCounter),
    (∀ key (member : key ∈ nonchallengeRawKeySet ctx),
      database key = view ⟨key, member⟩) ∧
    ClaimsDatabaseEvent
      (branchClaims
        (branchKeys (encode actualProgram) groupedDecode actualProgram branch)
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
          (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
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
            (fun opening => ((List.ofFn fun j : Fin 6 =>
              V8Smz9PiopReconstruction.points execution.opening j)).getD opening.val 0)
            query ∧
          CurrentNoWitnessLabelOutcome ns statement pending nonce wire oracle transcript
            execution pcs erasedRecords fuel input query ∧
          noWitnessRoleFailure role ns statement pending nonce wire oracle transcript
            execution pcs erasedRecords fuel input query)

/-- Same nonchallenge X-view gives the exact same filtered decoder record set.
Recognized challenge cells remain unconstrained. -/
theorem grouped_filtered_records_eq_of_same_xview
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (ctx : Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (keyBytesExact : ∀ key, ctx.keyBytes key = groupRepresentative
      (included (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire) key))
    (left right : Database (Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (sameX : xView (nonchallengeRawKeySet ctx) left =
      xView (nonchallengeRawKeySet ctx) right) :
    oneStatementFilter (globalLeafStatement ns) statement.toBytes
      (eraseChallengeRecords (rawRecords
        (fun key => groupRepresentative (included
          (producer.bind fun wire =>
            verifierProgram ns currentDsl statement pending nonce wire) key))
        (vectorOutputBytes groupZero) left)) =
    oneStatementFilter (globalLeafStatement ns) statement.toBytes
      (eraseChallengeRecords (rawRecords
        (fun key => groupRepresentative (included
          (producer.bind fun wire =>
            verifierProgram ns currentDsl statement pending nonce wire) key))
        (vectorOutputBytes groupZero) right)) := by
  apply grouped_one_statement_view_eq_of_nonchallenge_key_agreement
  intro key nonchallenge
  have ctxNonchallenge : parseStageQuery (ctx.keyBytes key) = none := by
    rw [keyBytesExact]
    exact nonchallenge
  have member : key ∈ nonchallengeRawKeySet ctx :=
    Finset.mem_filter.mpr ⟨Finset.mem_univ _, ctxNonchallenge⟩
  have sameCell := congrFun sameX ⟨key, member⟩
  simpa [xView] using sameCell

/-- Replaying a fixed branch through either claims database returns the same
answer for every recorded call. This fixes all verifier-stage values used by
the selector independently of unqueried recognized challenge cells. -/
theorem same_branch_claims_fix_grouped_oracle_reads
    {Result : Type} (program : Program Result)
    (branch : Branches groupedDecode program)
    (left right : Database (Key program) (VectorOutput GroupCounter))
    (leftClaims : ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode program) groupedDecode program branch)
        (branchAnswers (encode program) groupedDecode program branch)) left)
    (rightClaims : ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode program) groupedDecode program branch)
        (branchAnswers (encode program) groupedDecode program branch)) right)
    (fallback : RawDigest) :
    ∀ call, call ∈ SmzaRp05PhysicalAcceptedReplayLite.answerLog
      groupedDecode program branch →
      finiteGroupedDatabaseOracle program left fallback call.1 =
        finiteGroupedDatabaseOracle program right fallback call.1 := by
  intro call member
  have leftRead := claims_supply_grouped_oracle_answers
    (encode program) program branch left leftClaims fallback call member
  have rightRead := claims_supply_grouped_oracle_answers
    (encode program) program branch right rightClaims fallback call member
  change (match left (encode program call.1) with
    | none => fallback
    | some vector => vectorOutputBytes (SmzaRp05GroupedSuffix.groupCounterOf call.1) vector) =
    (match right (encode program call.1) with
    | none => fallback
    | some vector => vectorOutputBytes (SmzaRp05GroupedSuffix.groupCounterOf call.1) vector)
  exact leftRead.symm.trans rightRead

/-- Coverage by the actual nonchallenge view.  On an accepted full-claims
branch, the same-stage classifier either exposes its filtered-record
collision or supplies a role tag whose selector has the actual database as
completion witness.  The completion agrees with the X-view at every key, not
only the branch's logged nonchallenge calls. -/
theorem accepted_grouped_failure_is_xview_selected_or_filtered_collision
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (accepted : branchResult groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
      branch = some ())
    (database : Database (Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
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
      SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed) packed)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (ctx : Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (keyBytesExact : ∀ key, ctx.keyBytes key = groupRepresentative
      (included (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire) key))
    (work : Work (Counter := GroupCounter) (BaseWork := BaseWork)) :
    ¬ SmzaRecordedTracePath.RecordsCollisionFree
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (eraseChallengeRecords (rawRecords
            (fun key => groupRepresentative (included
              (producer.bind fun wire =>
                verifierProgram ns currentDsl statement pending nonce wire) key))
            (vectorOutputBytes groupZero) database))) ∨
      ∃ role, currentAcceptedXViewRoleSelector producer ns statement pending nonce
        fallback typed parsed noPackedWitness fuel enough ctx keyBytesExact role branch
        (xView (nonchallengeRawKeySet ctx) database) work := by
  classical
  let program := producer.bind fun wire =>
    verifierProgram ns currentDsl statement pending nonce wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let erasedRecords := eraseChallengeRecords (rawRecords
    (fun key => groupRepresentative (included program key))
    (vectorOutputBytes groupZero) database)
  let filteredRecords := oneStatementFilter (globalLeafStatement ns)
    statement.toBytes erasedRecords
  have classified := accepted_grouped_branch_has_same_stage_no_witness_classification
    producer ns statement pending nonce branch accepted database claims fallback
    typed parsed noPackedWitness fuel enough
  dsimp only [program, oracle, erasedRecords, filteredRecords] at classified
  rcases classified with ⟨wire, transcript, producerOk, verifierOk,
      transcriptOk, execution, pcs, stageOutcome⟩
  rcases stageOutcome with filteredCollision |
      ⟨coordinates, query, input, ordered, image, indexes, inputMember,
        hashMember, currentOutcome, labelOutcome⟩
  · exact Or.inl filteredCollision
  · by_cases filteredGood : SmzaRecordedTracePath.RecordsCollisionFree filteredRecords
    · obtain ⟨role, roleFailure⟩ := no_witness_label_has_role_failure ns statement
        pending nonce wire oracle transcript execution pcs erasedRecords fuel input
        query labelOutcome
      apply Or.inr
      refine ⟨role, database, ?_, claims, ?_⟩
      · intro key member
        rfl
      · refine ⟨filteredGood, ⟨oracle, ?_, ?_⟩⟩
        · rfl
        · have roleFailure' : noWitnessRoleFailure role ns statement pending nonce
              wire oracle transcript execution pcs
              (eraseChallengeRecords (rawRecords
                (fun key => groupRepresentative (included program key))
                (vectorOutputBytes groupZero) database)) fuel input query := by
            simpa [erasedRecords] using roleFailure
          exact ⟨wire, transcript, producerOk, verifierOk, transcriptOk, execution,
            pcs, coordinates, query, input, ordered, image, indexes, inputMember,
            hashMember, currentOutcome, labelOutcome, roleFailure'⟩
    · exact Or.inl filteredGood

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedXViewRoleCoverage
