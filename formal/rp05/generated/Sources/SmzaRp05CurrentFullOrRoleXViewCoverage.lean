import SmzaRp05CurrentFullOrRoleExtraction
import SmzaRp05CurrentAcceptedSameStageDecoder
import SmzaRp05CurrentAcceptedFilteredClassification
import SmzaRp05CurrentRetainedQuerySupport
import SmzaChallengeStageTargets
import SmzaRp04ChronologicalAlgebra
import SmzaRp05CurrentPublicStatementTransport
import HegemonCrypto.SmallWoodV8Smz9PiopReconstruction

/-! X-view coverage retaining the actual current full extraction arm.

The success selector is not an arbitrary accepted witness: it is the exact
successful `CurrentFullOrRoleOutcome` source arm from the deterministic
filtered decoder execution, with the same completion database and branch
claims as the selected X-view. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFullOrRoleXViewCoverage

open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
  (V8PublicStatement CanonicalPublicStatement encodePublicStatement)
open Hegemon.Transaction.Poseidon2V8RelationProgram
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentFullOrRoleExtraction (currentAcceptedXViewFailureRoleSelector)
open SmzaRp05CurrentAcceptedXViewRoleCoverage
  (noWitnessRoleFailure)
open SmzaRp05CurrentAcceptedFilteredClassification (CurrentNoWitnessLabelOutcome)
open SmzaRp05CurrentMaxAgreementRecovery (Position Query Coefficients)
open SmzaRp05CurrentAcceptedQueryExtraction (CurrentDecoderOutcome)
open SmzaRp05CurrentResponseInputDecoder (responseRuleOfRawInputSelection)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05CurrentTwelveCalculated (currentStageTails)
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05CurrentTracePrefixes406 (currentSourceDecoder406)
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
open SmzaRp05FilteredDecoderInstability (globalOnlineNext globalNormalizedPayload)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05GroupedSuffix (groupRepresentative groupZero GroupCounter)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution (XKey xView)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open SmzaRp05CurrentAcceptedSameStageDecoder
  (accepted_grouped_branch_has_same_stage_decoder_outcome)
open SmzaRp05CurrentAcceptedFilteredLabelReadback
  (actual_filtered_decoder_outcome_has_current_label_or_relation)
open SmzaRp05CurrentAcceptedXViewRoleCoverage
  (no_witness_label_has_role_failure)
open SmzaRp05CurrentRetainedQuerySupport (measuredDataTable measuredMaskTable)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05CurrentResponseInputDecoder (responseRuleOfRawInputSelection)
open SmzaChallengeStageTargets (Role)
open SmzaQ38McaSourceBinding (oracleData oracleMasks)
open SmzaRp05TracePrefixes (rootOracle)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext globalNormalizedPayload)
open SmzaRp05TracePrefixes (Payload queryCoefficients)
open SmzaRp04ChronologicalAlgebra (claimedPolynomials)
open SmzaQ38LvcsOpening (rowCombination)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)
open V8Smz9McaDecoder (DecodedSource)
open SmzaQ38Recovery (packedFromRows)
open SmzaRp05CurrentPublicStatementTransport (rustV8SemanticPrimitives)
open SmzaRp05Components (program)
open SmzaRp05CurrentAcceptedRelationWitness
  (current_full_rows_yield_typed_accepted_witness)
open HegemonCrypto.SmallWood.PiopExtraction (FullySatisfied)
open V8SmzaOracleParser (parseFramed)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open HegemonCrypto.SmallWood.V8Smz9PiopReconstruction (points)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8SmzaOracleParser (RawDigest RawInput)

open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/- The conjunction with negated no-witness outcome makes this selector's
final arm precisely the successful current designated extraction. It avoids
duplicating the large source carrier already checked in the extraction core. -/
local notation "Payload" => SmzaRp05TracePrefixes.Payload

def CurrentDesignatedFullSuccess
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
    (records : Records) (fuel : Nat) (input : RawInput)
    (typed : V8PublicStatement) : Prop :=
  ∃ _matrixGood : ¬ currentMatrixBad
      (oracleData (rootOracle ns (extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
        fuel .root pcs.post.root)))
      (oracleMasks (rootOracle ns (extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
        fuel .root pcs.post.root))) (sampledCoefficients (gammaRows pcs.post)),
    ∃ fpp openingPayload : Payload,
      parseFramed input = some (SmallWoodTranscript.piopInputDomain, fpp.bytes) ∧
      globalNormalizedPayload ns input = some ⟨.fpp, fpp.bytes⟩ ∧
      fpp.bytes.drop 16304 = statement.toBytes ∧
      parseFramed pcs.openingInput =
        some (SmallWoodTranscript.decsOpeningDomain, openingPayload.bytes) ∧
      globalNormalizedPayload ns pcs.openingInput =
        some ⟨.decs, openingPayload.bytes⟩ ∧
      claimedPolynomials (queryCoefficients openingPayload) =
        currentStageClaims pcs.heads (currentStageTails
          (sameProofRows execution.middle.pcs execution.piop)) ∧
      ∃ source : DecodedSource HegemonCrypto.SmallWood.Goldilocks (Fin 5) 140,
        currentSourceDecoder406 (rootOracle ns (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
          fuel .root pcs.post.root)) fpp (sampledCoefficients (gammaRows pcs.post)) =
            some source ∧
        (∀ combination, currentStageClaims pcs.heads (currentStageTails
          (sameProofRows execution.middle.pcs execution.piop)) combination =
          rowCombination source.data (baseOpeningPoints execution.opening.1) combination) ∧
        FullySatisfied ((relationModel currentDsl certificates).recoveredCandidate
          statement source.data).system ∧
        CanonicalPublicStatement rustV8SemanticPrimitives typed ∧
        SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed)
          (packedFromRows source.data)

def currentAcceptedXViewFullSuccessSelector
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest) (typed : V8PublicStatement)
    (fuel : Nat)
    (ctx : Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (view : XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput GroupCounter)) : Prop :=
  let actualProgram := producer.bind fun wire =>
    verifierProgram ns currentDsl statement pending nonce wire
  ∃ database : Database (Key actualProgram) (VectorOutput GroupCounter),
    (∀ key (member : key ∈ nonchallengeRawKeySet ctx),
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
          wire.salt statement.toBytes (statementBindingWords statement)
          wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending,
        ∃ coordinates : Fin 38 → Position, ∃ query : Query, ∃ input : RawInput,
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
            (fun opening => (List.ofFn fun j : Fin 6 => points execution.opening j).getD
              opening.val 0) query ∧
          CurrentDesignatedFullSuccess ns statement pending nonce wire oracle transcript
            execution pcs erasedRecords fuel input typed)

/-- Same accepted branch/claims and same nonchallenge X-view completion yield
filtered collision, a successful designated current full extraction, or one
of the existing guard-free role-failure selectors. No arbitrary packed
accepted witness is quantified by this coverage result. -/
theorem accepted_nonchallenge_consistent_branch_has_full_or_failure_selector_or_collision
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
    (fuel : Nat) (enough : 25 ≤ fuel)
    (ctx : Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    :
    ¬ SmzaRecordedTracePath.RecordsCollisionFree
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (eraseChallengeRecords (rawRecords
            (fun key => groupRepresentative (included
              (producer.bind fun wire =>
                verifierProgram ns currentDsl statement pending nonce wire) key))
            (vectorOutputBytes groupZero) database))) ∨
      currentAcceptedXViewFullSuccessSelector producer ns statement pending nonce
        fallback typed fuel ctx branch (xView (nonchallengeRawKeySet ctx) database) ∨
      ∃ role, currentAcceptedXViewFailureRoleSelector producer ns statement pending nonce
        fallback fuel ctx role branch (xView (nonchallengeRawKeySet ctx) database) := by
  classical
  let program := producer.bind fun wire =>
    verifierProgram ns currentDsl statement pending nonce wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let erasedRecords := eraseChallengeRecords (rawRecords
    (fun key => groupRepresentative (included program key))
    (vectorOutputBytes groupZero) database)
  let filteredRecords := oneStatementFilter (globalLeafStatement ns)
    statement.toBytes erasedRecords
  have bindingLength : (statementBindingWords statement).length = 138 :=
    SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement
  obtain ⟨wire, transcript, producerOk, verifierOk, transcriptOk,
    execution, pcs, decoded⟩ :=
    accepted_grouped_branch_has_same_stage_decoder_outcome producer ns currentDsl
      statement pending nonce branch accepted database claims fallback fuel enough
      bindingLength
  rcases decoded with collision | ⟨coordinates, query, input, ordered, image,
      indexes, inputMember, hashMember, currentOutcome⟩
  · exact Or.inl collision
  · by_cases filteredGood : SmzaRecordedTracePath.RecordsCollisionFree filteredRecords
    · have labelResult := actual_filtered_decoder_outcome_has_current_label_or_relation
        certificates execution pcs erasedRecords fuel enough input hashMember query
        currentOutcome
      rcases labelResult with matrixBad | ⟨matrixGood, fpp, openingPayload,
          inputParsed, inputNormalized, inputSuffix, openingParsed, openingNormalized,
          claimsRead, labelOutcome⟩
      · have noWitness : CurrentNoWitnessLabelOutcome ns statement pending nonce wire
          oracle transcript execution pcs erasedRecords fuel input query := Or.inl matrixBad
        obtain ⟨role, roleFailure⟩ := no_witness_label_has_role_failure ns statement
          pending nonce wire oracle transcript execution pcs erasedRecords fuel input query
          noWitness
        right; right
        refine ⟨role, database, ?_, claims, ?_⟩
        · intro key member; rfl
        · refine ⟨filteredGood, ⟨oracle, ?_, ?_⟩⟩
          · rfl
          · exact ⟨wire, transcript, producerOk, verifierOk, transcriptOk,
              execution, pcs, coordinates, query, input, ordered, image, indexes,
              inputMember, hashMember, currentOutcome, noWitness, roleFailure⟩
      · rcases labelOutcome with sourceBad | ⟨source, decodedSource, sourceClaims,
          relationOutcome⟩
        · have noWitness : CurrentNoWitnessLabelOutcome ns statement pending nonce wire
            oracle transcript execution pcs erasedRecords fuel input query :=
              Or.inr ⟨matrixGood, fpp, openingPayload, inputParsed, inputNormalized,
                inputSuffix, openingParsed, openingNormalized, claimsRead, Or.inl sourceBad⟩
          obtain ⟨role, roleFailure⟩ := no_witness_label_has_role_failure ns statement
            pending nonce wire oracle transcript execution pcs erasedRecords fuel input query
            noWitness
          right; right
          refine ⟨role, database, ?_, claims, ?_⟩
          · intro key member; rfl
          · refine ⟨filteredGood, ⟨oracle, ?_, ?_⟩⟩
            · rfl
            · exact ⟨wire, transcript, producerOk, verifierOk, transcriptOk,
                execution, pcs, coordinates, query, input, ordered, image, indexes,
                inputMember, hashMember, currentOutcome, noWitness, roleFailure⟩
        · rcases relationOutcome with full | failure
          · have acceptedTyped := current_full_rows_yield_typed_accepted_witness
              statement typed parsed source.data full
            right; left
            refine ⟨database, ?_, claims, ?_⟩
            · intro key member; rfl
            · refine ⟨filteredGood, ⟨oracle, ?_, ?_⟩⟩
              · rfl
              · exact ⟨wire, transcript, producerOk, verifierOk, transcriptOk,
                  execution, pcs, coordinates, query, input, ordered, image, indexes,
                  inputMember, hashMember, currentOutcome,
                  ⟨matrixGood, fpp, openingPayload, inputParsed, inputNormalized,
                    inputSuffix, openingParsed, openingNormalized, claimsRead,
                    source, decodedSource, sourceClaims, full,
                    acceptedTyped.1, acceptedTyped.2⟩⟩
          · have noWitness : CurrentNoWitnessLabelOutcome ns statement pending nonce wire
              oracle transcript execution pcs erasedRecords fuel input query :=
                Or.inr ⟨matrixGood, fpp, openingPayload, inputParsed, inputNormalized,
                  inputSuffix, openingParsed, openingNormalized, claimsRead,
                  Or.inr ⟨source, decodedSource, sourceClaims, failure⟩⟩
            obtain ⟨role, roleFailure⟩ := no_witness_label_has_role_failure ns statement
              pending nonce wire oracle transcript execution pcs erasedRecords fuel input
              query noWitness
            right; right
            refine ⟨role, database, ?_, claims, ?_⟩
            · intro key member; rfl
            · refine ⟨filteredGood, ⟨oracle, ?_, ?_⟩⟩
              · rfl
              · exact ⟨wire, transcript, producerOk, verifierOk, transcriptOk,
                  execution, pcs, coordinates, query, input, ordered, image, indexes,
                  inputMember, hashMember, currentOutcome, noWitness, roleFailure⟩
    · exact Or.inl filteredGood

end HegemonCrypto.SmallWood.SmzaRp05CurrentFullOrRoleXViewCoverage
