import SmzaRp05CurrentHistoryVerifierProgram
import SmzaRp05CurrentHistoryObserverReadback
import SmzaRp05CurrentJointAcceptedExecution
import SmzaRp05CurrentHistorySelectorContexts
import SmzaRp05CurrentAcceptedMassToScalar
import SmzaRp05ExecutableProgramEquality
import SmzaRp05CurrentProgramKeyReadbackTransport
import SmzaRp05CurrentGroupedContext
import SmzaRp05FiniteKeyStateEmbedding
import SmzaRp05CurrentClaimsXViewCompletion
import SmzaRp05CurrentPhysicalBranchClaimsConsistent
import SmzaRp05CurrentPhysicalNonchallengeClaims
import SmzaRp05CurrentNonchallengeRecordView
import SmzaRp05CurrentFullOrRoleXViewCoverage
import SmzaRp05CurrentFullOrRoleExtraction
import SmzaRp05CurrentAcceptedDecsExtractionFailureEvent
import SmzaRp05CurrentFilteredCollisionEventSpec
import SmzaRp05ChallengeRecordErasure
import SmzaRp05FilteredCollision
import SmzaRp05FilteredReadback
import SmzaRp04StatementRecordFilter

/-! # One global failure cover for an ordered verifier history

Per-stage terminal observers are used only as pointwise classifiers.  Their
read supports are already contained in the one actual history, so losses are
joined as a union on the common terminal database rather than added stage by
stage.  The collision and readout projections below are consequently charged
once against the full history.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryFailureCoverage

open scoped Classical
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult physicalRun)
open SmzaRp05CurrentHistoryVerifierProgram
  (HistoryStage historyProgram retainedPrefixAt stageVerifierAt terminalHistoryStageObserver
    indexedStageVerifierProgram terminalHistoryStageObserver_key_eq
    terminalHistoryStageObserver_groups_eq)
open SmzaRp05CurrentHistoryObserverReadback
  (accepted_history_has_exact_terminal_stage_observer_with_replay)
open SmzaRp05CurrentJointAcceptedExecution (sequentialUnitBranch)
open SmzaRp05CurrentHistorySelectorContexts
  (historyStageProducer actualProgram_history_stage_eq_observer
    history_stage_target_key_eq_history history_stage_context_keyBytes_eq
    history_stage_context_cast_eq)
open SmzaRp05CurrentAcceptedMassToScalar (currentAcceptedMassContexts)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05FiniteKeyStateEmbedding (key_type_eq_of_groups_eq)
open SmzaRp05FiniteKeyStateEmbedding (included_cast_key_type_eq_of_groups_eq
  encode_cast_key_type_eq_of_groups_eq)
open SmzaRp05CurrentProgramKeyReadbackTransport
  (acceptedBranchClaims_cast_program rawRecords_cast_key_database)
open SmzaRp05CurrentClaimsXViewCompletion (claims_completion_preserving_view)
open SmzaRp05CurrentPhysicalBranchClaimsConsistent
  (nonzero_physical_branch_claims_consistent)
open SmzaRp05CurrentPhysicalNonchallengeClaims (branchNonchallengeClaims)
open SmzaRp05CurrentNonchallengeRecordView
  (grouped_one_statement_view_eq_of_nonchallenge_key_agreement)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05CurrentFullOrRoleXViewCoverage
  (currentAcceptedXViewFullSuccessSelector
    accepted_nonchallenge_consistent_branch_has_full_or_failure_selector_or_collision)
open SmzaRp05CurrentFullOrRoleExtraction (currentAcceptedXViewFailureRoleSelector)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open SmzaRp05ConditionedExecution (xView XKey)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram
  (Key encode included included_encode_of_reachable answer_log_input_reachable)
open SmzaRp05ExecutableAddressCompiler (groups reachable)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification (V8PublicStatement)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open SmzaRp05FilteredCollision (filteredRawCollision)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp04StatementRecordFilter (oneStatementFilter recordsCollisionFree_mono)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaRp05GroupedSuffix (GroupKey groupKeyOf)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawDigest)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaChallengeStageTargets (Role)
open SmzaRp05CurrentSelectedChallengeClaims
  (nonchallengeRawKeySet nonchallenge_raw_key_set_unrecognized)
open SmzaRp05ConditionedExecution (xView XKey)
open SmzaRp05PhysicalAcceptedReplayLite (answerLog branch_claims_eq_answer_log)
open SmzaChallengeStageTargets (parseStageQuery)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxRecDepth 18000
set_option maxHeartbeats 1600000
set_option exponentiation.threshold 1024

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

private theorem context_keyBytes_cast_apply {KeyLeft KeyRight : Type}
    [Fintype KeyLeft] [DecidableEq KeyLeft]
    [Fintype KeyRight] [DecidableEq KeyRight]
    (sameKey : KeyLeft = KeyRight)
    (ctx : Context (Key := KeyLeft) (Counter := GroupCounter)
      (BaseWork := BaseWork)) :
    (cast (congrArg (fun key => Context (Key := key)
      (Counter := GroupCounter) (BaseWork := BaseWork)) sameKey) ctx).keyBytes =
      fun key => ctx.keyBytes (cast sameKey.symm key) := by
  cases sameKey
  rfl

private theorem cast_symm_cast_apply {Left Right : Type}
    (same : Left = Right) (value : Left) :
    cast same.symm (cast same value) = value := by
  cases same
  rfl

private theorem encode_cast_program {Result : Type}
    (left right : Program Result) (sameProgram : left = right)
    (raw : V8SmzaOracleParser.RawInput) :
    encode right raw = cast (congrArg Key sameProgram) (encode left raw) := by
  cases sameProgram
  rfl

private theorem included_cast_program {Result : Type}
    (left right : Program Result) (sameProgram : left = right)
    (key : Key left) :
    included right (cast (congrArg Key sameProgram) key) = included left key := by
  cases sameProgram
  rfl

/-- A statement-filtered collision in a terminal observer is included in
collision-freeness of the entire challenge-erased record set.  No stage index
remains in the resulting global event. -/
theorem observer_statement_collision_implies_history_collision
    {Result : Type} (ns : Namespace)
    (program : Program Result)
    (statement : List HegemonCrypto.CanonicalBytes.Byte)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (bad : ¬ SmzaRecordedTracePath.RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ns) statement
        (eraseChallengeRecords
          (rawRecords (fun key => groupRepresentative (included program key))
            (vectorOutputBytes groupZero) database)))) :
    ¬ SmzaRecordedTracePath.RecordsCollisionFree
      (eraseChallengeRecords
        (rawRecords (fun key => groupRepresentative (included program key))
          (vectorOutputBytes groupZero) database)) := by
  have subsetErased :
      oneStatementFilter (globalLeafStatement ns) statement
        (eraseChallengeRecords
          (rawRecords (fun key => groupRepresentative (included program key))
            (vectorOutputBytes groupZero) database)) ⊆
      eraseChallengeRecords
        (rawRecords (fun key => groupRepresentative (included program key))
          (vectorOutputBytes groupZero) database) := by
    intro record member
    exact (Finset.mem_filter.mp member).1
  intro erasedFree
  exact bad (recordsCollisionFree_mono subsetErased erasedFree)

/-- Claim completeness is monotone under the literal list inclusion supplied
by an accepted history observer's retained read prefix. -/
theorem claims_database_event_of_subset
    {Input Output : Type}
    (historyClaims observerClaims : List (Input × Output))
    (database : Database Input Output)
    (observerSubset : observerClaims ⊆ historyClaims)
    (historyComplete : ClaimsDatabaseEvent historyClaims database) :
    ClaimsDatabaseEvent observerClaims database := by
  intro claim member
  exact historyComplete claim (observerSubset member)

/-- Conversely, a missing observer claim whose read is in the actual history
is already the one global history-readout failure. -/
theorem missing_history_of_missing_subset_claim
    {Input Output : Type}
    (historyClaims observerClaims : List (Input × Output))
    (database : Database Input Output)
    (observerSubset : observerClaims ⊆ historyClaims)
    (observerMissing : ¬ ClaimsDatabaseEvent observerClaims database) :
    ¬ ClaimsDatabaseEvent historyClaims database := by
  intro historyComplete
  exact observerMissing (claims_database_event_of_subset historyClaims observerClaims
    database observerSubset historyComplete)

/-- The stage observer and original history have the same finite key carrier.
This explicit equivalence preserves the represented GroupKey, so byte
encoding and database coordinates are definitionally compatible after the
cast. -/
def historyObserverKeyEquiv (stages : List HistoryStage)
    (i : Fin stages.length) :
    Key (terminalHistoryStageObserver stages i) ≃ Key (historyProgram stages) where
  toFun key := ⟨key.val, by
    simpa only [terminalHistoryStageObserver_groups_eq stages i] using key.property⟩
  invFun key := ⟨key.val, by
    simpa only [← terminalHistoryStageObserver_groups_eq stages i] using key.property⟩
  left_inv key := by apply Subtype.ext; rfl
  right_inv key := by apply Subtype.ext; rfl

/-- The raw grouped encoding agrees under the observer-to-history key
equivalence for every actual observer read. -/
theorem historyObserver_encode_cast
    (stages : List HistoryStage) (i : Fin stages.length)
    (raw : V8SmzaOracleParser.RawInput)
    (reachable : raw ∈ reachable
      (terminalHistoryStageObserver stages i)) :
    historyObserverKeyEquiv stages i (encode (terminalHistoryStageObserver stages i) raw) =
      encode (historyProgram stages) raw := by
  apply Subtype.ext
  have observerGroup := included_encode_of_reachable
    (terminalHistoryStageObserver stages i) raw reachable
  have groupMember : groupKeyOf raw ∈ groups (historyProgram stages) := by
    rw [← terminalHistoryStageObserver_groups_eq stages i]
    unfold groups
    exact Finset.mem_image.mpr ⟨raw, reachable, rfl⟩
  have historyUniverse : groupKeyOf raw ∈
      insert (groupKeyOf []) (groups (historyProgram stages)) :=
    Finset.mem_insert_of_mem groupMember
  have historyGroup : included (historyProgram stages)
      (encode (historyProgram stages) raw) = groupKeyOf raw := by
    simp [encode, included, historyUniverse]
  exact observerGroup.trans historyGroup.symm

/-- Pull a history database back to one terminal observer without changing
any represented group or byte-string coordinate. -/
def historyDatabaseOnObserver (stages : List HistoryStage) (i : Fin stages.length)
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter)) :
    Database (Key (terminalHistoryStageObserver stages i)) (VectorOutput GroupCounter) :=
  fun key => database (historyObserverKeyEquiv stages i key)

/-- Reindexing the same database by the exact observer/history Key
equivalence does not change its literal raw record relation. -/
theorem history_observer_raw_records_eq
    (stages : List HistoryStage) (i : Fin stages.length)
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter)) :
    rawRecords (fun key => groupRepresentative
        (included (terminalHistoryStageObserver stages i) key))
        (vectorOutputBytes groupZero) (historyDatabaseOnObserver stages i database) =
      rawRecords (fun key => groupRepresentative
        (included (historyProgram stages) key))
        (vectorOutputBytes groupZero) database := by
  classical
  ext record
  rw [V8Smz9CoherentMerkleInstrument.rawRecords,
    V8Smz9CoherentMerkleInstrument.rawRecords]
  simp only [Finset.mem_image]
  constructor
  · rintro ⟨⟨key, output⟩, stored, recorded⟩
    rcases Finset.mem_filter.mp stored with ⟨_, known⟩
    refine ⟨⟨historyObserverKeyEquiv stages i key, output⟩,
      Finset.mem_filter.mpr ⟨Finset.mem_univ _, ?_⟩, ?_⟩
    · simpa [historyDatabaseOnObserver] using known
    · have keyBytes : groupRepresentative
          (included (terminalHistoryStageObserver stages i) key) =
          groupRepresentative (included (historyProgram stages)
            (historyObserverKeyEquiv stages i key)) := rfl
      exact (congrArg (fun raw => (raw, vectorOutputBytes groupZero output)) keyBytes).trans
        recorded
  · rintro ⟨⟨key, output⟩, stored, recorded⟩
    rcases Finset.mem_filter.mp stored with ⟨_, known⟩
    refine ⟨⟨(historyObserverKeyEquiv stages i).symm key, output⟩,
      Finset.mem_filter.mpr ⟨Finset.mem_univ _, ?_⟩, ?_⟩
    · simpa [historyDatabaseOnObserver] using known
    · have keyBytes : groupRepresentative
          (included (terminalHistoryStageObserver stages i)
            ((historyObserverKeyEquiv stages i).symm key)) =
          groupRepresentative (included (historyProgram stages) key) := rfl
      exact (congrArg (fun raw => (raw, vectorOutputBytes groupZero output)) keyBytes).trans
        recorded

/-- The observer's literal branch claims, translated by the exact Key
equivalence, are a subset of the original history branch claims whenever
the readback helper says its answer log is a retained prefix. -/
theorem terminal_observer_claims_subset_history
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (observerBranch : Branches groupedDecode (terminalHistoryStageObserver stages i))
    (answerLogSubset : ∀ call,
      call ∈ answerLog groupedDecode (terminalHistoryStageObserver stages i) observerBranch →
      call ∈ answerLog groupedDecode (historyProgram stages) historyBranch) :
    List.map (fun claim =>
      (historyObserverKeyEquiv stages i claim.1, claim.2))
      (branchClaims (branchKeys (encode (terminalHistoryStageObserver stages i))
        groupedDecode (terminalHistoryStageObserver stages i) observerBranch)
        (branchAnswers (encode (terminalHistoryStageObserver stages i)) groupedDecode
          (terminalHistoryStageObserver stages i) observerBranch)) ⊆
    branchClaims (branchKeys (encode (historyProgram stages)) groupedDecode
      (historyProgram stages) historyBranch)
      (branchAnswers (encode (historyProgram stages)) groupedDecode
        (historyProgram stages) historyBranch) := by
  intro claim member
  rw [branch_claims_eq_answer_log] at member ⊢
  rcases List.mem_map.mp member with ⟨observerClaim, observerClaimMember, mappedEq⟩
  rcases List.mem_map.mp observerClaimMember with ⟨call, callMember, observerClaimEq⟩
  have historyCall := answerLogSubset call callMember
  have historyMem :
      (encode (historyProgram stages) call.1, call.2) ∈
        List.map
          (fun (call : V8SmzaOracleParser.RawInput × VectorOutput GroupCounter) =>
            (encode (historyProgram stages) call.1, call.2))
          (answerLog groupedDecode (historyProgram stages) historyBranch) := by
    exact List.mem_map.mpr ⟨call, historyCall, rfl⟩
  have reachable := answer_log_input_reachable groupedDecode
    (terminalHistoryStageObserver stages i) observerBranch call callMember
  have encodedEq := historyObserver_encode_cast stages i call.1 reachable
  have claimEq : claim = (encode (historyProgram stages) call.1, call.2) := by
    calc
      claim = (historyObserverKeyEquiv stages i observerClaim.1, observerClaim.2) := mappedEq.symm
      _ = (historyObserverKeyEquiv stages i (encode (terminalHistoryStageObserver stages i)
          call.1), call.2) := by
            exact (congrArg
              (fun pair : Key (terminalHistoryStageObserver stages i) ×
                  VectorOutput GroupCounter =>
                (historyObserverKeyEquiv stages i pair.1, pair.2))
              observerClaimEq).symm
      _ = (encode (historyProgram stages) call.1, call.2) := by
            exact congrArg (fun key : Key (historyProgram stages) => (key, call.2)) encodedEq
  rw [claimEq]
  exact historyMem

/-- Completeness of the single history readout supplies every terminal
observer claim after the exact finite-key cast. -/
theorem terminal_observer_claims_complete_from_history
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (observerBranch : Branches groupedDecode (terminalHistoryStageObserver stages i))
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter))
    (answerLogSubset : ∀ call,
      call ∈ answerLog groupedDecode (terminalHistoryStageObserver stages i) observerBranch →
      call ∈ answerLog groupedDecode (historyProgram stages) historyBranch)
    (historyComplete : ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode (historyProgram stages)) groupedDecode
        (historyProgram stages) historyBranch)
        (branchAnswers (encode (historyProgram stages)) groupedDecode
          (historyProgram stages) historyBranch)) database) :
    ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode (terminalHistoryStageObserver stages i)) groupedDecode
        (terminalHistoryStageObserver stages i) observerBranch)
        (branchAnswers (encode (terminalHistoryStageObserver stages i)) groupedDecode
          (terminalHistoryStageObserver stages i) observerBranch))
      (historyDatabaseOnObserver stages i database) := by
  intro claim member
  have subset := terminal_observer_claims_subset_history stages i historyBranch observerBranch
    answerLogSubset
  have translatedClaim := subset (by
    rw [List.mem_map]
    exact ⟨claim, member, rfl⟩)
  have known := historyComplete
    (historyObserverKeyEquiv stages i claim.1, claim.2) translatedClaim
  simpa only [historyDatabaseOnObserver] using known

/-- A missing recognized (or unrecognized) observer claim is included in
the single history-readout failure because the observer reuses only history
answer-log calls. -/
theorem terminal_observer_readout_missing_implies_history_missing
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (observerBranch : Branches groupedDecode (terminalHistoryStageObserver stages i))
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter))
    (answerLogSubset : ∀ call,
      call ∈ answerLog groupedDecode (terminalHistoryStageObserver stages i) observerBranch →
      call ∈ answerLog groupedDecode (historyProgram stages) historyBranch)
    (observerMissing : ¬ ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode (terminalHistoryStageObserver stages i)) groupedDecode
        (terminalHistoryStageObserver stages i) observerBranch)
        (branchAnswers (encode (terminalHistoryStageObserver stages i)) groupedDecode
          (terminalHistoryStageObserver stages i) observerBranch))
      (historyDatabaseOnObserver stages i database)) :
    ¬ ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode (historyProgram stages)) groupedDecode
        (historyProgram stages) historyBranch)
        (branchAnswers (encode (historyProgram stages)) groupedDecode
          (historyProgram stages) historyBranch)) database := by
  intro historyComplete
  exact observerMissing (terminal_observer_claims_complete_from_history stages i
    historyBranch observerBranch database answerLogSubset historyComplete)

/-- Pointwise full-or-role coverage on one terminal stage observer.  When
the actual history readout is complete, the observer's retained read log is
complete as well.  If designated full extraction is absent, the existing
classifier gives either a role-failure selector or a stage collision; the
latter is immediately embedded in the one raw-record collision event for
this shared database.  If history readout is incomplete, that single global
readout alternative is returned instead. -/
theorem terminal_stage_failure_is_global_collision_or_role_or_readout
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (accepted : branchResult groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
      branch = some ())
    (historyClaims : List
      (Key (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
        × VectorOutput GroupCounter))
    (database : Database (Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (observerSubset : branchClaims
      (branchKeys (encode (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire)) groupedDecode
        (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
        branch)
      (branchAnswers (encode (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire)) groupedDecode
        (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
        branch) ⊆ historyClaims)
    (notFull : ¬ currentAcceptedXViewFullSuccessSelector producer ns statement pending nonce
      fallback typed fuel ctx branch (xView (nonchallengeRawKeySet ctx) database)) :
    ¬ SmzaRecordedTracePath.RecordsCollisionFree
        (eraseChallengeRecords
          (rawRecords (fun key => groupRepresentative
            (included (producer.bind fun wire =>
                verifierProgram ns currentDsl statement pending nonce wire) key))
            (vectorOutputBytes groupZero) database)) ∨
      (∃ role, currentAcceptedXViewFailureRoleSelector producer ns statement pending nonce
        fallback fuel ctx role branch (xView (nonchallengeRawKeySet ctx) database)) ∨
      ¬ ClaimsDatabaseEvent historyClaims database := by
  by_cases historyComplete : ClaimsDatabaseEvent historyClaims database
  · have observerComplete : ClaimsDatabaseEvent _ database :=
      claims_database_event_of_subset historyClaims _ database
        observerSubset historyComplete
    have covered := accepted_nonchallenge_consistent_branch_has_full_or_failure_selector_or_collision
      producer ns statement pending nonce branch accepted database observerComplete
      fallback typed parsed fuel enough ctx
    rcases covered with collisionAt | fullAt | ⟨role, roleFailed⟩
    · exact Or.inl (observer_statement_collision_implies_history_collision
        ns (producer.bind fun wire =>
          verifierProgram ns currentDsl statement pending nonce wire) statement.toBytes
        database collisionAt)
    · exact False.elim (notFull fullAt)
    · exact Or.inr (Or.inl ⟨role, roleFailed⟩)
  · exact Or.inr (Or.inr historyComplete)

/-- Exact retained data for a stage of one accepted history.  Besides the
terminal observer branch this records the original producer wire and both
original sub-branches; the observer is therefore never a fresh execution. -/
structure AcceptedHistoryStageReadback
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches groupedDecode (historyProgram stages)) where
  observerBranch : Branches groupedDecode (terminalHistoryStageObserver stages i)
  observerAccepted : branchResult groupedDecode
    (terminalHistoryStageObserver stages i) observerBranch = some ()
  historyAccepted : branchResult groupedDecode (historyProgram stages) historyBranch = some ()
  answerLogSubset : ∀ call,
    call ∈ answerLog groupedDecode (terminalHistoryStageObserver stages i) observerBranch →
    call ∈ answerLog groupedDecode (historyProgram stages) historyBranch
  replayStageBranch : Branches groupedDecode (indexedStageVerifierProgram stages i)
  observerBranchEq : observerBranch = sequentialUnitBranch groupedDecode
    (historyProgram stages) historyBranch (indexedStageVerifierProgram stages i)
    replayStageBranch
  replayStageAccepted : branchResult groupedDecode
    (indexedStageVerifierProgram stages i) replayStageBranch = some ()
  wire : ExistingProofFieldView
  producerBranch : Branches groupedDecode (stages[i.val].proofProducer)
  producerAccepted : branchResult groupedDecode (stages[i.val].proofProducer)
    producerBranch = some wire
  verifierBranch : Branches groupedDecode (stageVerifierAt stages i wire)
  verifierAccepted : branchResult groupedDecode (stageVerifierAt stages i wire)
    verifierBranch = some ()

/-- The checked readback helper constructs all of the retained stage fields
from the original accepted history branch. -/
theorem accepted_history_stage_readback
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (historyAccepted : branchResult groupedDecode (historyProgram stages) historyBranch = some ()) :
    Nonempty (AcceptedHistoryStageReadback stages i historyBranch) := by
  obtain ⟨observerBranch, observerAccepted, answerLogSubset,
    ⟨wire, producerBranch, verifierBranch, producerAccepted, verifierAccepted⟩,
    ⟨replayStageBranch, observerBranchEq, replayStageAccepted⟩⟩ :=
    accepted_history_has_exact_terminal_stage_observer_with_replay groupedDecode
      stages i historyBranch historyAccepted
  exact ⟨⟨observerBranch, observerAccepted, historyAccepted, answerLogSubset,
    replayStageBranch, observerBranchEq, replayStageAccepted, wire, producerBranch,
    producerAccepted, verifierBranch, verifierAccepted⟩⟩

theorem historyStageProgramEq
    (stages : List HistoryStage) (i : Fin stages.length) :
    actualProgram (historyStageProducer stages i) (stages[i.val]).ns
      (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce =
    terminalHistoryStageObserver stages i :=
  actualProgram_history_stage_eq_observer stages i

def historyStageKeyCast
    (stages : List HistoryStage) (i : Fin stages.length)
    (key : Key (actualProgram (historyStageProducer stages i)
      (stages[i.val]).ns (stages[i.val]).statement (stages[i.val]).pending
      (stages[i.val]).nonce)) : Key (historyProgram stages) :=
  cast (history_stage_target_key_eq_history stages i) key

def historyStageContext
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (stages : List HistoryStage) (i : Fin stages.length)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role) (role : Role) :
    SmzaRp05CurrentAdaptiveExecution.Context (Key := Key
      ((historyStageProducer stages i).bind fun wire =>
        verifierProgram (stages[i.val]).ns currentDsl (stages[i.val]).statement
          (stages[i.val]).pending (stages[i.val]).nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork) :=
  currentGroupedContext (BaseWork := BaseWork)
    ((historyStageProducer stages i).bind fun wire =>
      verifierProgram (stages[i.val]).ns currentDsl (stages[i.val]).statement
        (stages[i.val]).pending (stages[i.val]).nonce wire)
    model bounded (stages[i.val]).ns role (advice role) 28 28 (fun _ => ∅)

theorem historyStageKeyBytesEq
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (stages : List HistoryStage) (i : Fin stages.length)
    (commonNs : Namespace) (stageNsEq : (stages[i.val]).ns = commonNs)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role) (role : Role)
    (key : Key (actualProgram (historyStageProducer stages i)
      (stages[i.val]).ns (stages[i.val]).statement (stages[i.val]).pending
      (stages[i.val]).nonce)) :
    (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role).keyBytes key =
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅)).keyBytes
        (historyStageKeyCast stages i key) := by
  have bytes := history_stage_context_keyBytes_eq (BaseWork := BaseWork)
    stages i commonNs stageNsEq model bounded advice role
  let keyEq := history_stage_target_key_eq_history stages i
  let stageCtx := currentAcceptedMassContexts (BaseWork := BaseWork)
    (historyStageProducer stages i) (stages[i.val]).ns (stages[i.val]).statement
    (stages[i.val]).pending (stages[i.val]).nonce model bounded advice 28 28 role
  have castKeyBytes :
      (cast (congrArg (fun key => Context (Key := key)
        (Counter := GroupCounter) (BaseWork := BaseWork)) keyEq) stageCtx).keyBytes
          (historyStageKeyCast stages i key) = stageCtx.keyBytes key := by
    rw [context_keyBytes_cast_apply keyEq stageCtx]
    change stageCtx.keyBytes
      (cast keyEq.symm (cast keyEq key)) = stageCtx.keyBytes key
    exact congrArg stageCtx.keyBytes (cast_symm_cast_apply keyEq key)
  have atKey := congrFun bytes (historyStageKeyCast stages i key)
  calc
    (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role).keyBytes key =
        (cast (congrArg (fun key => Context (Key := key)
          (Counter := GroupCounter) (BaseWork := BaseWork)) keyEq) stageCtx).keyBytes
            (historyStageKeyCast stages i key) := by
          exact castKeyBytes.symm
    _ = (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅)).keyBytes
          (historyStageKeyCast stages i key) := atKey

theorem historyStageNonchallengeMem
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (stages : List HistoryStage) (i : Fin stages.length)
    (commonNs : Namespace) (stageNsEq : (stages[i.val]).ns = commonNs)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role) (role : Role)
    (key : Key (actualProgram (historyStageProducer stages i)
      (stages[i.val]).ns (stages[i.val]).statement (stages[i.val]).pending
      (stages[i.val]).nonce))
    (member : key ∈ nonchallengeRawKeySet
      (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role)) :
    historyStageKeyCast stages i key ∈ nonchallengeRawKeySet
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅)) := by
  have stageNone := nonchallenge_raw_key_set_unrecognized
    (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role) key member
  have bytesEq := historyStageKeyBytesEq (BaseWork := BaseWork)
    stages i commonNs stageNsEq model bounded advice role key
  apply Finset.mem_filter.mpr
  refine ⟨Finset.mem_univ _, ?_⟩
  change parseStageQuery ((currentGroupedContext (BaseWork := BaseWork)
    (historyProgram stages) model bounded commonNs role (advice role) 28 28
    (fun _ => ∅)).keyBytes (historyStageKeyCast stages i key)) = none
  rw [← bytesEq]
  exact stageNone

/-- Pull a history X-view back through the canonical stage-to-history Key
cast.  The context adapter proves the byte classifier is identical, so this
does not change which raw calls are nonchallenge. -/
def historyStageView
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (stages : List HistoryStage) (i : Fin stages.length)
    (commonNs : Namespace) (stageNsEq : (stages[i.val]).ns = commonNs)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role) (role : Role)
    (view : SmzaRp05ConditionedExecution.XKey (nonchallengeRawKeySet
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅))) →
      Option (VectorOutput GroupCounter)) :
    SmzaRp05ConditionedExecution.XKey (nonchallengeRawKeySet
      (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role)) →
      Option (VectorOutput GroupCounter) :=
  fun key => view ⟨historyStageKeyCast stages i key.val,
    historyStageNonchallengeMem (BaseWork := BaseWork) stages i commonNs stageNsEq
      model bounded advice role key.val key.property⟩

/-- A same-history role selector.  It retains the complete original history
claim event and the exact accepted stage readback, while the selected role
failure is evaluated on the global history X-view transported to that
stage's finite-key coordinates. -/
def currentHistoryFailureRoleSelector
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (fallback : RawDigest) (fuel : Nat)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (role : Role)
    (view : SmzaRp05ConditionedExecution.XKey (nonchallengeRawKeySet
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅))) →
      Option (VectorOutput GroupCounter)) : Prop :=
  ∃ completion : Database (Key (historyProgram stages)) (VectorOutput GroupCounter),
    (∀ key (member : key ∈ nonchallengeRawKeySet
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅))),
      completion key = view ⟨key, member⟩) ∧
    ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode (historyProgram stages)) groupedDecode
        (historyProgram stages) historyBranch)
        (branchAnswers (encode (historyProgram stages)) groupedDecode
          (historyProgram stages) historyBranch)) completion ∧
    ∃ i : Fin stages.length,
      ∃ readback : AcceptedHistoryStageReadback stages i historyBranch,
        currentAcceptedXViewFailureRoleSelector
          (historyStageProducer stages i) (stages[i.val]).ns
          (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce
          fallback fuel (historyStageContext stages i model bounded advice role)
          role
          (SmzaRp05ExecutableProgramEquality.castProgramBranch groupedDecode
            (terminalHistoryStageObserver stages i)
            (actualProgram (historyStageProducer stages i) (stages[i.val]).ns
              (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce)
            (historyStageProgramEq stages i).symm readback.observerBranch)
          (historyStageView (BaseWork := BaseWork) stages i commonNs (stageNsEq i)
            model bounded advice role view)

/-- Existential no-full-success event on the common original-history X-view.
The witness contains the accepted terminal observer recovered from the one
accepted history branch, including its actual retained wire and read-log
inclusion; it is not an independently sampled execution. -/
def currentHistoryFailureWitness
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (fallback : RawDigest) (typed : Fin stages.length → V8PublicStatement)
    (fuel : Nat) (historyBranch : Branches groupedDecode (historyProgram stages))
    (view : SmzaRp05ConditionedExecution.XKey (nonchallengeRawKeySet
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs .decsMatrix (advice .decsMatrix) 28 28 (fun _ => ∅))) →
      Option (VectorOutput GroupCounter)) : Prop :=
  branchResult groupedDecode (historyProgram stages) historyBranch = some () ∧
  ∃ i : Fin stages.length,
    ∃ readback : AcceptedHistoryStageReadback stages i historyBranch,
      ¬ currentAcceptedXViewFullSuccessSelector
        (historyStageProducer stages i) (stages[i.val]).ns
        (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce
        fallback (typed i) fuel
        (historyStageContext stages i model bounded advice .decsMatrix)
        (SmzaRp05ExecutableProgramEquality.castProgramBranch groupedDecode
          (terminalHistoryStageObserver stages i)
          (actualProgram (historyStageProducer stages i) (stages[i.val]).ns
            (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce)
          (historyStageProgramEq stages i).symm readback.observerBranch)
        (historyStageView (BaseWork := BaseWork) stages i commonNs (stageNsEq i)
          model bounded advice .decsMatrix view)

/-- A terminal-stage failure on any retained prefix is covered by one global
history collision, one of the four common-key role selectors, or the single
nonchallenge readout loss for the original history.  Completion fills only
recognized/unread coordinates; every original nonchallenge value is kept. -/
theorem accepted_history_failure_witness_implies_global_collision_or_role_or_nonchallenge_readout
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (typed : ∀ _i : Fin stages.length, V8PublicStatement)
    (parsed : ∀ i : Fin stages.length,
      parseCurrentPublicStatement? (stages[i.val]).statement = some (typed i))
    (fuel : Nat) (enough : 25 ≤ fuel)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (fallback : RawDigest)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (initial : HegemonCrypto.CmsCompressedOracle.State
      (Key (historyProgram stages)) (VectorOutput GroupCounter)
      (VectorOutput GroupCounter)
      (SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := GroupCounter) (BaseWork := BaseWork)))
    (originalMassNe : HegemonCrypto.CmsCompressedOracle.normSquared
      (physicalRun
        (encode (historyProgram stages)) groupedDecode (historyProgram stages)
        historyBranch initial) ≠ 0)
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter))
    (failure : currentHistoryFailureWitness (BaseWork := BaseWork)
      stages commonNs stageNsEq model bounded advice fallback typed fuel historyBranch
      (xView (nonchallengeRawKeySet
        (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
          model bounded commonNs .decsMatrix (advice .decsMatrix) 28 28 (fun _ => ∅)))
        database)) :
    ¬ SmzaRecordedTracePath.RecordsCollisionFree
      (eraseChallengeRecords
        (rawRecords (fun key => groupRepresentative (included (historyProgram stages) key))
          (vectorOutputBytes groupZero) database)) ∨
    (∃ role : Role, currentHistoryFailureRoleSelector (BaseWork := BaseWork)
      stages commonNs stageNsEq model bounded advice fallback fuel historyBranch role
      (xView (nonchallengeRawKeySet
        (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
          model bounded commonNs role (advice role) 28 28 (fun _ => ∅))) database)) ∨
    ¬ ClaimsDatabaseEvent
      (branchNonchallengeClaims
        (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
          model bounded commonNs .decsMatrix (advice .decsMatrix) 28 28
          (fun _ => ∅)).keyBytes (encode (historyProgram stages)) groupedDecode
        (historyProgram stages) historyBranch) database := by
  classical
  let historyCtx := currentGroupedContext (BaseWork := BaseWork)
    (historyProgram stages) model bounded commonNs .decsMatrix
    (advice .decsMatrix) 28 28 (fun _ => ∅)
  let historyView := xView (nonchallengeRawKeySet historyCtx) database
  let claims := branchClaims (branchKeys (encode (historyProgram stages)) groupedDecode
      (historyProgram stages) historyBranch)
    (branchAnswers (encode (historyProgram stages)) groupedDecode
      (historyProgram stages) historyBranch)
  by_cases nonchallengeComplete : ClaimsDatabaseEvent
      (branchNonchallengeClaims historyCtx.keyBytes (encode (historyProgram stages))
        groupedDecode (historyProgram stages) historyBranch) database
  · have consistent : ∃ completion : Database (Key (historyProgram stages))
        (VectorOutput GroupCounter), ClaimsDatabaseEvent claims completion := by
      simpa only [claims] using nonzero_physical_branch_claims_consistent
        (encode (historyProgram stages)) groupedDecode (historyProgram stages)
        historyBranch initial originalMassNe
    have viewClaims : ∀ claim ∈ claims,
        ∀ member : claim.1 ∈ nonchallengeRawKeySet historyCtx,
          historyView ⟨claim.1, member⟩ = some claim.2 := by
      intro claim claimMember member
      have nonchallenge : claim ∈ branchNonchallengeClaims historyCtx.keyBytes
          (encode (historyProgram stages)) groupedDecode (historyProgram stages)
          historyBranch := by
        unfold branchNonchallengeClaims
        apply List.mem_filter.mpr
        refine ⟨claimMember, ?_⟩
        have parsedNone := nonchallenge_raw_key_set_unrecognized historyCtx claim.1 member
        simp [parsedNone]
      calc
        historyView ⟨claim.1, member⟩ = database claim.1 := rfl
        _ = some claim.2 := nonchallengeComplete claim nonchallenge
    obtain ⟨completion, completionClaims, completionView⟩ :=
      claims_completion_preserving_view claims (nonchallengeRawKeySet historyCtx)
        historyView consistent viewClaims
    obtain ⟨_historyAccepted, i, readback, notFull⟩ := failure
    have observerComplete := terminal_observer_claims_complete_from_history stages i
      historyBranch readback.observerBranch completion readback.answerLogSubset completionClaims
    -- The observer reads only calls already present in the accepted history;
    -- its claim event is therefore complete in this one history completion.
    have actualEq := historyStageProgramEq stages i
    let stageCtx := historyStageContext (BaseWork := BaseWork) stages i model bounded advice .decsMatrix
    let stageDatabase := fun key : Key
        (actualProgram (historyStageProducer stages i) (stages[i.val]).ns
          (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce) =>
      completion (historyStageKeyCast stages i key)
    let observerProgram := terminalHistoryStageObserver stages i
    let stageProgram := actualProgram (historyStageProducer stages i)
      (stages[i.val]).ns (stages[i.val]).statement (stages[i.val]).pending
      (stages[i.val]).nonce
    have observerStageEq : observerProgram = stageProgram := actualEq.symm
    let observerStageKeyEq : Key observerProgram = Key stageProgram :=
      congrArg Key observerStageEq
    have observerStageGroupsEq : groups observerProgram = groups stageProgram :=
      congrArg groups observerStageEq
    have stageHistoryGroupsEq : groups stageProgram = groups (historyProgram stages) := by
      calc
        groups stageProgram = groups observerProgram := congrArg groups observerStageEq.symm
        _ = groups (historyProgram stages) := terminalHistoryStageObserver_groups_eq stages i
    have observerStageKeyEqProof : observerStageKeyEq =
        key_type_eq_of_groups_eq observerProgram stageProgram observerStageGroupsEq :=
      Subsingleton.elim _ _
    have stageHistoryKeyEqProof : history_stage_target_key_eq_history stages i =
        key_type_eq_of_groups_eq stageProgram (historyProgram stages) stageHistoryGroupsEq :=
      Subsingleton.elim _ _
    have observerEncodeEq (raw : V8SmzaOracleParser.RawInput) :
        encode stageProgram raw = cast observerStageKeyEq (encode observerProgram raw) := by
      rw [observerStageKeyEqProof]
      exact (encode_cast_key_type_eq_of_groups_eq observerProgram stageProgram
        observerStageGroupsEq raw).symm
    let observerDatabase := historyDatabaseOnObserver stages i completion
    have observerStageDatabaseEq : ∀ key : Key observerProgram,
        stageDatabase (cast observerStageKeyEq key) = observerDatabase key := by
      intro key
      change completion (historyStageKeyCast stages i (cast observerStageKeyEq key)) =
        completion (historyObserverKeyEquiv stages i key)
      congr 1
      apply Subtype.ext
      change included (historyProgram stages)
          (cast (history_stage_target_key_eq_history stages i)
            (cast observerStageKeyEq key)) =
        included (historyProgram stages) (historyObserverKeyEquiv stages i key)
      rw [stageHistoryKeyEqProof, observerStageKeyEqProof]
      calc
        included (historyProgram stages)
            (cast (key_type_eq_of_groups_eq stageProgram (historyProgram stages)
              stageHistoryGroupsEq)
              (cast (key_type_eq_of_groups_eq observerProgram stageProgram
                observerStageGroupsEq) key)) =
            included stageProgram (cast (key_type_eq_of_groups_eq observerProgram
              stageProgram observerStageGroupsEq) key) :=
          included_cast_key_type_eq_of_groups_eq stageProgram (historyProgram stages)
            stageHistoryGroupsEq _
        _ = included observerProgram key :=
          included_cast_key_type_eq_of_groups_eq observerProgram stageProgram
            observerStageGroupsEq key
        _ = included (historyProgram stages) (historyObserverKeyEquiv stages i key) := by
          rfl
    let stageBranch := SmzaRp05ExecutableProgramEquality.castProgramBranch groupedDecode
      observerProgram stageProgram observerStageEq readback.observerBranch
    have stageAccepted : branchResult groupedDecode
        (actualProgram (historyStageProducer stages i) (stages[i.val]).ns
          (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce)
        stageBranch = some () := by
      change branchResult groupedDecode stageProgram
        (SmzaRp05ExecutableProgramEquality.castProgramBranch groupedDecode
          observerProgram stageProgram observerStageEq readback.observerBranch) = some ()
      exact (SmzaRp05ExecutableProgramEquality.branchResult_cast_program groupedDecode
        observerProgram stageProgram observerStageEq readback.observerBranch).trans
        readback.observerAccepted
    have stageComplete : ClaimsDatabaseEvent
        (branchClaims (branchKeys (encode (actualProgram (historyStageProducer stages i)
          (stages[i.val]).ns (stages[i.val]).statement (stages[i.val]).pending
          (stages[i.val]).nonce)) groupedDecode
            (actualProgram (historyStageProducer stages i) (stages[i.val]).ns
              (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce)
              stageBranch)
          (branchAnswers (encode (actualProgram (historyStageProducer stages i)
            (stages[i.val]).ns (stages[i.val]).statement (stages[i.val]).pending
            (stages[i.val]).nonce)) groupedDecode
              (actualProgram (historyStageProducer stages i) (stages[i.val]).ns
                (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce)
                stageBranch)) stageDatabase := by
      exact acceptedBranchClaims_cast_program groupedDecode observerProgram stageProgram
        observerStageEq observerStageKeyEq (encode observerProgram) (encode stageProgram)
        observerEncodeEq readback.observerBranch observerDatabase stageDatabase
        observerStageDatabaseEq observerComplete
    have stageViewFor (role : Role) :
        xView (nonchallengeRawKeySet
          (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role))
          stageDatabase =
        historyStageView (BaseWork := BaseWork) stages i commonNs (stageNsEq i)
          model bounded advice role
          (xView (nonchallengeRawKeySet
            (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
              model bounded commonNs role (advice role) 28 28 (fun _ => ∅))) database) := by
      funext key
      let historyKey := historyStageKeyCast stages i key.val
      have roleMember := historyStageNonchallengeMem (BaseWork := BaseWork)
        stages i commonNs (stageNsEq i) model bounded advice role key.val key.property
      have decsMember : historyKey ∈ nonchallengeRawKeySet historyCtx := by
        have bytesEq :
            (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
              model bounded commonNs role (advice role) 28 28 (fun _ => ∅)).keyBytes =
            historyCtx.keyBytes := rfl
        apply Finset.mem_filter.mpr
        refine ⟨Finset.mem_univ _, ?_⟩
        rw [← bytesEq]
        exact nonchallenge_raw_key_set_unrecognized
          (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
            model bounded commonNs role (advice role) 28 28 (fun _ => ∅))
          historyKey roleMember
      simp only [xView, historyStageView]
      change completion historyKey = database historyKey
      rw [completionView historyKey decsMember]
      rfl
    have stageView : xView (nonchallengeRawKeySet stageCtx) stageDatabase =
        historyStageView (BaseWork := BaseWork) stages i commonNs (stageNsEq i)
          model bounded advice .decsMatrix historyView := by
      simpa only [historyView, historyCtx, stageCtx] using stageViewFor .decsMatrix
    have noFullAtCompletion : ¬ currentAcceptedXViewFullSuccessSelector
        (historyStageProducer stages i) (stages[i.val]).ns
        (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce
        fallback (typed i) fuel stageCtx stageBranch
        (xView (nonchallengeRawKeySet stageCtx) stageDatabase) := by
      intro full
      apply notFull
      rw [← stageView]
      exact full
    have covered := accepted_nonchallenge_consistent_branch_has_full_or_failure_selector_or_collision
      (historyStageProducer stages i) (stages[i.val]).ns
      (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce
      stageBranch stageAccepted stageDatabase stageComplete fallback (typed i) (parsed i)
      fuel enough stageCtx
    rcases covered with collisionAt | fullAt | ⟨role, roleFailure⟩
    · have stageCollisionBad : ¬ SmzaRecordedTracePath.RecordsCollisionFree
          (oneStatementFilter (globalLeafStatement (stages[i.val]).ns)
            (stages[i.val]).statement.toBytes
            (eraseChallengeRecords (rawRecords
              (fun key => groupRepresentative (included
                (actualProgram (historyStageProducer stages i) (stages[i.val]).ns
                  (stages[i.val]).statement (stages[i.val]).pending
                  (stages[i.val]).nonce) key))
              (vectorOutputBytes groupZero) stageDatabase))) := by
        exact collisionAt
      have observerKeyBytesEq : ∀ key : Key observerProgram,
          groupRepresentative (included stageProgram (cast observerStageKeyEq key)) =
            groupRepresentative (included observerProgram key) := by
        intro key
        exact congrArg groupRepresentative
          (included_cast_program observerProgram stageProgram observerStageEq key)
      have observerRawRecordsEq := rawRecords_cast_key_database observerStageKeyEq
        (fun key => groupRepresentative (included observerProgram key))
        (fun key => groupRepresentative (included stageProgram key))
        (vectorOutputBytes groupZero) observerKeyBytesEq observerDatabase stageDatabase
        observerStageDatabaseEq
      have erasedObserverCollision : ¬ SmzaRecordedTracePath.RecordsCollisionFree
          (oneStatementFilter (globalLeafStatement (stages[i.val]).ns)
            (stages[i.val]).statement.toBytes
            (eraseChallengeRecords
              (rawRecords (fun key => groupRepresentative (included observerProgram key))
                (vectorOutputBytes groupZero) observerDatabase))) := by
        have observerCollisionBad := stageCollisionBad
        rw [observerRawRecordsEq] at observerCollisionBad
        exact observerCollisionBad
      have completionCollision : ¬ SmzaRecordedTracePath.RecordsCollisionFree
          (eraseChallengeRecords
            (rawRecords (fun key => groupRepresentative (included (historyProgram stages) key))
              (vectorOutputBytes groupZero) completion)) := by
        have erasedObserverCollision := observer_statement_collision_implies_history_collision
          (stages[i.val]).ns observerProgram
          (stages[i.val]).statement.toBytes
          observerDatabase erasedObserverCollision
        rw [history_observer_raw_records_eq stages i completion] at erasedObserverCollision
        exact erasedObserverCollision
      have completionOriginalRecords :=
        SmzaRp05CurrentNonchallengeRecordView.grouped_erased_raw_records_eq_of_nonchallenge_key_agreement
          (historyProgram stages) completion database
          (by
            intro key parsedNone
            have member : key ∈ nonchallengeRawKeySet historyCtx := by
              apply Finset.mem_filter.mpr
              refine ⟨Finset.mem_univ _, ?_⟩
              change parseStageQuery
                (groupRepresentative (included (historyProgram stages) key)) = none
              exact parsedNone
            calc
              completion key = historyView ⟨key, member⟩ := completionView key member
              _ = database key := rfl)
      rw [← completionOriginalRecords]
      exact Or.inl completionCollision
    · exact False.elim (noFullAtCompletion fullAt)
    · have roleFailureView : currentAcceptedXViewFailureRoleSelector
          (historyStageProducer stages i) (stages[i.val]).ns
          (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce
          fallback fuel (historyStageContext stages i model bounded advice role) role
          stageBranch
          (historyStageView (BaseWork := BaseWork) stages i commonNs (stageNsEq i)
            model bounded advice role
            (xView (nonchallengeRawKeySet
              (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
                model bounded commonNs role (advice role) 28 28 (fun _ => ∅))) database)) := by
        -- The role only changes selector policy; its canonical key bytes and
        -- hence the nonchallenge key set are the same in the decs-matrix view.
        rw [← stageViewFor role]
        simpa only [currentAcceptedXViewFailureRoleSelector, stageCtx, historyStageContext,
          nonchallengeRawKeySet, currentGroupedContext] using roleFailure
      refine Or.inr (Or.inl ?_)
      refine ⟨role, completion, ?_, completionClaims, ?_⟩
      · intro key member
        have globalMember : key ∈ nonchallengeRawKeySet
            (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
              model bounded commonNs role (advice role) 28 28 (fun _ => ∅)) := by
          -- Key membership is independent of the role/advice fields.
          simpa [historyCtx, nonchallengeRawKeySet, currentGroupedContext] using member
        exact completionView key globalMember
      · exact ⟨i, readback, roleFailureView⟩
  · exact Or.inr (Or.inr nonchallengeComplete)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryFailureCoverage
