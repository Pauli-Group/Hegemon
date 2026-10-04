import SmzaRp05CurrentSourceLedgerTransitions
import SmzaRp05CurrentSourceBlockReplay
import SmzaRp05CurrentInitializedHistoryMassEndpoint
import SmzaRp05CurrentJointAuthorizationMassEndpoint
import SmzaRp05AuthorizationClosureIdentity
import SmzaRp05AuthorizationClosureModes
import SmzaRp05AuthorizationClosureTagsExistence
import SmzaRp05NullifierBinding
import SmzaRp05ActualAcceptedAuthorizationEndpoint
import SmzaRp05SupplyClosureInputNative
import SmzaRp05CurrentPublicHistoryAdmission
import SmzaRp05CurrentHistorySelectedStageExtraction
import SmzaRp05OriginalMassLossJoin

/-! # Current RP05 single-spend credential/history endpoint

This endpoint is deliberately about the current five-word credential and
seven-word recorded owner vector.  It connects the exact selected current
relation rows to one positive native-value input and the chronological
opening/unspent check.  Approval spends additionally expose the relation's
fresh selected signer and seven-word policy tag.  It does not assert
externally authenticated human ownership, possession of a signing secret,
complete reconstructed threshold-signature history, or Rust/verifier
refinement.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05SingleSpendAuthorizationEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (projectNote projectPosition spongeSourceWord)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
  (CurrentSourceLedgerPrefix initialCurrentSourceLedgerPrefix)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureIdentity
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureIdentity
  (selectedRow selectedMessage modeValue)
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureModes (lane_row)
open HegemonCrypto.SmallWood.SmzaRp05NullifierBinding (nullifierPreimage)
open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
  (certificateOutput)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceBlockReplay (CurrentRunEnvelope)
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureTagsExistence
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation (approvalRow finalRow)
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (packedWitnessLaneRows relationRowCount packingFactor)
open HegemonCrypto.SmallWood.SmzaRp05AcceptedSingleKeySemanticIdentity (acceptedGlobalKey)
open HegemonCrypto.SmallWood.SmzaRp05LiveAuthorizationIdentity (LiveAuthorizationInput)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRunner
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceTransferConstructor
open HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness
  (designatedInputPacked)
open HegemonCrypto.SmallWood.SmzaRp05CurrentHistorySelectedStageExtraction
  (CurrentHistoryOriginalOutcome CurrentHistoryBlockLayout
    currentHistoryBlockLayoutStageCount canonicalCurrentSelectedHistoryBlocks?
    packCanonicalCurrentPublicBlocks
    canonicalCurrentSelectedHistoryBlocks?_accepted_public_views
    canonicalCurrentSelectedHistoryBlocks?_block_stages_envelopes_present_of_no_history_failure)
open HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryVerifierProgram
  (HistoryStage historyProgram)
open HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryFailureMass (historyFailureEvent)
open HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryCertificateMass
  (currentHistoryGenesisChargedFailureEvent
    currentHistoryGenesisPathNoteCommitmentGameEvent
    currentHistoryGenesisPathMerkleCompressionGameEvent
    currentHistoryGenesisComparisonOutput)
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicHistoryAdmission
  (CurrentPublicHistoryAccepted
    selectedBlockPublicView
    public_history_acceptance_complete_or_charged)
open HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult)
open HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryCertificateMass
  (currentSelectedHistoryFailureFrame)
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
  (parseCurrentPublicStatement?)
open HegemonCrypto.SmallWood.SmzaRp05LeafNamespace (Namespace)
open HegemonCrypto.SmallWood.SmzaRp05TracePrefixes (RelationModel)
open HegemonCrypto.SmallWood.SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree (openingAt)
open SmzaFiniteLedgerSupply (potential allowance)
open V8SmzaOracleParser (RawDigest)
open scoped BigOperators
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation (RegisterBasis partialRandomOracleState)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAuthorizationCertificate
  (outcomeEventMass nullifierPrimitiveEvent singleKeyPrimitiveEvent
    accumulatorPrimitiveEvent mixedClawPrimitiveEvent)
open HegemonCrypto.SmallWood.SmzaRp05OriginalBornOutcomeMass
  (originalOutcomeWeight original_outcome_weight_nonnegative)
open HegemonCrypto.SmallWood.SmzaRp05OriginalMassLossJoin
  (outcome_mass_union_le_add)
open HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open HegemonCrypto.SmallWood.SmzaRp05OrdinarySoundnessExecution
  (OrdinaryPrefix ordinaryRun)
open HegemonCrypto.SmallWood.SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAdaptiveExecution (Work)
open HegemonCrypto.SmallWood.SmzaRp05SourceReadSchedule (readBudget)
open HegemonCrypto.SmallWood.SmzaRp05CurrentProtocolModelBound (current_model_within_protocol)
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement (relationModel)
open HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates (currentDsl)
open HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedReplayLite (physicalRun)
open HegemonCrypto.SmallWood.SmzaRp05GroupedSuffix (GroupCounter)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)
open HegemonCrypto.SmallWood.SmzaRp05CurrentBalanceCanonicality
open SmzaQ38Recovery (packedFromRows)
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packed_word_canonical)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (canonical_nat_cast_injective)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs (publicAnchor)
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree (openingAt)
open scoped Classical

set_option autoImplicit false
set_option maxRecDepth 4096
set_option maxHeartbeats 1000000

local notation "Statement" => SmzaRp05StatementNamespace.Statement

private theorem selectedRow_cases_from_conditions
    (approval final isFirst : Prop)
    [Decidable approval] [Decidable final] [Decidable isFirst] :
    (if approval then if isFirst then 110 else 106
      else if final then if isFirst then 111 else 110 else 106) = 106 ∨
    (if approval then if isFirst then 110 else 106
      else if final then if isFirst then 111 else 110 else 106) = 110 ∨
    (if approval then if isFirst then 110 else 106
      else if final then if isFirst then 111 else 110 else 106) = 111 := by
  by_cases hApproval : approval
  · by_cases hFirst : isFirst
    · simpa only [if_pos hApproval, if_pos hFirst] using
        (show (110 : Nat) = 106 ∨ 110 = 110 ∨ 110 = 111 from
          Or.inr (Or.inl rfl))
    · simpa only [if_pos hApproval, if_neg hFirst] using
        (show (106 : Nat) = 106 ∨ 106 = 110 ∨ 106 = 111 from Or.inl rfl)
  · by_cases hFinal : final
    · by_cases hFirst : isFirst
      · simpa only [if_neg hApproval, if_pos hFinal, if_pos hFirst] using
          (show (111 : Nat) = 106 ∨ 111 = 110 ∨ 111 = 111 from
            Or.inr (Or.inr rfl))
      · simpa only [if_neg hApproval, if_pos hFinal, if_neg hFirst] using
          (show (110 : Nat) = 106 ∨ 110 = 110 ∨ 110 = 111 from
            Or.inr (Or.inl rfl))
    · simpa only [if_neg hApproval, if_neg hFinal] using
        (show (106 : Nat) = 106 ∨ 106 = 110 ∨ 106 = 111 from Or.inl rfl)

private theorem selectedRow_cases (packed : List Nat) (input : Fin 2) :
    selectedRow packed input = 106 ∨ selectedRow packed input = 110 ∨
      selectedRow packed input = 111 := by
  change (if modeValue packed approvalRow = 1 then
      if input.val = 0 then 110 else 106
    else if modeValue packed finalRow = 1 then
      if input.val = 0 then 111 else 110 else 106) = 106 ∨
    (if modeValue packed approvalRow = 1 then
      if input.val = 0 then 110 else 106
    else if modeValue packed finalRow = 1 then
      if input.val = 0 then 111 else 110 else 106) = 110 ∨
    (if modeValue packed approvalRow = 1 then
      if input.val = 0 then 110 else 106
    else if modeValue packed finalRow = 1 then
      if input.val = 0 then 111 else 110 else 106) = 111
  exact selectedRow_cases_from_conditions
    (modeValue packed approvalRow = 1) (modeValue packed finalRow = 1)
    (input.val = 0)

/-- Source-derived current credential facts for one active input.  The
credential key is the current five-word selected nullifier key; its owner
commitment is all seven current words selected by the accepted source mode.
The note-frame equation ties those exact owner words to the note sponge
inside this same packed witness. -/
structure CurrentSingleSpendCredentialFacts
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2) : Prop where
  accepted : SmzaRp05Components.program.AcceptsPacked
    (encodePublicStatement typed) (sourcePacked run)
  active : (encodePublicStatement typed).getD input.val 0 = 1
  selectedSourceRow :
    selectedRow (sourcePacked run) input = 106 ∨
      selectedRow (sourcePacked run) input = 110 ∨
      selectedRow (sourcePacked run) input = 111
  fiveWordCredential : ∀ limb : Fin 5,
    (nullifierPreimage (sourcePacked run) input).getD limb.val 0 =
      (selectedMessage (sourcePacked run) input).key limb
  sevenWordRecordedOwner : ∀ limb : Fin 7,
    (sourcePacked run).getD ((95 + input.val) * 64 + limb.val) 0 =
      (selectedMessage (sourcePacked run) input).digest.getD limb.val 0
  currentAccumulatorMessage : selectedRow (sourcePacked run) input = 110 →
    ∀ limb : Fin 7,
      (sourcePacked run).getD (110 * 64 + limb.val) 0 =
        (selectedMessage (sourcePacked run) input).digest.getD limb.val 0
  secondaryAccumulatorMessage : selectedRow (sourcePacked run) input = 111 →
    ∀ limb : Fin 7,
      (sourcePacked run).getD (111 * 64 + limb.val) 0 =
        (selectedMessage (sourcePacked run) input).digest.getD limb.val 0
  noteFrameOwner : ∀ limb : Fin 7,
    spongeSourceWord (sourcePacked run) (noteCall input) (noteOwnerWord limb) =
      (sourcePacked run).getD ((95 + input.val) * 64 + limb.val) 0
  approvalHasFreshSelectedSigner :
    modeValue (sourcePacked run) approvalRow = 1 →
      ∃ slot : Fin 6,
        (sourcePacked run).getD ((206 + slot.val) * 64) 0 = 1 ∧
        (sourcePacked run).getD ((139 + slot.val) * 64) 0 = 0 ∧
        ∀ limb : Fin 7,
          (sourcePacked run).getD ((164 + 7 * slot.val + limb.val) * 64) 0 =
            (LiveAuthorizationInput.digest
              (.singleKey (acceptedGlobalKey (sourcePacked run)))).getD limb.val 0

private theorem projected_note_owner_coordinate_from_words
    (word : Nat → Nat) (limb : Fin 7) :
    ([word 0, word 1] ++
      (List.range 4).map (fun i => word (2 + i)) ++
      (List.range 4).map (fun i => word (6 + i)) ++
      (List.range 4).map (fun i => word (10 + i)) ++
      (List.range 4).map (fun i => word (14 + i))).getD
        (noteOwnerWord limb) 0 = word (noteOwnerWord limb) := by
  fin_cases limb <;> rfl

private theorem projected_note_owner_coordinate (packed : List Nat)
    (input : Fin 2) (limb : Fin 7) :
    (exactV8NoteWords (projectNote packed (noteCall input))).getD
        (noteOwnerWord limb) 0 =
      spongeSourceWord packed (noteCall input) (noteOwnerWord limb) := by
  let word := fun coordinate => spongeSourceWord packed (noteCall input) coordinate
  change ([word 0, word 1] ++
      (List.range 4).map (fun i => word (2 + i)) ++
      (List.range 4).map (fun i => word (6 + i)) ++
      (List.range 4).map (fun i => word (10 + i)) ++
      (List.range 4).map (fun i => word (14 + i))).getD
        (noteOwnerWord limb) 0 = word (noteOwnerWord limb)
  exact projected_note_owner_coordinate_from_words word limb

/-- Historical success packages the credential facts together with the exact
chronological opening match and the explicit seven owner coordinates read
back from that opening. -/
structure CurrentSingleSpendHistoricalAuthorizationFacts
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2) : Prop where
  credential : CurrentSingleSpendCredentialFacts run input
  historyBinding : CurrentInputLedgerBinding ledgerPrefix run input
  recordedOwnerCoordinate : ∀ limb : Fin 7,
    (exactV8NoteWords (openingAt ledgerPrefix.snapshot.openings
      (projectPosition (sourcePacked run) input.val))).getD
        (noteOwnerWord limb) 0 =
      (selectedMessage (sourcePacked run) input).digest.getD limb.val 0

/-- Every active input of the actual designated source has the current RP05
five/seven-word credential binding.  The accepted packed vector is obtained
from the source run, never supplied independently. -/
theorem current_run_active_input_has_credential_facts
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2)
    (active : (encodePublicStatement typed).getD input.val 0 = 1) :
    CurrentSingleSpendCredentialFacts run input := by
  have source := source_run_accepted run
  have rowCases : selectedRow (sourcePacked run) input = 106 ∨
      selectedRow (sourcePacked run) input = 110 ∨
      selectedRow (sourcePacked run) input = 111 := by
    exact selectedRow_cases (sourcePacked run) input
  refine ⟨source.2, active, rowCases, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro limb
    exact accepted_message_key_word source.2 input limb
  · intro limb
    exact accepted_owner_message_digest source.2 input active limb
  · intro selected limb
    simpa [selectedMessage, selected, FramedAuthorizationInput.digest] using
      accepted_bound_vector_word source.2 0 limb
  · intro selected limb
    simpa [selectedMessage, selected, FramedAuthorizationInput.digest] using
      accepted_bound_vector_word source.2 1 limb
  · intro limb
    exact accepted_input_owner_source source.2 input limb
  · intro approvalMode
    have approvalWord : (sourcePacked run).getD (approvalRow * 64) 0 = 1 := by
      apply canonical_nat_cast_injective
        (packed_word_canonical source.2.2.1 (approvalRow * 64)) (by decide)
      have modeWord :
          ((sourcePacked run).getD (approvalRow * 64) 0 : Goldilocks) = 1 := by
        have selectedMode :
            ((packedWitnessLaneRows (sourcePacked run) 0).getD approvalRow 0 : Goldilocks) = 1 := by
          simpa only [modeValue] using approvalMode
        have packedMode :
            ((packedWitnessLaneRows (sourcePacked run) 0).getD approvalRow 0 : Goldilocks) =
              ((sourcePacked run).getD (approvalRow * 64) 0 : Goldilocks) := by
          have row := congrArg (fun word : Nat => (word : Goldilocks))
            (lane_row (sourcePacked run) 0 approvalRow (by decide))
          simpa only [Nat.mul_zero, Nat.add_zero] using row
        calc
          ((sourcePacked run).getD (approvalRow * 64) 0 : Goldilocks) =
              ((packedWitnessLaneRows (sourcePacked run) 0).getD approvalRow 0 : Goldilocks) :=
            packedMode.symm
          _ = 1 := selectedMode
      exact modeWord
    have selected := accepted_approval_has_fresh_semantic_signer source.2 approvalWord
    simpa [approvalRow] using selected

/-- A positive native-value input is active under the source's canonical
public statement, so the active-input credential theorem applies. -/
theorem current_run_positive_input_has_credential_facts
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2)
    (positive : 0 < inputSlotNative typed (sourcePacked run) input) :
    CurrentSingleSpendCredentialFacts run input := by
  have canonical := (source_run_accepted run).1
  have active : (encodePublicStatement typed).getD input.val 0 = 1 := by
    rw [encoded_input_flag_for typed canonical input.isLt]
    exact positive_input_slot_active typed (sourcePacked run) input positive
  exact current_run_active_input_has_credential_facts run input active

private theorem historical_authorization_facts_of_binding
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2)
    (positive : 0 < inputSlotNative typed (sourcePacked run) input)
    (binding : CurrentInputLedgerBinding ledgerPrefix run input) :
    CurrentSingleSpendHistoricalAuthorizationFacts ledgerPrefix run input := by
  have credential := current_run_positive_input_has_credential_facts run input positive
  have recordedOwner : ∀ limb : Fin 7,
      (exactV8NoteWords (openingAt ledgerPrefix.snapshot.openings
        (projectPosition (sourcePacked run) input.val))).getD
          (noteOwnerWord limb) 0 =
        (selectedMessage (sourcePacked run) input).digest.getD limb.val 0 := by
    intro limb
    have openingEq := congrArg
      (fun words : List Nat => words.getD (noteOwnerWord limb) 0)
      binding.2.1
    have projectedEq :
        (exactV8NoteWords (projectNote (sourcePacked run) (noteCall input))).getD
            (noteOwnerWord limb) 0 =
          (selectedMessage (sourcePacked run) input).digest.getD limb.val 0 := by
      calc
        _ = spongeSourceWord (sourcePacked run) (noteCall input)
            (noteOwnerWord limb) := projected_note_owner_coordinate _ _ _
        _ = (sourcePacked run).getD ((95 + input.val) * 64 + limb.val) 0 :=
          credential.noteFrameOwner limb
        _ = (selectedMessage (sourcePacked run) input).digest.getD limb.val 0 :=
          credential.sevenWordRecordedOwner limb
    exact openingEq.symm.trans projectedEq
  exact ⟨credential, binding, recordedOwner⟩

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

private theorem designated_packed_eq_source_packed
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) :
    designatedInputPacked run = sourcePacked run := by
  change packedFromRows run.source.data = packedFromRows run.source.data
  rfl

/-- Every positive native input in a successful exact run fold has a current
five-word credential and a seven-word owner vector bound to the historical
opening at its chronological ledger prefix. -/
theorem current_complete_run_fold_authorizes_positive_inputs
    {registry : Nat → V8NoteOpening} {trailing : List V8NoteOpening}
    {initial final : CurrentSourceLedgerPrefix}
    {runs : List CurrentRunEnvelope}
    {actions : List SmzaFiniteLedgerSupply.Action}
    (fold : CurrentSelectedRunFold registry trailing initial runs actions final .complete) :
    ∀ envelope, envelope ∈ runs → ∀ input : Fin 2,
      (positive : 0 < inputSlotNative envelope.typedStatement
        (sourcePacked envelope.run) input) →
      ∃ ledgerPrefix : CurrentSourceLedgerPrefix,
        CurrentSingleSpendHistoricalAuthorizationFacts ledgerPrefix envelope.run input := by
  generalize outcomeEq : CurrentSelectedRunOutcome.complete = outcome at fold
  revert outcomeEq
  induction fold with
  | complete ledgerPrefix =>
      intro outcomeEq
      cases outcomeEq
      intro envelope member
      cases member
  | stopped _ =>
      intro outcomeEq
      cases outcomeEq
  | @transfer ledgerPrefix next final envelope tail actions outcome
      admitted bindings registryEq step nextEq rest ih =>
      intro outcomeEq
      cases nextEq
      intro target member input positive
      rcases List.mem_cons.mp member with head | tail
      · subst target
        have positiveDesignated :
            0 < inputSlotNative envelope.typedStatement
              (designatedInputPacked envelope.run) input := by
          rw [designated_packed_eq_source_packed envelope.run]
          exact positive
        have binding : CurrentInputLedgerBinding ledgerPrefix envelope.run input :=
          bindings input positiveDesignated
        exact ⟨ledgerPrefix, historical_authorization_facts_of_binding
          ledgerPrefix envelope.run input positive binding⟩
      · exact ih outcomeEq target tail input positive

omit [Fintype BaseWork] [DecidableEq BaseWork] in
private theorem current_complete_block_receipt_authorizes_positive_inputs
    {before after : CurrentSourceLedgerPrefix}
    (receipt : CurrentSelectedBlockReceipt (BaseWork := BaseWork) before after) :
    ∀ envelope, envelope ∈ receipt.result.runs → ∀ input : Fin 2,
      (positive : 0 < inputSlotNative envelope.typedStatement
        (sourcePacked envelope.run) input) →
      ∃ ledgerPrefix : CurrentSourceLedgerPrefix,
        CurrentSingleSpendHistoricalAuthorizationFacts ledgerPrefix envelope.run input :=
  current_complete_run_fold_authorizes_positive_inputs receipt.fold

/-- Coverage predicate over the exact chronological trace of a generated
history. It ranges over each successful receipt's actual replay `runs`. -/
def currentSelectedHistoryTracePositiveSpendAuthorization
    {blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))}
    {initial final : CurrentSourceLedgerPrefix}
    (trace : CurrentSelectedHistoryTrace (BaseWork := BaseWork)
      blocks initial final) : Prop :=
  match trace with
  | .nil _ => True
  | .cons receipt rest =>
      (∀ envelope, envelope ∈ receipt.result.runs → ∀ input : Fin 2,
        (positive : 0 < inputSlotNative envelope.typedStatement
          (sourcePacked envelope.run) input) →
        ∃ ledgerPrefix : CurrentSourceLedgerPrefix,
          CurrentSingleSpendHistoricalAuthorizationFacts ledgerPrefix envelope.run input) ∧
      currentSelectedHistoryTracePositiveSpendAuthorization rest

omit [Fintype BaseWork] [DecidableEq BaseWork] in
private theorem current_complete_history_trace_authorizes_positive_inputs
    {blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))}
    {initial final : CurrentSourceLedgerPrefix}
    (trace : CurrentSelectedHistoryTrace (BaseWork := BaseWork)
      blocks initial final) :
    currentSelectedHistoryTracePositiveSpendAuthorization trace := by
  induction trace with
  | nil => trivial
  | cons receipt rest ih =>
      exact ⟨current_complete_block_receipt_authorizes_positive_inputs receipt, ih⟩

/-- Success means the actual genesis executor returned its complete history
trace, and every designated positive-native source input in that exact trace
has the recorded credential/opening/unspent facts. -/
def actualCurrentSelectedHistoryPositiveSpendAuthorizationSuccess
    (blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))) : Prop :=
  ∃ (final : CurrentSourceLedgerPrefix)
    (trace : CurrentSelectedHistoryTrace (BaseWork := BaseWork) blocks
      initialCurrentSourceLedgerPrefix final)
    (boundary : final.stagedOpenings = final.snapshot.openings)
    (invariant : potential (openingAt final.stagedOpenings) final.ledger ≤
      allowance final.ledger),
    executeSelectedCurrentHistoryFromGenesis blocks =
      .complete trace boundary invariant ∧
    currentSelectedHistoryTracePositiveSpendAuthorization trace

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- The actual complete history result supplies the positive-spend success
predicate above, with no caller-selected replay outcome. -/
theorem actual_current_history_success_has_positive_spend_authorization
    (blocks : List (CurrentSelectedBlock (BaseWork := BaseWork)))
    (final : CurrentSourceLedgerPrefix)
    (trace : CurrentSelectedHistoryTrace (BaseWork := BaseWork) blocks
      initialCurrentSourceLedgerPrefix final)
    (boundary : final.stagedOpenings = final.snapshot.openings)
    (invariant : potential (openingAt final.stagedOpenings) final.ledger ≤
      allowance final.ledger)
    (actual : executeSelectedCurrentHistoryFromGenesis blocks =
      .complete trace boundary invariant) :
    actualCurrentSelectedHistoryPositiveSpendAuthorizationSuccess blocks := by
  exact ⟨final, trace, boundary, invariant, actual,
    current_complete_history_trace_authorizes_positive_inputs trace⟩

/-- One same-run positive native spend either binds its actual current owner
credential to the exact historical note and proves that its projected
position is still unspent, or returns the existing concrete current/prior
path or authorization-game failure.  No success fact is an argument. -/
theorem current_positive_spend_authorized_or_actual_history_failure
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2)
    (positive : 0 < inputSlotNative typed (sourcePacked run) input)
    (admitted : publicAnchor (encodePublicStatement typed) ∈
      ledgerPrefix.snapshot.parent.history)
    (fresh : sourceNullifiersFresh ledgerPrefix.spentNullifiers run = true) :
    CurrentSingleSpendHistoricalAuthorizationFacts ledgerPrefix run input ∨
      CurrentInputChargedFailure
        ⟨preamble, typed, run, input, positive, ledgerPrefix.snapshot, admitted⟩
        ledgerPrefix.snapshot ledgerPrefix.priorSpends := by
  rcases positive_input_success_or_charged_failure ledgerPrefix run input positive
      admitted fresh with binding | failure
  · exact Or.inl (historical_authorization_facts_of_binding
      ledgerPrefix run input positive binding)
  · exact Or.inr failure

/-- For the exact same accepted original outcome, failure of positive-native
spend authorization is covered by global extraction failure or the actual
first charged history frame. Public admission rules out native and coinbase
failures when extraction succeeded; no successful ledger result is assumed. -/
theorem accepted_current_history_positive_spend_authorization_failure_in_union
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ i : Fin stages.length,
      parseCurrentPublicStatement? (stages[i.val]).statement = some (typed i))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length)
    (outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages)
    (accepted : branchResult groupedDecode (historyProgram stages) outcome.1 = some ())
    (publicAccepted : CurrentPublicHistoryAccepted
      (packCanonicalCurrentPublicBlocks layout (List.ofFn typed))) :
    ¬ actualCurrentSelectedHistoryPositiveSpendAuthorizationSuccess
        ((canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
          stages commonNs stageNsEq typed parsed model bounded fallback outcome
          layout layoutCoversHistory).getD []) →
    historyFailureEvent (BaseWork := BaseWork) stages commonNs stageNsEq
      fallback typed 28 model bounded outcome.1 outcome.2.database ∨
    currentHistoryGenesisChargedFailureEvent
      (fun original : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages =>
        (canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
          stages commonNs stageNsEq typed parsed model bounded fallback
          original layout layoutCoversHistory).getD []) outcome := by
  classical
  intro noSuccess
  by_cases extractionFailure : historyFailureEvent (BaseWork := BaseWork)
      stages commonNs stageNsEq fallback typed 28 model bounded
      outcome.1 outcome.2.database
  · exact Or.inl extractionFailure
  · right
    let blocks := (canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
      stages commonNs stageNsEq typed parsed model bounded fallback
      outcome layout layoutCoversHistory).getD []
    have views := canonicalCurrentSelectedHistoryBlocks?_accepted_public_views
      (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed model bounded
      fallback outcome layout layoutCoversHistory accepted
    have blocksAccepted : CurrentPublicHistoryAccepted
        (blocks.map selectedBlockPublicView) := by
      rw [show blocks.map selectedBlockPublicView =
        packCanonicalCurrentPublicBlocks layout (List.ofFn typed) from views]
      exact publicAccepted
    have present :=
      canonicalCurrentSelectedHistoryBlocks?_block_stages_envelopes_present_of_no_history_failure
        (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed model bounded
        fallback outcome layout layoutCoversHistory accepted extractionFailure
    rcases public_history_acceptance_complete_or_charged
        blocks blocksAccepted present with complete | charged
    · rcases complete with ⟨final, trace, boundary, invariant, actual⟩
      exact False.elim (noSuccess
        (actual_current_history_success_has_positive_spend_authorization
          blocks final trace boundary invariant actual))
    · change (currentSelectedHistoryFailureFrame
        (executeSelectedCurrentHistoryFromGenesis blocks)).isSome = true at charged
      exact charged

private theorem current_single_spend_event_mass_mono
    {Outcome : Type} [Fintype Outcome]
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (left right : Outcome → Prop)
    (included : ∀ outcome, left outcome → right outcome) :
    outcomeEventMass mass left ≤ outcomeEventMass mass right := by
  classical
  unfold outcomeEventMass
  apply Finset.sum_le_sum
  intro outcome _
  by_cases leftOccurs : left outcome
  · have rightOccurs := included outcome leftOccurs
    simp [leftOccurs, rightOccurs]
  · by_cases rightOccurs : right outcome <;>
      simp [leftOccurs, rightOccurs, nonnegative outcome]

/-! The original-measure union root is inherited directly from the initialized
public-history consumer.  It combines global accepted extraction failure and
the actual first charged source-history failure on the same original Born
outcome measure, without conditioning on accepted branches. -/

/-- Quantitative single-spend endpoint on the literal original Born measure.
The measured event is branch acceptance, source-chain public admission, and
failure of the success predicate for that outcome's exact canonical blocks.
Its event is contained in accepted extraction failure or first charged
history failure, so the 130-bit extraction term is charged once. -/
theorem actual_current_initialized_single_spend_authorization_failure_mass_bound
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (typed : ∀ _i : Fin stages.length, V8PublicStatement)
    (parsed : ∀ i : Fin stages.length,
      parseCurrentPublicStatement? (stages[i.val]).statement = some (typed i))
    (fallback : RawDigest)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key (historyProgram stages))
      (Counter := GroupCounter) (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key (historyProgram stages))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (incomingUnit : normSquared
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers) = 1)
    (queriesWithin : queries + readBudget groupedDecode (historyProgram stages) ≤ cap)
    (capBound : cap ≤ 3 * 2 ^ 64)
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length) :
    let program := historyProgram stages
    let model := relationModel currentDsl SmzaRp05GeneratedCertificates.certificates
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    let mass := originalOutcomeWeight
      (fun branch => physicalRun (encode program) groupedDecode program branch initial)
    let blocksForOriginalOutcome := fun (outcome :
        CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages) =>
      (canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
        stages commonNs stageNsEq typed parsed model current_model_within_protocol
        fallback outcome layout layoutCoversHistory).getD []
    ∀ (epsilonNoteCommitment epsilonMerkle epsilonNullifier epsilonSingle
      epsilonAccumulator epsilonMixed : ℝ),
    (noteBound : outcomeEventMass mass
      (currentHistoryGenesisPathNoteCommitmentGameEvent blocksForOriginalOutcome) ≤
        epsilonNoteCommitment) →
    (merkleBound : outcomeEventMass mass
      (currentHistoryGenesisPathMerkleCompressionGameEvent blocksForOriginalOutcome) ≤
        epsilonMerkle) →
    (nullifierBound : outcomeEventMass mass
      (nullifierPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocksForOriginalOutcome))) ≤
        epsilonNullifier) →
    (singleBound : outcomeEventMass mass
      (singleKeyPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocksForOriginalOutcome))) ≤
        epsilonSingle) →
    (accumulatorBound : outcomeEventMass mass
      (accumulatorPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocksForOriginalOutcome))) ≤
        epsilonAccumulator) →
    (mixedBound : outcomeEventMass mass
      (mixedClawPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocksForOriginalOutcome))) ≤
        epsilonMixed) →
    outcomeEventMass mass (fun outcome =>
      branchResult groupedDecode program outcome.1 = some () ∧
      CurrentPublicHistoryAccepted
        (packCanonicalCurrentPublicBlocks layout (List.ofFn typed)) ∧
      ¬ actualCurrentSelectedHistoryPositiveSpendAuthorizationSuccess
        (blocksForOriginalOutcome outcome)) <
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) + epsilonNoteCommitment + epsilonMerkle +
        epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed := by
  classical
  intro program model initial mass blocksForOriginalOutcome
    epsilonNoteCommitment epsilonMerkle epsilonNullifier epsilonSingle
    epsilonAccumulator epsilonMixed noteBound merkleBound nullifierBound singleBound
    accumulatorBound mixedBound
  letI := physicalBranchesFintype groupedDecode program
  let authorizationFailure := fun outcome :
      CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages =>
    branchResult groupedDecode program outcome.1 = some () ∧
      CurrentPublicHistoryAccepted
        (packCanonicalCurrentPublicBlocks layout (List.ofFn typed)) ∧
      ¬ actualCurrentSelectedHistoryPositiveSpendAuthorizationSuccess
        (blocksForOriginalOutcome outcome)
  let extractionOrChargedFailure := fun outcome :
      CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages =>
    (branchResult groupedDecode program outcome.1 = some () ∧
      historyFailureEvent (BaseWork := BaseWork) stages commonNs stageNsEq
        fallback typed 28 model current_model_within_protocol
        outcome.1 outcome.2.database) ∨
      currentHistoryGenesisChargedFailureEvent blocksForOriginalOutcome outcome
  have massNonnegative : ∀ outcome, 0 ≤ mass outcome := by
    intro outcome
    exact original_outcome_weight_nonnegative
      (fun branch => physicalRun (encode program) groupedDecode program branch initial)
      outcome
  have included : ∀ outcome, authorizationFailure outcome →
      extractionOrChargedFailure outcome := by
    intro outcome failure
    rcases failure with ⟨accepted, publicAccepted, noSuccess⟩
    have union := accepted_current_history_positive_spend_authorization_failure_in_union
      stages commonNs stageNsEq typed parsed model current_model_within_protocol
      fallback layout layoutCoversHistory outcome accepted publicAccepted noSuccess
    rcases union with extractionFailure | chargedFailure
    · exact Or.inl ⟨accepted, extractionFailure⟩
    · exact Or.inr chargedFailure
  have eventBound :
      outcomeEventMass mass authorizationFailure ≤
        outcomeEventMass mass extractionOrChargedFailure :=
    current_single_spend_event_mass_mono mass massNonnegative
      authorizationFailure extractionOrChargedFailure included
  have inheritedBound :
      outcomeEventMass mass extractionOrChargedFailure <
        ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) + epsilonNoteCommitment + epsilonMerkle +
          epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed := by
    change outcomeEventMass mass (fun outcome =>
      (branchResult groupedDecode program outcome.1 = some () ∧
        historyFailureEvent (BaseWork := BaseWork) stages commonNs stageNsEq
          fallback typed 28 model current_model_within_protocol
          outcome.1 outcome.2.database) ∨
      currentHistoryGenesisChargedFailureEvent blocksForOriginalOutcome outcome) < _
    exact HegemonCrypto.SmallWood.SmzaRp05CurrentInitializedHistoryMassEndpoint.actual_current_initialized_history_failure_mass_bound
      stages commonNs stageNsEq typed parsed fallback ordinaryProgram registers incomingUnit
      queriesWithin capBound layout layoutCoversHistory epsilonNoteCommitment
      epsilonMerkle epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed
      noteBound merkleBound nullifierBound singleBound accumulatorBound mixedBound
  change outcomeEventMass mass authorizationFailure < _
  exact lt_of_le_of_lt eventBound inheritedBound

abbrev actual_current_initialized_history_failure_mass_bound :=
  @HegemonCrypto.SmallWood.SmzaRp05CurrentInitializedHistoryMassEndpoint.actual_current_initialized_history_failure_mass_bound

end HegemonCrypto.SmallWood.SmzaRp05SingleSpendAuthorizationEndpoint
