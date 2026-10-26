import SmzaRp05CurrentAcceptedExtractionFailureEndpoint

/-! Fixed-context extraction accounting and an adaptive selection reduction.

This module does NOT discharge H2. The current producer outputs only a proof
view; namespace, statement, pending flag and nonce are fixed before the run.
The actual context-output producer's physical execution is not represented by
`FixedExperiment`. In particular, postselecting a context does not justify
reusing incomingUnit or an empty independent oracle.

The finite-family bound below is derived from the existing full-extraction
endpoint, without a supplied probability bound. Its loss is the number of
contexts. Even a family varying only the 32-bit nonce costs 32 bits; a family
of at least 2^130 contexts gives no positive security-bit margin. This is not an efficient
extractor theorem: it retains the existing finite compressed-oracle model and
its existential X-view/full-source selector, and does not refine Rust.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ContextExtractionAccounting

open SmzaRp05OrdinarySoundnessExecution (OrdinaryPrefix)
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRp05CurrentAdaptiveExecution (Work)
open SmzaRp05ConditionedExecution
  (FixedTable fixedFiberToActive otherRoleTransform activeMemoryEquiv ActiveMemory)
open SmzaRoleDomainConditioning (ActiveKey unrecognized_is_active)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentAcceptedMassToScalar
  (currentAcceptedMassContexts)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentAcceptedDecsExtractionFailureEvent
  (grouped_four_role_failure_support_implies_current_advice_event_or_missing_claims)
open SmzaRp05CurrentSelectedChallengeClaims (recognizedActiveChallengeClaims)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix GroupCounter GroupComplement groupEncode groupKeyOf
    groupRepresentative groupAddress groupZero group_address_complement)
open SmzaRp05ActualEventRecertification (event)
open SmzaRp05OrdinarySoundnessExecution
  (ordinaryRun emptyAuthorizationContexts)
open SmzaRp05AdaptivePhysicalReadBound
  (ReadsAtMost ReadsWithinKeys physicalBranchesFintype)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult physicalRun)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol protocolBlockCap PhysicalInput)
open SmzaRp05RelationRefinement (relationModel GeneratedCertificates)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentOrdinarySoundnessFinalBound
  (ordinary_selected_readout_collision_scalar_bound)
open SmzaRp05CurrentOrdinaryInitializedLedger (ordinary_scalar_rhs_below_130)
open SmzaRp05CurrentProtocolModelBound
  (current_model_within_protocol current_protocol_positive_caps)
open SmzaRp05SourceReadSchedule
  (readBudget source_reads_within_budget source_reads_within_finite_address_space)
open SmzaRp05GroupedSuffix (GroupCounter)
open SmzaRp05CurrentFullOrRoleExtraction (currentAcceptedXViewFailureRoleSelector)
open SmzaRp05CurrentFullOrRoleXViewCoverage (currentAcceptedXViewFullSuccessSelector)
open SmzaRp05ConditionedExecution (XKey xView)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8SmzaOracleParser (RawDigest)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
  (V8PublicStatement encodePublicStatement)
open SmzaRp05CurrentAdviceDependentPhysicalMass (currentAdviceEventSpec)


noncomputable section
set_option autoImplicit false
set_option maxRecDepth 18000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

/-- Exact context-and-proof output missing from the fixed endpoint producer.
No parser success or witness existence is built into this record. -/
structure ProducedContext where
  ns : Namespace
  statement : SmzaRp05StatementNamespace.Statement
  pending : Bool
  nonce : Fin (2 ^ 32)
  wire : ExistingProofFieldView

/-- A producer may read the oracle before choosing every context field. The
ordinary verifier consumes precisely that produced context and proof. A
physical compressed-oracle mass/extraction theorem for THIS program remains
required for H2; fixedFailureMass_lt below does not apply to this type. -/
def contextProducingVerifierProgram (producer : Program ProducedContext) : Program Unit :=
  producer.bind fun produced =>
    SmzaRp05ExecutablePcsClosureStatement.verifierProgram produced.ns currentDsl
      produced.statement produced.pending produced.nonce produced.wire

/-- Exact executable-oracle semantics of the new target program. This is an
evaluation equation, not a QROM/physical-run probability or extraction claim. -/
theorem contextProducingVerifierProgram_eval_iff
    (producer : Program ProducedContext)
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle) :
    (contextProducingVerifierProgram producer).eval oracle = some () ↔
      ∃ produced, producer.eval oracle = some produced ∧
        (SmzaRp05ExecutablePcsClosureStatement.verifierProgram produced.ns currentDsl
          produced.statement produced.pending produced.nonce produced.wire).eval oracle = some () := by
  simp [contextProducingVerifierProgram, Program.eval_bind, Option.bind_eq_some_iff]

/-- Structural inputs to the existing *fixed-context* endpoint. No failure
probability, selected-event coverage or extraction success is supplied. -/
structure FixedExperiment (BaseWork : Type) [Fintype BaseWork] [DecidableEq BaseWork] where
  producer : Program ExistingProofFieldView
  ns : Namespace
  statement : SmzaRp05StatementNamespace.Statement
  pending : Bool
  nonce : Fin (2 ^ 32)
  fallback : RawDigest
  typed : V8PublicStatement
  parsed : parseCurrentPublicStatement? statement = some typed
  cap : Nat
  finish : Nat
  queries : Nat
  ordinaryProgram : OrdinaryPrefix
    (Key := Key (actualProgram producer ns statement pending nonce))
    (Counter := GroupCounter) (BaseWork := BaseWork) (cap := cap) 0 finish queries
  registers : RegisterBasis
    (Input := Key (actualProgram producer ns statement pending nonce))
    (Phase := VectorOutput GroupCounter)
    (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ
  incomingUnit : normSquared
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers) = 1
  queriesWithin : queries + readBudget groupedDecode
    (actualProgram producer ns statement pending nonce) ≤ cap
  capBound : cap ≤ 3 * 2 ^ 64

/-- The original accepted full-extraction-failure projection, unchanged. -/
def fixedFailureMass {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (experiment : FixedExperiment BaseWork) : ℝ := by
  classical
  let producer := experiment.producer
  let ns := experiment.ns
  let statement := experiment.statement
  let pending := experiment.pending
  let nonce := experiment.nonce
  let fallback := experiment.fallback
  let typed := experiment.typed
  let ordinaryProgram := experiment.ordinaryProgram
  let registers := experiment.registers
  exact
    let program := actualProgram producer ns statement pending nonce
    let contexts := currentAcceptedMassContexts (BaseWork := BaseWork)
      producer ns statement pending nonce (relationModel currentDsl
        SmzaRp05GeneratedCertificates.certificates)
      current_model_within_protocol (fun _ => fun _ _ _ _ => none) 28 28
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    let ctx := contexts .decsMatrix
    letI := physicalBranchesFintype groupedDecode program
    (∑ branch : Branches groupedDecode program,
      if branchResult groupedDecode program branch = some () then
        normSquared (workspaceEventProjection
          (fun _work database => ¬ currentAcceptedXViewFullSuccessSelector
            producer ns statement pending nonce fallback typed 28 ctx branch
            (xView (nonchallengeRawKeySet ctx) database))
          (physicalRun (encode program) groupedDecode program branch initial))
      else 0)

theorem fixedFailureMass_lt {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (experiment : FixedExperiment BaseWork) :
    fixedFailureMass experiment < ((1 / (2 : Rat)^130 : Rat) : ℝ) := by
  exact SmzaRp05CurrentAcceptedExtractionFailureEndpoint.actual_accepted_full_extraction_failure_mass_below_130_bits
    experiment.producer experiment.ns experiment.statement experiment.pending
    experiment.nonce experiment.fallback experiment.typed experiment.parsed
    experiment.ordinaryProgram experiment.registers experiment.incomingUnit
    experiment.queriesWithin experiment.capBound

/-- Actual endpoint composition for a finite family. This is a sum of fixed
experiment losses, not a claim about a context-selected physical execution. -/
theorem sum_fixedFailureMass_lt {Context BaseWork : Type}
    [Fintype Context] [Nonempty Context] [Fintype BaseWork] [DecidableEq BaseWork]
    (experiments : Context → FixedExperiment BaseWork) :
    (∑ context, fixedFailureMass (experiments context)) <
      (Fintype.card Context : ℝ) * ((1 / (2 : Rat)^130 : Rat) : ℝ) := by
  have bound := Finset.sum_lt_sum_of_nonempty (s := (Finset.univ : Finset Context))
    Finset.univ_nonempty (fun context _ => fixedFailureMass_lt (experiments context))
  simpa using bound

/-- Unnormalized event mass on one shared outcome space. -/
def eventMass {Outcome : Type} [Fintype Outcome]
    (weight : Outcome → ℝ) (event : Outcome → Prop) : ℝ := by
  classical
  exact ∑ outcome, if event outcome then weight outcome else 0

/-- Arbitrary outcome-dependent selection needs no independence assumption.
To use this with the fixed RP05 endpoint, a caller must FIRST prove a common
physical outcome representation whose fixed-context failure events have the
corresponding fixedFailureMass. That execution transport is the open H2 step.
The theorem does not assume, or conclude, that this transport exists. -/
theorem selected_event_mass_le_sum {Context Outcome : Type}
    [Fintype Context] [Fintype Outcome]
    (weight : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ weight outcome)
    (choose : Outcome → Context) (failure : Context → Outcome → Prop) :
    eventMass weight (fun outcome => failure (choose outcome) outcome) ≤
      ∑ context, eventMass weight (failure context) := by
  classical
  unfold eventMass
  calc
    (∑ outcome, if failure (choose outcome) outcome then weight outcome else 0) ≤
        ∑ outcome, ∑ context, if failure context outcome then weight outcome else 0 := by
      apply Finset.sum_le_sum
      intro outcome _
      exact Finset.single_le_sum (f := fun context => if failure context outcome then weight outcome else 0)
        (fun context _ => by split_ifs <;> simp [nonnegative outcome])
        (Finset.mem_univ (choose outcome))
    _ = ∑ context, ∑ outcome, if failure context outcome then weight outcome else 0 :=
      Finset.sum_comm

/-- Concrete dispatcher for an already supplied family of extractors. This
creates no new extractor, and by itself asserts no knowledge soundness. -/
def dispatchExtractor {Context Outcome Witness : Type}
    (choose : Outcome → Context) (extract : Context → Outcome → Option Witness)
    (outcome : Outcome) : Option Witness := extract (choose outcome) outcome

/-- The failure event includes absent AND relation-invalid extracted witnesses. -/
def extractionFailure {Context Outcome Witness : Type}
    (accept : Context → Outcome → Prop) (relation : Context → Witness → Prop)
    (extract : Context → Outcome → Option Witness) (context : Context) (outcome : Outcome) : Prop :=
  accept context outcome ∧ ¬ ∃ witness, extract context outcome = some witness ∧ relation context witness

theorem selected_extraction_failure_mass_le_sum {Context Outcome Witness : Type}
    [Fintype Context] [Fintype Outcome]
    (weight : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ weight outcome)
    (choose : Outcome → Context) (accept : Context → Outcome → Prop)
    (relation : Context → Witness → Prop) (extract : Context → Outcome → Option Witness) :
    eventMass weight (fun outcome => accept (choose outcome) outcome ∧
      ¬ ∃ witness, dispatchExtractor choose extract outcome = some witness ∧
        relation (choose outcome) witness) ≤
    ∑ context, eventMass weight (extractionFailure accept relation extract context) :=
  selected_event_mass_le_sum weight nonnegative choose (extractionFailure accept relation extract)

/-- Sharpness example: adaptive diagonal selection makes every outcome fail,
although each fixed context sees only its own outcome's mass. Thus the
finite-context factor cannot be discarded merely by conditioning. -/
theorem diagonal_selection_mass {Context : Type} [Fintype Context]
    (weight : Context → ℝ) :
    eventMass weight (fun outcome => outcome = outcome) = ∑ outcome, weight outcome := by
  classical
  simp [eventMass]

theorem fixed_diagonal_mass {Context : Type} [Fintype Context]
    (weight : Context → ℝ) (context : Context) :
    eventMass weight (fun outcome => outcome = context) = weight context := by
  classical
  simp [eventMass]

end
end HegemonCrypto.SmallWood.SmzaRp05ContextExtractionAccounting
