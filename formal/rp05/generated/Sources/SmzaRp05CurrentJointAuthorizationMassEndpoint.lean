import SmzaRp05ActualAcceptedAuthorizationEndpoint
import SmzaRp05OriginalMassLossJoin
import SmzaRp05OriginalBornOutcomeMass
import SmzaRp05CurrentJointAuthorizationEndpoint
import SmzaRp05CurrentFirstSelectorMass
import SmzaRp05CurrentSecondSelectorMass
import SmzaRp05CurrentAcceptedExtractionFailureEndpoint
import SmzaRp05CurrentAcceptedMassToScalar
import SmzaRp05CurrentProtocolModelBound
import SmzaRp05CurrentJointAcceptedExecution
import SmzaRp05CurrentJointExtractionPrograms
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05OrdinarySoundnessExecution
import SmzaRp05CmsKeyEqualityTransport
import SmzaRp05CmsInitializedEqualityTransport
import SmzaRp05PhysicalAcceptedReplayLite
import SmzaRp05AdaptivePhysicalReadBound
import SmzaRp05SourceReadSchedule
import HegemonCrypto.CmsOracleSimulation
import SmzaChallengeStageTargets

/-! # Same-outcome authorization-loss composition

The selected comparison is the actual two-target output map from the checked
joint execution. This arithmetic layer keeps both extraction failures and the
authorization-certificate failure on one original outcome measure. Concrete
selector-loss bounds are supplied by the current accepted extraction
endpoints in the final consumer below; the four primitive-game bounds remain
explicit assumptions on the induced games for this same output map.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentJointAuthorizationMassEndpoint

open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
open HegemonCrypto.SmallWood.SmzaRp05CurrentAuthorizationCertificate
open HegemonCrypto.SmallWood.SmzaRp05OriginalMassLossJoin
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointAcceptedExecution
  (secondAcceptedVerifierProgram secondProducerAfterFirst)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedMassToScalar (currentAcceptedMassContexts)
open HegemonCrypto.SmallWood.SmzaRp05CurrentProtocolModelBound (current_model_within_protocol)
open HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open HegemonCrypto.SmallWood.SmzaRp05OrdinarySoundnessExecution (OrdinaryPrefix ordinaryRun)
open HegemonCrypto.SmallWood.SmzaRp05SourceReadSchedule (readBudget)
open HegemonCrypto.SmallWood.SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult physicalRun)
open HegemonCrypto.CmsCompressedOracle (Basis normSquared)
open HegemonCrypto.CmsOracleSimulation (RegisterBasis partialRandomOracleState)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAdaptiveExecution (Context Work)
open HegemonCrypto.SmallWood.SmzaRp05GroupedSuffix (GroupCounter)
open HegemonCrypto.SmallWood.SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open HegemonCrypto.SmallWood.SmzaRp05LeafNamespace (Namespace)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification (V8PublicStatement encodePublicStatement)
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open HegemonCrypto.SmallWood.SmzaRp05CurrentFullOrRoleXViewCoverage (currentAcceptedXViewFullSuccessSelector)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open HegemonCrypto.SmallWood.SmzaRp05ConditionedExecution (XKey xView)
open HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates (currentDsl certificates)
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement (relationModel)
open HegemonCrypto.SmallWood.SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open HegemonCrypto.SmallWood.SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaChallengeStageTargets (Role)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointAuthorizationEndpoint
  (currentJointSelectorComparisonOutput currentJointFirstSelectorFailure
    currentJointSecondSelectorFailure)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointExtractionPrograms
  (actualProgram_firstTarget_eq_terminalUnitPrefixReplayObserver
    firstTarget_key_eq_terminalUnitPrefixReplayObserver secondTarget_key_eq_joint)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointObserverKeys
  (terminal_observer_key_eq_joint terminalWholePrefixObserver)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointObserverMass
  (branchesFintype)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointRetainedProofs
  (terminalUnitPrefixReplayObserver)
open HegemonCrypto.SmallWood.SmzaRp05CmsKeyEqualityTransport
  (ordinaryPrefixTypeEq ordinaryRun_cast)
open HegemonCrypto.SmallWood.SmzaRp05CmsInitializedEqualityTransport
  (castRegisterState partialRandomOracleState_normSquared_cast_empty
    partialRandomOracleState_cast_empty)
open HegemonCrypto.SmallWood.SmzaRp05OriginalBornOutcomeMass
  (originalOutcomeWeight original_outcome_weight_nonnegative)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedExtractionFailureEndpoint
  (actual_accepted_full_extraction_failure_mass_below_130_bits)
open HegemonCrypto.SmallWood.SmzaRp05CurrentFirstSelectorMass
  (current_joint_first_selector_mass_eq_event_mass)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSecondSelectorMass
  (current_joint_second_selector_mass_eq_event_mass)
open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
  (DesignatedAuthorizationComparison)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8SmzaOracleParser (RawDigest)
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/-- The actual chronological carrier has a canonical finite branch index.
This local instance is constructed from the bounded read-tree definition;
it is not a caller-supplied mass or security premise. -/
private noncomputable instance currentJointBranchesFintype
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    Fintype (Branches groupedDecode (secondAcceptedVerifierProgram
      producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
      nonce₁ nonce₂)) :=
  branchesFintype groupedDecode (secondAcceptedVerifierProgram
    producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
    nonce₁ nonce₂)

/-- `Finset.univ` does not depend on which finite enumeration instance is
chosen for a fixed branch type. Keep this as a finite-sum rewrite rather than
eliminating an equality between the non-subsingleton `Fintype` structures. -/
private theorem sum_univ_fintype_irrel {α : Type} (left right : Fintype α)
    (f : α → ℝ) :
    @Finset.sum α ℝ _ (@Finset.univ α left) f =
      @Finset.sum α ℝ _ (@Finset.univ α right) f := by
  have hUniv : (@Finset.univ α left) = (@Finset.univ α right) := by
    ext value
    simp
  rw [hUniv]

/-- The exact internally-derived ordinary endpoint contexts: current checked
certificates, protocol model bound, empty earlier-table advice, and the
endpoint's fixed 28/28 fuel. -/
noncomputable def currentJointEndpointContexts
    (producer : Program ExistingProofFieldView) (ns : Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) :
    Role → Context (Key := Key (actualProgram producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork) :=
  currentAcceptedMassContexts (BaseWork := BaseWork) producer ns statement pending
    nonce (relationModel currentDsl certificates) current_model_within_protocol
    (fun _role => fun _ _ _ _ => none) 28 28

/-- The option output map for the actual chronological pair, with no caller
contexts: each selector sees the exact internally-derived endpoint context. -/
noncomputable def currentJointDerivedComparisonOutput
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (fallback₁ fallback₂ : RawDigest)
    (typed₁ typed₂ : V8PublicStatement)
    (parsed₁ : parseCurrentPublicStatement? statement₁ = some typed₁)
    (parsed₂ : parseCurrentPublicStatement? statement₂ = some typed₂)
    (input₁ input₂ : Fin 2)
    (active₁ : (encodePublicStatement typed₁).getD input₁.val 0 = 1)
    (active₂ : (encodePublicStatement typed₂).getD input₂.val 0 = 1) :
    (Branches groupedDecode (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) ×
      Basis (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
        (VectorOutput GroupCounter) (VectorOutput GroupCounter)
        (Work (Counter := GroupCounter) (BaseWork := BaseWork))) →
      Option DesignatedAuthorizationComparison := by
  let joint := secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  let firstProducer := joint.bind fun _ => producer₁
  let secondProducer := secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁
    pending₁ nonce₁
  exact currentJointSelectorComparisonOutput producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₁ fallback₂
    typed₁ typed₂ parsed₁ parsed₂ 28 28
    (currentJointEndpointContexts (BaseWork := BaseWork) firstProducer ns₁
      statement₁ pending₁ nonce₁ .decsMatrix)
    (currentJointEndpointContexts (BaseWork := BaseWork) secondProducer ns₂
      statement₂ pending₂ nonce₂ .decsMatrix)
    input₁ input₂ active₁ active₂

/-- Deterministic first-selector loss on an original joint branch/basis, using
the same internally-derived context as the endpoint. -/
def currentJointDerivedFirstSelectorFailure
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (fallback₁ : RawDigest) (typed₁ : V8PublicStatement) :
    (Branches groupedDecode (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) ×
      Basis (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
        (VectorOutput GroupCounter) (VectorOutput GroupCounter)
        (Work (Counter := GroupCounter) (BaseWork := BaseWork))) → Prop := by
  let joint := secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  let firstProducer := joint.bind fun _ => producer₁
  exact currentJointFirstSelectorFailure producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₁ typed₁ 28
    (currentJointEndpointContexts (BaseWork := BaseWork) firstProducer ns₁
      statement₁ pending₁ nonce₁ .decsMatrix)

/-- Deterministic second-selector loss on the same original joint
branch/basis, using its internally-derived endpoint context. -/
def currentJointDerivedSecondSelectorFailure
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (fallback₂ : RawDigest) (typed₂ : V8PublicStatement) :
    (Branches groupedDecode (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) ×
      Basis (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
        (VectorOutput GroupCounter) (VectorOutput GroupCounter)
        (Work (Counter := GroupCounter) (BaseWork := BaseWork))) → Prop := by
  let joint := secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  let secondProducer := secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁
    pending₁ nonce₁
  exact currentJointSecondSelectorFailure producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₂ typed₂ 28
    (currentJointEndpointContexts (BaseWork := BaseWork) secondProducer ns₂
      statement₂ pending₂ nonce₂ .decsMatrix)

/-- One original chronological joint branch/Born outcome measure. The ordinary
prefix and initial register vector are each specified once; no separate
transaction state or accepted-conditioned measure is introduced. -/
noncomputable def currentJointOriginalBornMass
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix
      (Key := Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
      (Counter := GroupCounter) (BaseWork := BaseWork)
      (cap := cap) 0 finish queries)
    (registers : RegisterBasis
      (Input := Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (outcome : Branches groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) ×
      Basis (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
        (VectorOutput GroupCounter) (VectorOutput GroupCounter)
        (Work (Counter := GroupCounter) (BaseWork := BaseWork))) : ℝ :=
  originalOutcomeWeight
    (fun branch => physicalRun
      (encode (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)) groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) branch
      (ordinaryRun ordinaryProgram
        (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)))
    outcome

/-- Accepted original outcomes of the same chronological joint program. -/
def currentJointBranchAccepted
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (outcome : Branches groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) ×
      Basis (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
        (VectorOutput GroupCounter) (VectorOutput GroupCounter)
        (Work (Counter := GroupCounter) (BaseWork := BaseWork))) : Prop :=
  branchResult groupedDecode
    (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂) outcome.1 = some ()

private theorem outcomeEventMass_mono
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
  · have rightTermNonnegative : 0 ≤ if right outcome then mass outcome else 0 := by
      by_cases rightOccurs : right outcome <;> simp [rightOccurs, nonnegative outcome]
    simpa [leftOccurs] using rightTermNonnegative

/-- Accepted authorization failure on the actual selected comparison output
is covered by either deterministic extraction loss or one of the concrete
primitive games induced by its certificate. The comparison output itself is
not treated as failure when it is `none`. -/
def acceptedJointAuthorizationClosureFailure
    {Outcome : Type}
    (accepted firstSelectorFailure secondSelectorFailure : Outcome → Prop)
    (output : Outcome → Option DesignatedAuthorizationComparison)
    (outcome : Outcome) : Prop :=
  accepted outcome ∧
    (firstSelectorFailure outcome ∨ secondSelectorFailure outcome ∨
      currentAuthorizationFailureEvent (certificateOutput output) outcome)

/-- Four explicit induced-game advantage hypotheses bound the original-mass
authorization failure term. This lemma performs only same-measure addition;
it assumes neither normalization nor independence. -/
theorem accepted_joint_authorization_failure_mass_le_selector_losses_and_games
    {Outcome : Type} [Fintype Outcome]
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (accepted firstSelectorFailure secondSelectorFailure : Outcome → Prop)
    (output : Outcome → Option DesignatedAuthorizationComparison)
    (epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed : ℝ)
    (nullifierBound : outcomeEventMass mass
      (nullifierPrimitiveEvent (certificateOutput output)) ≤ epsilonNullifier)
    (singleBound : outcomeEventMass mass
      (singleKeyPrimitiveEvent (certificateOutput output)) ≤ epsilonSingle)
    (accumulatorBound : outcomeEventMass mass
      (accumulatorPrimitiveEvent (certificateOutput output)) ≤ epsilonAccumulator)
    (mixedBound : outcomeEventMass mass
      (mixedClawPrimitiveEvent (certificateOutput output)) ≤ epsilonMixed) :
    outcomeEventMass mass
      (acceptedJointAuthorizationClosureFailure accepted firstSelectorFailure
        secondSelectorFailure output) ≤
      outcomeEventMass mass firstSelectorFailure +
      outcomeEventMass mass secondSelectorFailure +
      epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed := by
  classical
  let primitiveFailure := currentAuthorizationFailureEvent (certificateOutput output)
  have primitiveBound := actual_designated_failure_mass_le_assumed_advantages
    output mass nonnegative epsilonNullifier epsilonSingle epsilonAccumulator
    epsilonMixed nullifierBound singleBound accumulatorBound mixedBound
  have subsetUnion (outcome : Outcome) :
      acceptedJointAuthorizationClosureFailure accepted firstSelectorFailure
        secondSelectorFailure output outcome →
      firstSelectorFailure outcome ∨ secondSelectorFailure outcome ∨
        primitiveFailure outcome := by
    intro failure
    exact failure.2
  have unionFirst := outcome_mass_union_le_add mass nonnegative
    firstSelectorFailure (fun outcome =>
      secondSelectorFailure outcome ∨ primitiveFailure outcome)
  have unionSecond := outcome_mass_union_le_add mass nonnegative
    secondSelectorFailure primitiveFailure
  have combined := outcomeEventMass_mono mass nonnegative
    (acceptedJointAuthorizationClosureFailure accepted firstSelectorFailure
      secondSelectorFailure output)
    (fun outcome => firstSelectorFailure outcome ∨
      secondSelectorFailure outcome ∨ primitiveFailure outcome)
    subsetUnion
  linarith

/-- Concrete numerical composition on one original Born measure. Once the
two current selector-failure endpoints provide their strict 130-bit bounds,
their losses and the four explicit induced-game advantages combine without
conditioning the accepted outcomes. -/
theorem accepted_joint_authorization_failure_mass_below_129
    {Outcome : Type} [Fintype Outcome]
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (accepted firstSelectorFailure secondSelectorFailure : Outcome → Prop)
    (output : Outcome → Option DesignatedAuthorizationComparison)
    (epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed : ℝ)
    (firstLoss : outcomeEventMass mass firstSelectorFailure <
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ))
    (secondLoss : outcomeEventMass mass secondSelectorFailure <
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ))
    (nullifierBound : outcomeEventMass mass
      (nullifierPrimitiveEvent (certificateOutput output)) ≤ epsilonNullifier)
    (singleBound : outcomeEventMass mass
      (singleKeyPrimitiveEvent (certificateOutput output)) ≤ epsilonSingle)
    (accumulatorBound : outcomeEventMass mass
      (accumulatorPrimitiveEvent (certificateOutput output)) ≤ epsilonAccumulator)
    (mixedBound : outcomeEventMass mass
      (mixedClawPrimitiveEvent (certificateOutput output)) ≤ epsilonMixed) :
    outcomeEventMass mass
      (acceptedJointAuthorizationClosureFailure accepted firstSelectorFailure
        secondSelectorFailure output) <
      ((1 / (2 : Rat) ^ 129 : Rat) : ℝ) +
        epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed := by
  have composed := accepted_joint_authorization_failure_mass_le_selector_losses_and_games
    mass nonnegative accepted firstSelectorFailure secondSelectorFailure output
    epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed nullifierBound
    singleBound accumulatorBound mixedBound
  have arithmetic :
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) +
        ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) =
        ((1 / (2 : Rat) ^ 129 : Rat) : ℝ) := by norm_num
  linarith

/-- Fully bound chronological A endpoint. Its carrier is the one physical
two-verifier program, its ordinary prefix and register vector are supplied
once, and each deterministic selector-loss term is bounded by the checked
full-extraction endpoint after transporting that same prefix/state to the
corresponding target key. The four cryptographic premises are advantages of
the concrete games induced by the actual comparison certificate. -/
theorem actual_current_joint_authorization_failure_mass_below_129
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (fallback₁ fallback₂ : RawDigest)
    (typed₁ typed₂ : V8PublicStatement)
    (parsed₁ : parseCurrentPublicStatement? statement₁ = some typed₁)
    (parsed₂ : parseCurrentPublicStatement? statement₂ = some typed₂)
    (input₁ input₂ : Fin 2)
    (active₁ : (encodePublicStatement typed₁).getD input₁.val 0 = 1)
    (active₂ : (encodePublicStatement typed₂).getD input₂.val 0 = 1)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix
      (Key := Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
      (Counter := GroupCounter) (BaseWork := BaseWork)
      (cap := cap) 0 finish queries)
    (registers : RegisterBasis
      (Input := Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (incomingUnit : normSquared
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers) = 1)
    (scheduleWithin : queries + max
      (readBudget groupedDecode (actualProgram
        ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
        ns₁ statement₁ pending₁ nonce₁))
      (readBudget groupedDecode (actualProgram
        (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
        ns₂ statement₂ pending₂ nonce₂)) ≤ cap)
    (capBound : cap ≤ 3 * 2 ^ 64)
    (epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed : ℝ)
    (nullifierBound : outcomeEventMass
      (currentJointOriginalBornMass producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
        pending₁ pending₂ nonce₁ nonce₂ ordinaryProgram registers)
      (nullifierPrimitiveEvent (certificateOutput (fun outcome =>
        currentJointDerivedComparisonOutput producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₁ fallback₂ typed₁ typed₂
          parsed₁ parsed₂ input₁ input₂ active₁ active₂ outcome))) ≤ epsilonNullifier)
    (singleBound : outcomeEventMass
      (currentJointOriginalBornMass producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
        pending₁ pending₂ nonce₁ nonce₂ ordinaryProgram registers)
      (singleKeyPrimitiveEvent (certificateOutput (fun outcome =>
        currentJointDerivedComparisonOutput producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₁ fallback₂ typed₁ typed₂
          parsed₁ parsed₂ input₁ input₂ active₁ active₂ outcome))) ≤ epsilonSingle)
    (accumulatorBound : outcomeEventMass
      (currentJointOriginalBornMass producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
        pending₁ pending₂ nonce₁ nonce₂ ordinaryProgram registers)
      (accumulatorPrimitiveEvent (certificateOutput (fun outcome =>
        currentJointDerivedComparisonOutput producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₁ fallback₂ typed₁ typed₂
          parsed₁ parsed₂ input₁ input₂ active₁ active₂ outcome))) ≤ epsilonAccumulator)
    (mixedBound : outcomeEventMass
      (currentJointOriginalBornMass producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
        pending₁ pending₂ nonce₁ nonce₂ ordinaryProgram registers)
      (mixedClawPrimitiveEvent (certificateOutput (fun outcome =>
        currentJointDerivedComparisonOutput producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₁ fallback₂ typed₁ typed₂
          parsed₁ parsed₂ input₁ input₂ active₁ active₂ outcome))) ≤ epsilonMixed) :
    let accepted := currentJointBranchAccepted producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    let firstLoss := currentJointDerivedFirstSelectorFailure producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₁ typed₁
    let secondLoss := currentJointDerivedSecondSelectorFailure producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₂ typed₂
    let output := fun outcome => currentJointDerivedComparisonOutput producer₁ producer₂
      ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₁ fallback₂
      typed₁ typed₂ parsed₁ parsed₂ input₁ input₂ active₁ active₂ outcome
    outcomeEventMass
      (currentJointOriginalBornMass producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
        pending₁ pending₂ nonce₁ nonce₂ ordinaryProgram registers)
      (acceptedJointAuthorizationClosureFailure accepted firstLoss secondLoss output) <
      ((1 / (2 : Rat) ^ 129 : Rat) : ℝ) + epsilonNullifier + epsilonSingle +
        epsilonAccumulator + epsilonMixed := by
  classical
  let joint := secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  let firstProducer := joint.bind fun _ => producer₁
  let secondProducer := secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁
    pending₁ nonce₁
  let firstTarget := actualProgram firstProducer ns₁ statement₁ pending₁ nonce₁
  let secondTarget := actualProgram secondProducer ns₂ statement₂ pending₂ nonce₂
  let firstInputEq : Key joint = Key firstTarget := by
    have h₁ := firstTarget_key_eq_terminalUnitPrefixReplayObserver producer₁ producer₂
      ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    have h₂ := terminal_observer_key_eq_joint producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    have h₁₂ : Key firstTarget =
        Key (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂) := by
      simpa [firstTarget, firstProducer, joint, terminalUnitPrefixReplayObserver,
        terminalWholePrefixObserver] using h₁
    exact (h₁₂.trans h₂.symm).symm
  let secondInputEq : Key joint = Key secondTarget :=
    (secondTarget_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
      pending₁ pending₂ nonce₁ nonce₂).symm
  let firstPrefix := cast (ordinaryPrefixTypeEq (Counter := GroupCounter)
    (BaseWork := BaseWork) (cap := cap) firstInputEq) ordinaryProgram
  let secondPrefix := cast (ordinaryPrefixTypeEq (Counter := GroupCounter)
    (BaseWork := BaseWork) (cap := cap) secondInputEq) ordinaryProgram
  let firstRegisters := castRegisterState (Phase := VectorOutput GroupCounter)
    (Workspace := Work (BaseWork := BaseWork)) firstInputEq registers
  let secondRegisters := castRegisterState (Phase := VectorOutput GroupCounter)
    (Workspace := Work (BaseWork := BaseWork)) secondInputEq registers
  have firstIncomingUnit : normSquared
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ firstRegisters) = 1 := by
    rw [partialRandomOracleState_normSquared_cast_empty firstInputEq registers]
    exact incomingUnit
  have secondIncomingUnit : normSquared
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ secondRegisters) = 1 := by
    rw [partialRandomOracleState_normSquared_cast_empty secondInputEq registers]
    exact incomingUnit
  have firstReadWithin : queries + readBudget groupedDecode firstTarget ≤ cap := by
    exact le_trans (Nat.add_le_add_left (Nat.le_max_left _ _) _) scheduleWithin
  have secondReadWithin : queries + readBudget groupedDecode secondTarget ≤ cap := by
    exact le_trans (Nat.add_le_add_left (Nat.le_max_right _ _) _) scheduleWithin
  have firstProjectionBound := actual_accepted_full_extraction_failure_mass_below_130_bits
    (BaseWork := BaseWork) firstProducer ns₁ statement₁ pending₁ nonce₁ fallback₁ typed₁
    parsed₁ firstPrefix firstRegisters firstIncomingUnit firstReadWithin capBound
  have secondProjectionBound := actual_accepted_full_extraction_failure_mass_below_130_bits
    (BaseWork := BaseWork) secondProducer ns₂ statement₂ pending₂ nonce₂ fallback₂ typed₂
    parsed₂ secondPrefix secondRegisters secondIncomingUnit secondReadWithin capBound
  let mass := currentJointOriginalBornMass producer₁ producer₂ ns₁ ns₂ statement₁
    statement₂ pending₁ pending₂ nonce₁ nonce₂ ordinaryProgram registers
  let firstLoss := currentJointDerivedFirstSelectorFailure (BaseWork := BaseWork)
    producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    fallback₁ typed₁
  let secondLoss := currentJointDerivedSecondSelectorFailure (BaseWork := BaseWork)
    producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    fallback₂ typed₂
  let output := fun outcome => currentJointDerivedComparisonOutput (BaseWork := BaseWork)
    producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    fallback₁ fallback₂ typed₁ typed₂ parsed₁ parsed₂ input₁ input₂ active₁ active₂ outcome
  let accepted := currentJointBranchAccepted (BaseWork := BaseWork) producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  have nonnegative (outcome : Branches groupedDecode joint ×
      Basis (Key joint) (VectorOutput GroupCounter) (VectorOutput GroupCounter)
        (Work (Counter := GroupCounter) (BaseWork := BaseWork))) : 0 ≤ mass outcome :=
    original_outcome_weight_nonnegative _ outcome
  have firstBridge := current_joint_first_selector_mass_eq_event_mass
    (BaseWork := BaseWork) producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
    pending₁ pending₂ nonce₁ nonce₂ fallback₁ typed₁ 28
    (ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers))
  have secondBridge := current_joint_second_selector_mass_eq_event_mass
    (BaseWork := BaseWork) producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
    pending₁ pending₂ nonce₁ nonce₂ fallback₂ typed₂ 28
      (ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers))
  let jointInitial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  have firstInitialCast : cast
      (HegemonCrypto.SmallWood.SmzaRp05CmsKeyEqualityTransport.cmsStateTypeEq
        (Counter := GroupCounter) (BaseWork := BaseWork) firstInputEq) jointInitial =
      ordinaryRun firstPrefix
        (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ firstRegisters) := by
    rw [← partialRandomOracleState_cast_empty firstInputEq registers]
    exact ordinaryRun_cast firstInputEq ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  have secondInitialCast : cast
      (HegemonCrypto.SmallWood.SmzaRp05CmsKeyEqualityTransport.cmsStateTypeEq
        (Counter := GroupCounter) (BaseWork := BaseWork) secondInputEq) jointInitial =
      ordinaryRun secondPrefix
        (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ secondRegisters) := by
    rw [← partialRandomOracleState_cast_empty secondInputEq registers]
    exact ordinaryRun_cast secondInputEq ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  have firstLossBound : outcomeEventMass mass firstLoss <
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) := by
    letI := physicalBranchesFintype groupedDecode firstTarget
    -- The terminal observer mass bridge is the first target's checked
    -- projection sum after the single ordinary-state transport above.
    have firstLossShape : outcomeEventMass mass firstLoss =
        outcomeEventMass
          (originalOutcomeWeight (fun branch =>
            physicalRun (encode joint) groupedDecode joint branch jointInitial))
          (currentJointFirstSelectorFailure (BaseWork := BaseWork)
            producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
            nonce₁ nonce₂ fallback₁ typed₁ 28
            (currentAcceptedMassContexts (BaseWork := BaseWork) firstProducer
              ns₁ statement₁ pending₁ nonce₁
              (relationModel currentDsl certificates) current_model_within_protocol
              (fun _role => fun _ _ _ _ => none) 28 28 .decsMatrix)) := by
      rfl
    rw [firstLossShape, ← firstBridge]
    have firstUniv :
        (@Finset.univ (Branches groupedDecode firstTarget)
          (branchesFintype groupedDecode firstTarget)) =
        (@Finset.univ (Branches groupedDecode firstTarget)
          (physicalBranchesFintype groupedDecode firstTarget)) := by
      ext branch
      simp
    rw [firstUniv]
    rw [firstInitialCast]
    exact firstProjectionBound
  have secondLossBound : outcomeEventMass mass secondLoss <
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) := by
    letI := physicalBranchesFintype groupedDecode secondTarget
    have secondLossShape : outcomeEventMass mass secondLoss =
        outcomeEventMass
          (originalOutcomeWeight (fun branch =>
            physicalRun (encode joint) groupedDecode joint branch jointInitial))
          (currentJointSecondSelectorFailure (BaseWork := BaseWork)
            producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
            nonce₁ nonce₂ fallback₂ typed₂ 28
            (currentAcceptedMassContexts (BaseWork := BaseWork) secondProducer
              ns₂ statement₂ pending₂ nonce₂
              (relationModel currentDsl certificates) current_model_within_protocol
              (fun _role => fun _ _ _ _ => none) 28 28 .decsMatrix)) := by
      rfl
    rw [secondLossShape, ← secondBridge]
    have secondUniv :
        (@Finset.univ (Branches groupedDecode secondTarget)
          (branchesFintype groupedDecode secondTarget)) =
        (@Finset.univ (Branches groupedDecode secondTarget)
          (physicalBranchesFintype groupedDecode secondTarget)) := by
      ext branch
      simp
    rw [secondUniv]
    rw [secondInitialCast]
    exact secondProjectionBound
  exact accepted_joint_authorization_failure_mass_below_129 mass nonnegative accepted
    firstLoss secondLoss output epsilonNullifier epsilonSingle epsilonAccumulator
    epsilonMixed firstLossBound secondLossBound nullifierBound singleBound
    accumulatorBound mixedBound

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentJointAuthorizationMassEndpoint
