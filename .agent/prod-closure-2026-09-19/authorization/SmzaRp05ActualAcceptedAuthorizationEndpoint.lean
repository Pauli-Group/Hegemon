import SmzaRp05AcceptedPairAuthorization
import SmzaRp05CurrentAcceptedRelationWitness
import SmzaRp05CurrentTracePrefixes406
import SmzaRp05CurrentPublicStatementTransport
import SmzaRp05GeneratedCertificates
import SmzaRp05CurrentFullOrRoleXViewCoverage

/-! Connect checked authorization certificates to the designated current
406-map extraction retained by the full-success X-view selector. Every packed
relation witness is fixed to `packedFromRows source.data`, where `source` is
the exact decoder result for the selector's retained records, execution, root,
payload, and coefficients. Two spends may come from distinct actual executions
and independently selected active input slots. Primitive bounds remain
explicit hypotheses on the induced games; no unconditional hash hardness is
asserted here. -/

namespace HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8PublicDecoder
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05CurrentTracePrefixes406
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRelationWitness
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRefinement
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureNullifier
open HegemonCrypto.SmallWood.SmzaRp05CurrentAuthorizationCertificate
open HegemonCrypto.SmallWood.SmzaRp05AcceptedPairAuthorization
open HegemonCrypto.SmallWood.SmzaRp05CurrentFullOrRoleXViewCoverage
open HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult)
open HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteGroupedProgram (Key included)
open HegemonCrypto.SmallWood.SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosure (ExecutionStages)
open HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureStages (PcsStages)
open HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open HegemonCrypto.SmallWood.SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open HegemonCrypto.SmallWood.SmzaRp05LeafNamespace (Namespace)
open HegemonCrypto.SmallWood.SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAdaptiveExecution (Context)
open HegemonCrypto.SmallWood.SmzaRp05ConditionedExecution (XKey xView)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open HegemonCrypto.SmallWood.SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open HegemonCrypto.SmallWood.SmzaRp05TracePrefixes (rootOracle)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open HegemonCrypto.SmallWood.SmzaRp05PcsHashFppMiddle (gammaRows)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8SmzaOracleParser (RawDigest RawInput)
open HegemonCrypto.SmallWood.PiopExtraction (FullySatisfied)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedCausalPayloads (Records)
open HegemonCrypto.SmallWood.SmzaRp04StatementRecordFilter (oneStatementFilter)
open HegemonCrypto.SmallWood.SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open HegemonCrypto.SmallWood.SmzaRp05FilteredReadback (globalLeafStatement)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open HegemonCrypto.SmallWood.SmzaRp05PrimitiveCollisionGameLuna
open HegemonCrypto.SmallWood.SmzaRp05FivePrimitiveGameLedger
open SmzaQ38Recovery (packedFromRows)
open V8Smz9McaDecoder (DecodedSource)
open HegemonCrypto.SmallWood.SmzaRp05CurrentResponseInputDecoder (Goldilocks)
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1600000

attribute [local irreducible]
  SmzaRp05GeneratedCertificates.currentDsl
  SmzaRp05RelationRefinement.candidate
  HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied

/-- Actual current designated extraction plus source-current public admission.
No packed vector or accepted-spend record is supplied independently: the
vector used downstream is definitionally `packedFromRows source.data`. -/
structure DesignatedCurrentWitness (preamble : Statement)
    (typed : V8PublicStatement) where
  root : CurrentCommittedOracle
  fpp : SmzaRp05TracePrefixes.Payload
  coefficients : CurrentCoefficients
  source : DecodedSource Goldilocks (Fin 5) 140
  decoded : currentSourceDecoder406 root fpp coefficients = some source
  parsed : parseCurrentPublicStatement? preamble = some typed
  fullySatisfied : HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
    ((relationModel currentDsl certificates).recoveredCandidate
      preamble source.data).system

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- The successful X-view arm supplies the source itself, not just a claim that
some accepted packed vector exists. Its source is the exact output of the
deterministic current decoder on the retained response records. -/
theorem currentFullSuccessSelector_yields_designated_witness
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest) (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (fuel : Nat)
    (ctx : Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (view : XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput GroupCounter))
    (selected : currentAcceptedXViewFullSuccessSelector producer ns statement pending
      nonce fallback typed fuel ctx branch view) :
    Nonempty (DesignatedCurrentWitness statement typed) := by
  dsimp [currentAcceptedXViewFullSuccessSelector] at selected
  rcases selected with ⟨database, _, _, _, _, _, _, _, _, _, _, _, pcs,
    _, _, _, _, _, _, _, _, _, full⟩
  rcases full with ⟨_, fpp, _, _, _, _, _, _, _, source, decoded, _,
    fullySatisfied, _, _⟩
  let actualProgram := producer.bind fun wire =>
    verifierProgram ns currentDsl statement pending nonce wire
  let erasedRecords := eraseChallengeRecords (rawRecords
    (fun key => groupRepresentative (included actualProgram key))
    (vectorOutputBytes groupZero) database)
  let selectedRoot := rootOracle ns (extract (globalOnlineNext ns)
    (oneStatementFilter (globalLeafStatement ns) statement.toBytes erasedRecords)
    fuel .root pcs.post.root)
  exact ⟨{
    root := selectedRoot,
    fpp := fpp,
    coefficients := sampledCoefficients (gammaRows pcs.post),
    source := source,
    decoded := decoded,
    parsed := parsed,
    fullySatisfied := fullySatisfied }⟩

/-- A designated output map for actual authorization consumers. Classical
choice only packages the selector's proof; the resulting witness retains the
decoder equality and therefore cannot substitute an independently selected
accepted packed witness. -/
noncomputable def designatedWitnessOfFullSuccessSelector
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest) (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? statement = some typed)
    (fuel : Nat)
    (ctx : Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (view : XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput GroupCounter))
    (selected : currentAcceptedXViewFullSuccessSelector producer ns statement pending
      nonce fallback typed fuel ctx branch view) :
    DesignatedCurrentWitness statement typed :=
  Classical.choice (currentFullSuccessSelector_yields_designated_witness
    producer ns statement pending nonce fallback typed parsed fuel ctx branch view selected)

set_option maxHeartbeats 4000000 in
private noncomputable def spendAt
    {preamble : Statement} {typed : V8PublicStatement}
    (witness : DesignatedCurrentWitness preamble typed) (input : Fin 2)
    (active : (encodePublicStatement typed).getD input.val 0 = 1) :
    AcceptedActiveSpend := by
  have accepted := current_full_rows_yield_typed_accepted_witness
    preamble typed witness.parsed witness.source.data witness.fullySatisfied
  exact
    { publicWords := encodePublicStatement typed
      packed := packedFromRows witness.source.data
      input := input
      accepted := accepted.2
      active := active }

/-- Both active input views of the designated source-decoder output, sharing
the same accepted packed relation witness. -/
noncomputable def extractedActivePair {leftPreamble : Statement} {leftTyped : V8PublicStatement}
    {rightPreamble : Statement} {rightTyped : V8PublicStatement}
    (left : DesignatedCurrentWitness leftPreamble leftTyped)
    (right : DesignatedCurrentWitness rightPreamble rightTyped)
    (leftInput rightInput : Fin 2)
    (leftActive : (encodePublicStatement leftTyped).getD leftInput.val 0 = 1)
    (rightActive : (encodePublicStatement rightTyped).getD rightInput.val 0 = 1) :
    AcceptedSpendPair :=
  (spendAt left leftInput leftActive, spendAt right rightInput rightActive)

/-- One comparison is a pair of independently designated current extractor
outputs from the same outer experiment outcome, with active slots selected in
each transaction. The carrier contains no caller-constructed spend record. -/
structure DesignatedAuthorizationComparison where
  leftPreamble : Statement
  leftTyped : V8PublicStatement
  leftWitness : DesignatedCurrentWitness leftPreamble leftTyped
  leftInput : Fin 2
  leftActive : (encodePublicStatement leftTyped).getD leftInput.val 0 = 1
  rightPreamble : Statement
  rightTyped : V8PublicStatement
  rightWitness : DesignatedCurrentWitness rightPreamble rightTyped
  rightInput : Fin 2
  rightActive : (encodePublicStatement rightTyped).getD rightInput.val 0 = 1

/-- Construct the pair carrier from two independently retained successful
current full-success selectors. In particular, this constructor does not take
caller-provided packed witnesses or AcceptedActiveSpend records. -/
noncomputable def comparisonOfCurrentFullSuccessSelectors
    (leftProducer rightProducer : Program ExistingProofFieldView)
    (leftNs rightNs : Namespace)
    (leftPreamble rightPreamble : Statement)
    (leftPending rightPending : Bool)
    (leftNonce rightNonce : Fin (2 ^ 32))
    (leftFallback rightFallback : RawDigest)
    (leftTyped rightTyped : V8PublicStatement)
    (leftParsed : parseCurrentPublicStatement? leftPreamble = some leftTyped)
    (rightParsed : parseCurrentPublicStatement? rightPreamble = some rightTyped)
    (leftFuel rightFuel : Nat)
    (leftCtx : Context (Key := Key
      (leftProducer.bind fun wire => verifierProgram leftNs currentDsl leftPreamble
        leftPending leftNonce wire)) (Counter := GroupCounter) (BaseWork := BaseWork))
    (rightCtx : Context (Key := Key
      (rightProducer.bind fun wire => verifierProgram rightNs currentDsl rightPreamble
        rightPending rightNonce wire)) (Counter := GroupCounter) (BaseWork := BaseWork))
    (leftBranch : Branches groupedDecode
      (leftProducer.bind fun wire => verifierProgram leftNs currentDsl leftPreamble
        leftPending leftNonce wire))
    (rightBranch : Branches groupedDecode
      (rightProducer.bind fun wire => verifierProgram rightNs currentDsl rightPreamble
        rightPending rightNonce wire))
    (leftView : XKey (nonchallengeRawKeySet leftCtx) → Option (VectorOutput GroupCounter))
    (rightView : XKey (nonchallengeRawKeySet rightCtx) → Option (VectorOutput GroupCounter))
    (leftSelected : currentAcceptedXViewFullSuccessSelector leftProducer leftNs
      leftPreamble leftPending leftNonce leftFallback leftTyped leftFuel leftCtx
      leftBranch leftView)
    (rightSelected : currentAcceptedXViewFullSuccessSelector rightProducer rightNs
      rightPreamble rightPending rightNonce rightFallback rightTyped rightFuel rightCtx
      rightBranch rightView)
    (leftInput rightInput : Fin 2)
    (leftActive : (encodePublicStatement leftTyped).getD leftInput.val 0 = 1)
    (rightActive : (encodePublicStatement rightTyped).getD rightInput.val 0 = 1) :
    DesignatedAuthorizationComparison :=
  { leftPreamble := leftPreamble
    leftTyped := leftTyped
    leftWitness := designatedWitnessOfFullSuccessSelector leftProducer leftNs
      leftPreamble leftPending leftNonce leftFallback leftTyped leftParsed leftFuel
      leftCtx leftBranch leftView leftSelected
    leftInput := leftInput
    leftActive := leftActive
    rightPreamble := rightPreamble
    rightTyped := rightTyped
    rightWitness := designatedWitnessOfFullSuccessSelector rightProducer rightNs
      rightPreamble rightPending rightNonce rightFallback rightTyped rightParsed rightFuel
      rightCtx rightBranch rightView rightSelected
    rightInput := rightInput
    rightActive := rightActive }

noncomputable def DesignatedAuthorizationComparison.pair
    (comparison : DesignatedAuthorizationComparison) : AcceptedSpendPair :=
  extractedActivePair comparison.leftWitness comparison.rightWitness
    comparison.leftInput comparison.rightInput comparison.leftActive
    comparison.rightActive

noncomputable def certificateOutput {Outcome : Type}
    (output : Outcome → Option DesignatedAuthorizationComparison) :
    Outcome → Option CurrentAuthorizationPairCertificate :=
  fun outcome => (output outcome).map fun comparison =>
    certificateOfAcceptedPair comparison.pair

/-- Every authorization failure on the actual designated pair yields one of
the exact induced primitive games from the existing current certificates. -/
theorem actual_designated_failure_has_primitive_win
    (comparison : DesignatedAuthorizationComparison)
    (failure : acceptedPairAuthorizationFailure comparison.pair) :
    wins (toCollisionGameOutput
        (sourcePair comparison.pair)) ∨
      (selectedAuthorizationGameOutput
        (certificateOfAcceptedPair comparison.pair)).wins := by
  exact currentAuthorizationCertificateFailure_has_primitive_win
    (certificateOfAcceptedPair comparison.pair)
    ((acceptedPairAuthorizationFailure_iff_certificate
      comparison.pair).mp failure)

/-- Same-original-mass composition for the designated-extractor output map.
The four premises are the actual induced-game advantage bounds on this same
outcome measure. No numerical primitive hardness is inserted. -/
theorem actual_designated_failure_mass_le_assumed_advantages
    {Outcome : Type} [Fintype Outcome]
    (output : Outcome → Option
      DesignatedAuthorizationComparison)
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed : ℝ)
    (nullifierBound : outcomeEventMass mass
      (nullifierPrimitiveEvent (certificateOutput output)) ≤ epsilonNullifier)
    (singleBound : outcomeEventMass mass
      (singleKeyPrimitiveEvent (certificateOutput output)) ≤ epsilonSingle)
    (accumulatorBound : outcomeEventMass mass
      (accumulatorPrimitiveEvent (certificateOutput output)) ≤ epsilonAccumulator)
    (mixedBound : outcomeEventMass mass
      (mixedClawPrimitiveEvent (certificateOutput output)) ≤ epsilonMixed) :
    outcomeEventMass mass (currentAuthorizationFailureEvent
      (certificateOutput output)) ≤
        epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed :=
  currentAuthorizationFailureMass_le_assumed_advantages
    (certificateOutput output) mass nonnegative epsilonNullifier epsilonSingle
    epsilonAccumulator epsilonMixed nullifierBound singleBound
    accumulatorBound mixedBound

end HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
