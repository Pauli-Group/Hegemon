import SmzaRp05CurrentSourceLedgerRunner
import SmzaRp05CurrentSourceLedgerTransitions
import SmzaRp05CurrentAuthorizationCertificate
import SmzaRp05AcceptedPairAuthorization
import SmzaRp05ActualAcceptedAuthorizationEndpoint
import SmzaRp05OriginalMassLossJoin

/-! # First actual source-ledger failure to its induced game output

This adapter starts from the charged failure retained by the chronological
source-ledger fold.  It does not choose an unrelated pair of accepted runs:
the authorization comparison is the public projection of the exact current
spend and earlier spend in the charged classifier.  A path-collision arm is
kept separate. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryCertificateMass

open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRunner
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceBlockReplay
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree (openingAt)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions
  (currentSourceSpendComparison sourceSpendPrimitiveFailure
    sourceSpendPrimitiveFailure_eq_currentSourceSpendComparison)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureCanonicalPaths
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs (publicAnchor)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative (inputSlotNative)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedStageList (selectedTransactions)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceCoinbaseLedger (sourceCoinbaseOpenings)
open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedHistorySupplyEndpoint (coinbasePaid?)
open SmzaFiniteLedgerSupply (Action Ledger potential allowance)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAuthorizationCertificate
open HegemonCrypto.SmallWood.SmzaRp05AcceptedPairAuthorization
  (certificateOfAcceptedPair)
open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
  (DesignatedAuthorizationComparison)
open HegemonCrypto.SmallWood.SmzaRp05ConcretePrimitiveCoverage
open HegemonCrypto.SmallWood.SmzaRp05OriginalMassLossJoin (outcome_mass_union_le_add)
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureNullifier
open HegemonCrypto.SmallWood.SmzaRp05PrimitiveCollisionGameLuna
open HegemonCrypto.SmallWood.SmzaRp05FivePrimitiveGameLedger
open scoped Classical

set_option autoImplicit false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

local notation "certificateOutput" =>
  HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint.certificateOutput

/-- One concrete path-collision arm of the selected run's charged failure.
The witness retains the exact run, input slot, and prior spend when present. -/
inductive CurrentRunPathCollisionWitness
    (ledgerPrefix : CurrentSourceLedgerPrefix) (envelope : CurrentRunEnvelope) : Type where
  | currentInput (input : Fin 2)
      (positive : 0 < inputSlotNative envelope.typedStatement
        (sourcePacked envelope.run) input)
      (collision : HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions.CurrentInputPathCollision envelope.run
        ledgerPrefix.snapshot input) : CurrentRunPathCollisionWitness ledgerPrefix envelope
  | priorInput (input : Fin 2)
      (positive : 0 < inputSlotNative envelope.typedStatement
        (sourcePacked envelope.run) input)
      (old : CurrentSourceSpend) (member : old ∈ ledgerPrefix.priorSpends)
      (collision : HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions.CurrentInputPathCollision old.run old.snapshot old.input) :
      CurrentRunPathCollisionWitness ledgerPrefix envelope
  | runSlots
      (leftPositive : 0 < inputSlotNative envelope.typedStatement
        (sourcePacked envelope.run) 0)
      (rightPositive : 0 < inputSlotNative envelope.typedStatement
        (sourcePacked envelope.run) 1)
      (collision : HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions.CurrentInputPathCollision envelope.run
        ledgerPrefix.snapshot 0 ∨ HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions.CurrentInputPathCollision envelope.run
          ledgerPrefix.snapshot 1) : CurrentRunPathCollisionWitness ledgerPrefix envelope

/-- A proof-carrying exact primitive output for a canonical RP05 path
collision. Leaf inputs are the 18 effective note words hashed by the note
commitment sponge; node inputs are the ordered seven-word children hashed by
Merkle-domain Compress14. -/
inductive CurrentPathPrimitiveCollision : Type where
  | noteCommitment (left right : List Nat)
      (leftExact : ExactWords 18 left) (rightExact : ExactWords 18 right)
      (different : left ≠ right)
      (sameDigest : poseidon2V8Sponge poseidon2V8NoteDomain left =
        poseidon2V8Sponge poseidon2V8NoteDomain right) :
      CurrentPathPrimitiveCollision
  | merkleCompression (leftLeft leftRight rightLeft rightRight : Digest)
      (leftLeftExact : ExactWords 7 leftLeft)
      (leftRightExact : ExactWords 7 leftRight)
      (rightLeftExact : ExactWords 7 rightLeft)
      (rightRightExact : ExactWords 7 rightRight)
      (different : (leftLeft, leftRight) ≠ (rightLeft, rightRight))
      (sameDigest : poseidon2V8Compress14 poseidon2V8MerkleDomain
          leftLeft leftRight =
        poseidon2V8Compress14 poseidon2V8MerkleDomain rightLeft rightRight) :
      CurrentPathPrimitiveCollision

def CurrentPathPrimitiveCollision.isNoteCommitment :
    CurrentPathPrimitiveCollision → Prop
  | .noteCommitment .. => True
  | .merkleCompression .. => False

def CurrentPathPrimitiveCollision.isMerkleCompression :
    CurrentPathPrimitiveCollision → Prop
  | .noteCommitment .. => False
  | .merkleCompression .. => True

private theorem leaf_payload_of_effective_input
    (leaf word : List Nat) (path : AuthenticationPath Digest)
    (member : (HashInput.leaf word : HashInput (List Nat) Digest) ∈
      effectiveInputs rp05PathHash leaf path) : word = leaf := by
  induction path with
  | nil => simpa [effectiveInputs] using member
  | cons step tail ih =>
      have memberSplit :
          (HashInput.leaf word : HashInput (List Nat) Digest) =
              orderedInput step (rootFromPath rp05PathHash leaf tail) ∨
            (HashInput.leaf word : HashInput (List Nat) Digest) ∈
              effectiveInputs rp05PathHash leaf tail := by
        simpa only [effectiveInputs, List.mem_cons] using member
      rcases memberSplit with atNode | inTail
      · cases side : step.childSide <;>
          simp [orderedInput, side] at atNode
      · exact ih inTail

/-- Reduce the canonical effective-input witness itself. No claim is made
that the whole note object has canonical field segmentation: the exact
primitive frame is its effective 18-word sponge input. -/
noncomputable def canonicalPathCollision_primitive
    {left right : List Nat} {leftPath rightPath : AuthenticationPath Digest}
    (collision : CanonicalRp05PathCollision left right leftPath rightPath) :
    CurrentPathPrimitiveCollision := by
  let witness := collision.witness
  cases leftInput : witness.leftInput with
  | leaf leftWords =>
      cases rightInput : witness.rightInput with
      | leaf rightWords =>
          have leftPayload := leaf_payload_of_effective_input left leftWords
            leftPath (by simpa [witness, leftInput] using witness.leftUsed)
          have rightPayload := leaf_payload_of_effective_input right rightWords
            rightPath (by simpa [witness, rightInput] using witness.rightUsed)
          have leftInputExact := collision.leftExact
          rw [leftInput] at leftInputExact
          have leftExact : ExactWords 18 left := by
            simpa only [CanonicalEffectiveInput, leftPayload] using leftInputExact
          have rightInputExact := collision.rightExact
          rw [rightInput] at rightInputExact
          have rightExact : ExactWords 18 right := by
            simpa only [CanonicalEffectiveInput, rightPayload] using rightInputExact
          have different : left ≠ right := by
            intro equal
            apply witness.different
            simpa [leftInput, rightInput] using
              congrArg (fun words : List Nat =>
                (HashInput.leaf words : HashInput (List Nat) Digest))
                (leftPayload.trans (equal.trans rightPayload.symm))
          have sameDigest : poseidon2V8Sponge poseidon2V8NoteDomain left =
              poseidon2V8Sponge poseidon2V8NoteDomain right := by
            simpa [rp05PathHash, leftInput, rightInput, leftPayload, rightPayload]
              using witness.sameDigest
          exact .noteCommitment left right leftExact rightExact different sameDigest
      | node rightLeft rightRight =>
          have sameKind := witness.sameKind
          simp [leftInput, rightInput, isLeafInput] at sameKind
  | node leftLeft leftRight =>
      cases rightInput : witness.rightInput with
      | leaf rightWords =>
          have sameKind := witness.sameKind
          simp [leftInput, rightInput, isLeafInput] at sameKind
      | node rightLeft rightRight =>
          have leftInputExact := collision.leftExact
          rw [leftInput] at leftInputExact
          have leftExact : ExactWords 7 leftLeft ∧ ExactWords 7 leftRight := by
            simpa only [CanonicalEffectiveInput] using leftInputExact
          have rightInputExact := collision.rightExact
          rw [rightInput] at rightInputExact
          have rightExact : ExactWords 7 rightLeft ∧ ExactWords 7 rightRight := by
            simpa only [CanonicalEffectiveInput] using rightInputExact
          have different : (leftLeft, leftRight) ≠ (rightLeft, rightRight) := by
            intro equal
            apply witness.different
            cases equal
            simp [leftInput, rightInput]
          have sameDigest : poseidon2V8Compress14 poseidon2V8MerkleDomain
              leftLeft leftRight = poseidon2V8Compress14 poseidon2V8MerkleDomain
                rightLeft rightRight := by
            simpa [rp05PathHash, leftInput, rightInput] using witness.sameDigest
          exact .merkleCompression leftLeft leftRight rightLeft rightRight
            leftExact.1 leftExact.2 rightExact.1 rightExact.2 different sameDigest

/-- Exact same-position pair retained by the input-failure classifier. -/
structure CurrentRunAuthorizationGameWitness
    (ledgerPrefix : CurrentSourceLedgerPrefix) (envelope : CurrentRunEnvelope) where
  admitted : publicAnchor (encodePublicStatement envelope.typedStatement) ∈
    ledgerPrefix.snapshot.parent.history
  input : Fin 2
  positive : 0 < inputSlotNative envelope.typedStatement
    (sourcePacked envelope.run) input
  old : CurrentSourceSpend
  oldMember : old ∈ ledgerPrefix.priorSpends
  samePosition : old.position =
    (⟨envelope.preamble, envelope.typedStatement, envelope.run, input,
      positive, ledgerPrefix.snapshot, admitted⟩ : CurrentSourceSpend).position
  primitiveFailure : sourceSpendPrimitiveFailure
    ⟨envelope.preamble, envelope.typedStatement, envelope.run, input,
      positive, ledgerPrefix.snapshot, admitted⟩ old

private theorem charged_failure_has_path_or_actual_pair
    (ledgerPrefix : CurrentSourceLedgerPrefix) (envelope : CurrentRunEnvelope)
    (failure : CurrentRunChargedFailure ledgerPrefix envelope) :
    Nonempty (CurrentRunPathCollisionWitness ledgerPrefix envelope ⊕
      CurrentRunAuthorizationGameWitness ledgerPrefix envelope) := by
  cases failure with
  | input inputFailure =>
      rename_i admitted
      rcases inputFailure with ⟨input, positive, charged⟩
      rcases charged with currentCollision | oldCollision | samePosition
      · exact ⟨Sum.inl (.currentInput input positive currentCollision)⟩
      · obtain ⟨old, oldMember, collision⟩ := oldCollision
        exact ⟨Sum.inl (.priorInput input positive old oldMember collision)⟩
      · obtain ⟨old, oldMember, samePosition, primitiveFailure⟩ := samePosition
        exact ⟨Sum.inr ⟨admitted, input, positive, old, oldMember,
          samePosition, primitiveFailure⟩⟩
  | pathCollision leftPositive rightPositive collision =>
      exact ⟨Sum.inl (.runSlots leftPositive rightPositive collision)⟩

/-- The failure arm and its chosen proof data from the actual finite-ledger
fold. The comparison output below is obtained only from this retained frame. -/
structure CurrentRunChargedFailureFrame where
  ledgerPrefix : CurrentSourceLedgerPrefix
  envelope : CurrentRunEnvelope
  failure : CurrentRunChargedFailure ledgerPrefix envelope

/-- Read the actual selected-run outcome from the fold tuple chosen out of
`selected_block_fold_from_boundary`. The outcome carrier is data-valued, so
the charged arm retains its concrete prefix and envelope. -/
def currentSelectedOutcomeFailureFrame :
    CurrentSelectedRunOutcome → Option CurrentRunChargedFailureFrame
  | .complete => none
  | .chargedFailure (ledgerPrefix := ledgerPrefix) (envelope := envelope) failure =>
      some ⟨ledgerPrefix, envelope, failure⟩

/-- Project only the first charged source-input arm from the exact recursive
history result. Complete histories and native-replay/coinbase-check failures
remain explicit non-charged outcomes; they cannot manufacture a fold frame. -/
def currentSelectedHistoryFailureFrame
    {blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))}
    {initial : CurrentSourceLedgerPrefix} :
    CurrentSelectedHistoryOutcome (BaseWork := BaseWork) blocks initial →
      Option CurrentRunChargedFailureFrame
  | .complete _ _ _ => none
  | .failed _ _ failure =>
      match failure with
      | .native _ _ => none
      | .sourceInput _ _ (ledgerPrefix := ledgerPrefix)
          (envelope := envelope) chargedFailure _ =>
          some ⟨ledgerPrefix, envelope, chargedFailure⟩
      | .coinbase _ _ _ _ => none

omit [Fintype BaseWork] [DecidableEq BaseWork] in
@[simp] theorem currentSelectedHistoryFailureFrame_complete
    {blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))}
    {initial final : CurrentSourceLedgerPrefix}
    (trace : CurrentSelectedHistoryTrace blocks initial final)
    (boundary : final.stagedOpenings = final.snapshot.openings)
    (invariant : potential (openingAt final.stagedOpenings) final.ledger ≤
      allowance final.ledger) :
    currentSelectedHistoryFailureFrame (.complete trace boundary invariant) = none := rfl

omit [Fintype BaseWork] [DecidableEq BaseWork] in
@[simp] theorem currentSelectedHistoryFailureFrame_native
    {done tail : List (CurrentSelectedBlock (BaseWork := BaseWork))}
    {initial before : CurrentSourceLedgerPrefix}
    (trace : CurrentSelectedHistoryTrace done initial before)
    (block : CurrentSelectedBlock (BaseWork := BaseWork))
    (failure : CurrentBlockError)
    (actual : executeSelectedCurrentBlock before block.stages block.coinbase =
      .error failure) :
    currentSelectedHistoryFailureFrame
      (blocks := done ++ block :: tail) (initial := initial)
      (.failed (tail := tail) trace block (.native failure actual)) = none := rfl

omit [Fintype BaseWork] [DecidableEq BaseWork] in
@[simp] theorem currentSelectedHistoryFailureFrame_coinbase
    {done tail : List (CurrentSelectedBlock (BaseWork := BaseWork))}
    {initial before : CurrentSourceLedgerPrefix}
    (trace : CurrentSelectedHistoryTrace done initial before)
    (block : CurrentSelectedBlock (BaseWork := BaseWork))
    (result : CurrentBlockReplayResult before.snapshot.parent before.spentNullifiers
      (selectedTransactions block.stages) block.coinbase)
    (native : executeSelectedCurrentBlock before block.stages block.coinbase =
      .ok result)
    {actions : List Action} {final : CurrentSourceLedgerPrefix}
    (fold : CurrentSelectedRunFold (selectedBlockLedgerRegistry before result)
      (sourceCoinbaseOpenings block.coinbase) before result.runs actions final .complete)
    (checker : coinbasePaid? (currentSupplyCheckState before.ledger)
      (selectedDesignatedRuns result.runs) block.coinbase = none) :
    currentSelectedHistoryFailureFrame
      (blocks := done ++ block :: tail) (initial := initial)
      (.failed (tail := tail) trace block (.coinbase result native fold checker)) = none := rfl

omit [Fintype BaseWork] [DecidableEq BaseWork] in
@[simp] theorem currentSelectedHistoryFailureFrame_sourceInput
    {done tail : List (CurrentSelectedBlock (BaseWork := BaseWork))}
    {initial before : CurrentSourceLedgerPrefix}
    (trace : CurrentSelectedHistoryTrace done initial before)
    (block : CurrentSelectedBlock (BaseWork := BaseWork))
    (result : CurrentBlockReplayResult before.snapshot.parent before.spentNullifiers
      (selectedTransactions block.stages) block.coinbase)
    (native : executeSelectedCurrentBlock before block.stages block.coinbase =
      .ok result)
    {actions : List Action} {final ledgerPrefix : CurrentSourceLedgerPrefix}
    {envelope : CurrentRunEnvelope}
    (chargedFailure : CurrentRunChargedFailure ledgerPrefix envelope)
    (fold : CurrentSelectedRunFold (selectedBlockLedgerRegistry before result)
      (sourceCoinbaseOpenings block.coinbase) before result.runs actions final
        (.chargedFailure chargedFailure)) :
    currentSelectedHistoryFailureFrame
      (blocks := done ++ block :: tail) (initial := initial)
      (.failed (tail := tail) trace block
        (.sourceInput result native chargedFailure fold)) =
      some ⟨ledgerPrefix, envelope, chargedFailure⟩ := rfl

/-- Per-original-outcome projection of the actual empty-genesis executor.
The only input is that outcome's selected block history; success/failure and
the charged frame are computed by the executor itself. -/
noncomputable def currentHistoryGenesisOutcomeFrames {Outcome : Type}
    (blocks : Outcome → List (CurrentSelectedBlock (BaseWork := BaseWork))) :
    Outcome → Option CurrentRunChargedFailureFrame :=
  fun outcome => currentSelectedHistoryFailureFrame
    (executeSelectedCurrentHistoryFromGenesis (blocks outcome))

@[simp] theorem currentSelectedOutcomeFailureFrame_complete :
    currentSelectedOutcomeFailureFrame .complete = none := rfl

@[simp] theorem currentSelectedOutcomeFailureFrame_charged
    (ledgerPrefix : CurrentSourceLedgerPrefix) (envelope : CurrentRunEnvelope)
    (failure : CurrentRunChargedFailure ledgerPrefix envelope) :
    currentSelectedOutcomeFailureFrame (.chargedFailure failure) =
      some ⟨ledgerPrefix, envelope, failure⟩ := rfl

/-- Outcome-indexed frame map for the actual outcome component selected from
the existential whole-history fold result. -/
def currentHistoryOutcomeFrames {Outcome : Type}
    (selectedOutcome : Outcome → CurrentSelectedRunOutcome) :
    Outcome → Option CurrentRunChargedFailureFrame :=
  fun outcome => currentSelectedOutcomeFailureFrame (selectedOutcome outcome)

/-- The failure-frame projection is indexed by the exact fold input and
output lists. Its witness is chosen from a charged fold derivation for those
same indices, so it cannot substitute an unrelated accepted-run pair. -/
def CurrentRunFoldFailureFrameExists
    (registry : Nat → V8NoteOpening) (trailing : List V8NoteOpening)
    (initial : CurrentSourceLedgerPrefix) (runs : List CurrentRunEnvelope)
    (actions : List Action) (final : CurrentSourceLedgerPrefix) : Prop :=
  ∃ frame : CurrentRunChargedFailureFrame,
    CurrentSelectedRunFold registry trailing initial runs actions final
      (.chargedFailure frame.failure)

noncomputable def currentRunFoldFailureFrame
    (registry : Nat → V8NoteOpening) (trailing : List V8NoteOpening)
    (initial : CurrentSourceLedgerPrefix) (runs : List CurrentRunEnvelope)
    (actions : List Action) (final : CurrentSourceLedgerPrefix) :
    Option CurrentRunChargedFailureFrame :=
  if hasFailure : CurrentRunFoldFailureFrameExists registry trailing initial
      runs actions final then
    some (Classical.choose hasFailure)
  else none

theorem currentRunFoldFailureFrame_is_actual
    (registry : Nat → V8NoteOpening) (trailing : List V8NoteOpening)
    (initial : CurrentSourceLedgerPrefix) (runs : List CurrentRunEnvelope)
    (actions : List Action) (final : CurrentSourceLedgerPrefix)
    (frame : CurrentRunChargedFailureFrame)
    (selected : currentRunFoldFailureFrame registry trailing initial runs actions
      final = some frame) :
    CurrentSelectedRunFold registry trailing initial runs actions final
      (.chargedFailure frame.failure) := by
  by_cases hasFailure : CurrentRunFoldFailureFrameExists registry trailing
      initial runs actions final
  · simp [currentRunFoldFailureFrame, hasFailure] at selected
    subst frame
    exact Classical.choose_spec hasFailure
  · simp [currentRunFoldFailureFrame, hasFailure] at selected

noncomputable def classifyCurrentRunChargedFailure
    (frame : CurrentRunChargedFailureFrame) :
    CurrentRunPathCollisionWitness frame.ledgerPrefix frame.envelope ⊕
      CurrentRunAuthorizationGameWitness frame.ledgerPrefix frame.envelope :=
  Classical.choice (charged_failure_has_path_or_actual_pair
    frame.ledgerPrefix frame.envelope frame.failure)

/-- Optional deterministic comparison selected from the charged arm. The
`some` case contains precisely the pair already retained by the equal-position
failure; the path-collision alternative remains a `none` here. -/
noncomputable def currentRunFailureComparisonOutput
    (frame : CurrentRunChargedFailureFrame) :
    Option DesignatedAuthorizationComparison :=
  match classifyCurrentRunChargedFailure frame with
  | .inl _ => none
  | .inr witness =>
      some (currentSourceSpendComparison
        ⟨frame.envelope.preamble, frame.envelope.typedStatement,
          frame.envelope.run, witness.input, witness.positive,
          frame.ledgerPrefix.snapshot, witness.admitted⟩ witness.old)

noncomputable def currentRunFailurePathOutput
    (frame : CurrentRunChargedFailureFrame) :
    Option (CurrentRunPathCollisionWitness frame.ledgerPrefix frame.envelope) :=
  match classifyCurrentRunChargedFailure frame with
  | .inl witness => some witness
  | .inr _ => none

/-- Exact collision-game certificate emitted by a retained input-path
collision. `CurrentInputPathCollision` keeps the accepted path and historical
prefix path tied to the same designated input/position. -/
noncomputable def currentInputPathCollision_primitive
    {preamble : HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement}
    {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (snapshot : CurrentNativeSnapshot)
    (input : Fin 2)
    (collision : HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions.CurrentInputPathCollision
      run snapshot input) : CurrentPathPrimitiveCollision := by
  let countFacts := Classical.choose_spec collision
  let pathExists := countFacts.2
  have pathFacts := Classical.choose_spec pathExists
  exact canonicalPathCollision_primitive (Classical.choice pathFacts.2)

noncomputable def currentRunPathCollision_primitive
    (frame : CurrentRunChargedFailureFrame)
    (witness : CurrentRunPathCollisionWitness frame.ledgerPrefix frame.envelope) :
    CurrentPathPrimitiveCollision := by
  classical
  cases witness with
  | currentInput input positive collision =>
      exact currentInputPathCollision_primitive frame.envelope.run
        frame.ledgerPrefix.snapshot input collision
  | priorInput input positive old member collision =>
      exact currentInputPathCollision_primitive old.run old.snapshot old.input collision
  | runSlots leftPositive rightPositive collision =>
      by_cases left :
          HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions.CurrentInputPathCollision
            frame.envelope.run frame.ledgerPrefix.snapshot 0
      · exact currentInputPathCollision_primitive frame.envelope.run
          frame.ledgerPrefix.snapshot 0 left
      · exact currentInputPathCollision_primitive frame.envelope.run
          frame.ledgerPrefix.snapshot 1 (Or.resolve_left collision left)

noncomputable def currentRunFailurePathPrimitiveOutput
    (frame : CurrentRunChargedFailureFrame) :
    Option CurrentPathPrimitiveCollision :=
  match classifyCurrentRunChargedFailure frame with
  | .inl path => some (currentRunPathCollision_primitive frame path)
  | .inr _ => none

theorem currentRunFailure_comparison_or_path
    (frame : CurrentRunChargedFailureFrame) :
    (currentRunFailureComparisonOutput frame).isSome ∨
      (currentRunFailurePathOutput frame).isSome := by
  cases choice : classifyCurrentRunChargedFailure frame with
  | inl witness =>
      right
      unfold currentRunFailurePathOutput
      rw [choice]
      rfl
  | inr witness =>
      left
      unfold currentRunFailureComparisonOutput
      rw [choice]
      rfl

theorem currentRunFailureComparisonOutput_has_primitive_game
    (frame : CurrentRunChargedFailureFrame)
    (comparison : DesignatedAuthorizationComparison)
    (outputEq : currentRunFailureComparisonOutput frame = some comparison) :
    wins (toCollisionGameOutput (sourcePair comparison.pair)) ∨
      (selectedAuthorizationGameOutput
        (certificateOfAcceptedPair comparison.pair)).wins := by
  cases choice : classifyCurrentRunChargedFailure frame with
  | inl path =>
      unfold currentRunFailureComparisonOutput at outputEq
      rw [choice] at outputEq
      cases outputEq
  | inr witness =>
      unfold currentRunFailureComparisonOutput at outputEq
      rw [choice] at outputEq
      have primitive := witness.primitiveFailure
      rw [sourceSpendPrimitiveFailure_eq_currentSourceSpendComparison] at primitive
      have comparisonEq := Option.some.inj outputEq
      subst comparison
      exact primitive

/-- Bind the comparison and path-certificate outputs to one original
outcome carrier. A `none` outcome remains absent; selected failures are
classified from their actual retained fold frame. -/
noncomputable def currentHistoryFailureComparisonOutput
    {Outcome : Type} (frames : Outcome → Option CurrentRunChargedFailureFrame) :
    Outcome → Option DesignatedAuthorizationComparison :=
  fun outcome => (frames outcome).bind currentRunFailureComparisonOutput

noncomputable def currentHistoryFailurePathOutput
    {Outcome : Type} (frames : Outcome → Option CurrentRunChargedFailureFrame) :
    Outcome → Option (Σ frame : CurrentRunChargedFailureFrame,
      CurrentRunPathCollisionWitness frame.ledgerPrefix frame.envelope) :=
  fun outcome => (frames outcome).bind fun frame =>
    (currentRunFailurePathOutput frame).map fun path => ⟨frame, path⟩

noncomputable def currentHistoryFailurePathPrimitiveOutput {Outcome : Type}
    (frames : Outcome → Option CurrentRunChargedFailureFrame) :
    Outcome → Option CurrentPathPrimitiveCollision :=
  fun outcome => (frames outcome).bind currentRunFailurePathPrimitiveOutput

def currentHistoryChargedFailureEvent {Outcome : Type}
    (frames : Outcome → Option CurrentRunChargedFailureFrame)
    (outcome : Outcome) : Prop :=
  (frames outcome).isSome

def currentHistoryPathCollisionEvent {Outcome : Type}
    (frames : Outcome → Option CurrentRunChargedFailureFrame)
    (outcome : Outcome) : Prop :=
  (currentHistoryFailurePathOutput frames outcome).isSome

def currentHistoryPathPrimitiveGameEvent {Outcome : Type}
    (frames : Outcome → Option CurrentRunChargedFailureFrame)
    (outcome : Outcome) : Prop :=
  (currentHistoryFailurePathPrimitiveOutput frames outcome).isSome

def currentHistoryPathNoteCommitmentGameEvent {Outcome : Type}
    (frames : Outcome → Option CurrentRunChargedFailureFrame)
    (outcome : Outcome) : Prop :=
  ∃ output, currentHistoryFailurePathPrimitiveOutput frames outcome = some output ∧
    output.isNoteCommitment

def currentHistoryPathMerkleCompressionGameEvent {Outcome : Type}
    (frames : Outcome → Option CurrentRunChargedFailureFrame)
    (outcome : Outcome) : Prop :=
  ∃ output, currentHistoryFailurePathPrimitiveOutput frames outcome = some output ∧
    output.isMerkleCompression

theorem currentHistoryPathPrimitiveGameEvent_in_note_or_merkle
    {Outcome : Type}
    (frames : Outcome → Option CurrentRunChargedFailureFrame)
    (outcome : Outcome) :
    currentHistoryPathPrimitiveGameEvent frames outcome →
      currentHistoryPathNoteCommitmentGameEvent frames outcome ∨
        currentHistoryPathMerkleCompressionGameEvent frames outcome := by
  intro present
  cases outputEq : currentHistoryFailurePathPrimitiveOutput frames outcome with
  | none => simp [currentHistoryPathPrimitiveGameEvent, outputEq] at present
  | some output =>
      cases output with
      | noteCommitment left right leftExact rightExact different sameDigest =>
          exact Or.inl ⟨_, outputEq, trivial⟩
      | merkleCompression leftLeft leftRight rightLeft rightRight
          leftLeftExact leftRightExact rightLeftExact rightRightExact different sameDigest =>
          exact Or.inr ⟨_, outputEq, trivial⟩

noncomputable def currentHistoryOutcomeComparisonOutput {Outcome : Type}
    (selectedOutcome : Outcome → CurrentSelectedRunOutcome) :
    Outcome → Option DesignatedAuthorizationComparison :=
  currentHistoryFailureComparisonOutput (currentHistoryOutcomeFrames selectedOutcome)

noncomputable def currentHistoryOutcomePathOutput {Outcome : Type}
    (selectedOutcome : Outcome → CurrentSelectedRunOutcome) :
    Outcome → Option (Σ frame : CurrentRunChargedFailureFrame,
      CurrentRunPathCollisionWitness frame.ledgerPrefix frame.envelope) :=
  currentHistoryFailurePathOutput (currentHistoryOutcomeFrames selectedOutcome)

def currentHistoryOutcomeChargedFailureEvent {Outcome : Type}
    (selectedOutcome : Outcome → CurrentSelectedRunOutcome)
    (outcome : Outcome) : Prop :=
  currentHistoryChargedFailureEvent (currentHistoryOutcomeFrames selectedOutcome)
    outcome

def currentHistoryOutcomePathCollisionEvent {Outcome : Type}
    (selectedOutcome : Outcome → CurrentSelectedRunOutcome)
    (outcome : Outcome) : Prop :=
  currentHistoryPathCollisionEvent (currentHistoryOutcomeFrames selectedOutcome)
    outcome

noncomputable def currentHistoryGenesisComparisonOutput {Outcome : Type}
    (blocks : Outcome → List (CurrentSelectedBlock (BaseWork := BaseWork))) :
    Outcome → Option DesignatedAuthorizationComparison :=
  currentHistoryFailureComparisonOutput (currentHistoryGenesisOutcomeFrames blocks)

noncomputable def currentHistoryGenesisPathOutput {Outcome : Type}
    (blocks : Outcome → List (CurrentSelectedBlock (BaseWork := BaseWork))) :
    Outcome → Option (Σ frame : CurrentRunChargedFailureFrame,
      CurrentRunPathCollisionWitness frame.ledgerPrefix frame.envelope) :=
  currentHistoryFailurePathOutput (currentHistoryGenesisOutcomeFrames blocks)

noncomputable def currentHistoryGenesisPathPrimitiveOutput {Outcome : Type}
    (blocks : Outcome → List (CurrentSelectedBlock (BaseWork := BaseWork))) :
    Outcome → Option CurrentPathPrimitiveCollision :=
  currentHistoryFailurePathPrimitiveOutput (currentHistoryGenesisOutcomeFrames blocks)

def currentHistoryGenesisChargedFailureEvent {Outcome : Type}
    (blocks : Outcome → List (CurrentSelectedBlock (BaseWork := BaseWork)))
    (outcome : Outcome) : Prop :=
  currentHistoryChargedFailureEvent (currentHistoryGenesisOutcomeFrames blocks) outcome

def currentHistoryGenesisPathCollisionEvent {Outcome : Type}
    (blocks : Outcome → List (CurrentSelectedBlock (BaseWork := BaseWork)))
    (outcome : Outcome) : Prop :=
  currentHistoryPathCollisionEvent (currentHistoryGenesisOutcomeFrames blocks) outcome

def currentHistoryGenesisPathPrimitiveGameEvent {Outcome : Type}
    (blocks : Outcome → List (CurrentSelectedBlock (BaseWork := BaseWork)))
    (outcome : Outcome) : Prop :=
  currentHistoryPathPrimitiveGameEvent (currentHistoryGenesisOutcomeFrames blocks) outcome

def currentHistoryGenesisPathNoteCommitmentGameEvent {Outcome : Type}
    (blocks : Outcome → List (CurrentSelectedBlock (BaseWork := BaseWork)))
    (outcome : Outcome) : Prop :=
  currentHistoryPathNoteCommitmentGameEvent (currentHistoryGenesisOutcomeFrames blocks)
    outcome

def currentHistoryGenesisPathMerkleCompressionGameEvent {Outcome : Type}
    (blocks : Outcome → List (CurrentSelectedBlock (BaseWork := BaseWork)))
    (outcome : Outcome) : Prop :=
  currentHistoryPathMerkleCompressionGameEvent (currentHistoryGenesisOutcomeFrames blocks)
    outcome

theorem currentHistoryFailure_comparison_or_path
    {Outcome : Type} (frames : Outcome → Option CurrentRunChargedFailureFrame)
    (outcome : Outcome) (present : (frames outcome).isSome) :
    (currentHistoryFailureComparisonOutput frames outcome).isSome ∨
      (currentHistoryFailurePathOutput frames outcome).isSome := by
  cases frameOption : frames outcome with
  | none => simp [frameOption] at present
  | some frame =>
      have localCover := currentRunFailure_comparison_or_path frame
      simpa [currentHistoryFailureComparisonOutput,
        currentHistoryFailurePathOutput, frameOption] using localCover

/-- Direct game-win event for comparisons produced by the actual charged
run arm. This is intentionally not an accepted-pair certificate-failure
event: primitive wins are handled in their forward direction. -/
def sourceSpendPrimitiveGameEvent {Outcome : Type}
    (output : Outcome → Option DesignatedAuthorizationComparison)
    (outcome : Outcome) : Prop :=
  ∃ comparison, output outcome = some comparison ∧
    (wins (toCollisionGameOutput (sourcePair comparison.pair)) ∨
      (selectedAuthorizationGameOutput
        (certificateOfAcceptedPair comparison.pair)).wins)

theorem currentHistoryFailureComparisonOutput_gameEvent
    {Outcome : Type} (frames : Outcome → Option CurrentRunChargedFailureFrame)
    (outcome : Outcome)
    (comparison : DesignatedAuthorizationComparison)
    (outputEq : currentHistoryFailureComparisonOutput frames outcome =
      some comparison) :
    sourceSpendPrimitiveGameEvent
      (currentHistoryFailureComparisonOutput frames) outcome := by
  cases frameEq : frames outcome with
  | none => simp [currentHistoryFailureComparisonOutput, frameEq] at outputEq
  | some frame =>
      have comparisonEq : currentRunFailureComparisonOutput frame =
          some comparison := by
        simpa [currentHistoryFailureComparisonOutput, frameEq] using outputEq
      exact ⟨comparison, outputEq,
        currentRunFailureComparisonOutput_has_primitive_game frame comparison
          comparisonEq⟩

theorem currentHistoryChargedFailureEvent_included
    {Outcome : Type} (frames : Outcome → Option CurrentRunChargedFailureFrame)
    (outcome : Outcome) :
    currentHistoryChargedFailureEvent frames outcome →
      currentHistoryPathPrimitiveGameEvent frames outcome ∨
      sourceSpendPrimitiveGameEvent
        (currentHistoryFailureComparisonOutput frames) outcome := by
  intro present
  cases frameEq : frames outcome with
  | none => simp [currentHistoryChargedFailureEvent, frameEq] at present
  | some frame =>
      cases choice : classifyCurrentRunChargedFailure frame with
      | inl path =>
          left
          change ((frames outcome).bind currentRunFailurePathPrimitiveOutput).isSome
          rw [frameEq, Option.bind_some]
          unfold currentRunFailurePathPrimitiveOutput
          rw [choice]
          rfl
      | inr witness =>
          right
          let comparison := currentSourceSpendComparison
            ⟨frame.envelope.preamble, frame.envelope.typedStatement,
              frame.envelope.run, witness.input, witness.positive,
              frame.ledgerPrefix.snapshot, witness.admitted⟩ witness.old
          have outputEq : currentHistoryFailureComparisonOutput frames outcome =
              some comparison := by
            change ((frames outcome).bind currentRunFailureComparisonOutput) =
              some comparison
            rw [frameEq, Option.bind_some]
            unfold currentRunFailureComparisonOutput
            rw [choice]
          exact currentHistoryFailureComparisonOutput_gameEvent frames outcome
            comparison outputEq

/- This source-to-game proof keeps the selected game winner symbolic. The
constructor-name style linter forces WHNF of the nested game-output witness
and exhausts recursion here; kernel elaboration and the other linters remain
enabled. -/
set_option linter.constructorNameAsVariable false in
theorem sourceSpendPrimitiveGameEvent_implies_one_of_four
    {Outcome : Type}
    (output : Outcome → Option DesignatedAuthorizationComparison)
    (outcome : Outcome)
    (hit : sourceSpendPrimitiveGameEvent output outcome) :
    nullifierPrimitiveEvent (certificateOutput output) outcome ∨
      singleKeyPrimitiveEvent (certificateOutput output) outcome ∨
      accumulatorPrimitiveEvent (certificateOutput output) outcome ∨
      mixedClawPrimitiveEvent (certificateOutput output) outcome := by
  obtain ⟨comparison, outputEq, gameHit⟩ := hit
  rcases gameHit with collision | authorization
  · left
    refine ⟨certificateOfAcceptedPair comparison.pair, ?_, ?_⟩
    · simp [HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint.certificateOutput,
        outputEq]
    · simpa [certificateOfAcceptedPair, CurrentAuthorizationPairCertificate.spends] using collision
  · cases gameOutput : selectedAuthorizationGameOutput
      (certificateOfAcceptedPair comparison.pair) with
    | singleKey pair =>
        right; left
        have pairHit : singleKeyCollision pair := by
          rw [gameOutput, FramedAuthorizationGameOutput.wins] at authorization
          exact authorization
        refine ⟨certificateOfAcceptedPair comparison.pair, pair, ?_, gameOutput,
          pairHit⟩
        simp [HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint.certificateOutput,
          outputEq]
    | accumulator pair =>
        right; right; left
        have pairHit : accumulatorCompress14Collision pair := by
          rw [gameOutput, FramedAuthorizationGameOutput.wins] at authorization
          exact authorization
        refine ⟨certificateOfAcceptedPair comparison.pair, pair, ?_, gameOutput,
          pairHit⟩
        simp [HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint.certificateOutput,
          outputEq]
    | mixed pair =>
        right; right; right
        have pairHit : mixedDomainClaw pair := by
          rw [gameOutput, FramedAuthorizationGameOutput.wins] at authorization
          exact authorization
        refine ⟨certificateOfAcceptedPair comparison.pair, pair, ?_, gameOutput,
          pairHit⟩
        simp [HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint.certificateOutput,
          outputEq]

private theorem eventMass_mono_of_implication
    {Outcome : Type} [Fintype Outcome]
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (left right : Outcome → Prop)
    (included : ∀ outcome, left outcome → right outcome) :
    outcomeEventMass mass left ≤ outcomeEventMass mass right := by
  classical
  unfold outcomeEventMass
  apply Finset.sum_le_sum
  intro outcome _
  by_cases leftHit : left outcome
  · have rightHit := included outcome leftHit
    simp [leftHit, rightHit]
  · by_cases rightHit : right outcome
    · simpa [leftHit, rightHit] using nonnegative outcome
    · simp [leftHit, rightHit]

private theorem eventMass_le_note_add_merkle
    {Outcome : Type} [Fintype Outcome]
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (frames : Outcome → Option CurrentRunChargedFailureFrame) :
    outcomeEventMass mass (currentHistoryPathPrimitiveGameEvent frames) ≤
      outcomeEventMass mass (currentHistoryPathNoteCommitmentGameEvent frames) +
        outcomeEventMass mass (currentHistoryPathMerkleCompressionGameEvent frames) := by
  have included := eventMass_mono_of_implication mass nonnegative
    (currentHistoryPathPrimitiveGameEvent frames)
    (fun outcome => currentHistoryPathNoteCommitmentGameEvent frames outcome ∨
      currentHistoryPathMerkleCompressionGameEvent frames outcome)
    (fun outcome => currentHistoryPathPrimitiveGameEvent_in_note_or_merkle frames outcome)
  have splitMass := SmzaRp05OriginalMassLossJoin.outcome_mass_union_le_add
    mass nonnegative (currentHistoryPathNoteCommitmentGameEvent frames)
    (currentHistoryPathMerkleCompressionGameEvent frames)
  linarith

/-- The direct primitive-win event generated from the actual charged pair is
covered by the four exact induced-game events on the same output map. This
does not use the reverse (invalid) implication from game win to certificate
failure. -/
theorem sourceSpendPrimitiveGameEvent_mass_le_four_game_masses
    {Outcome : Type} [Fintype Outcome]
    (output : Outcome → Option DesignatedAuthorizationComparison)
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome) :
    outcomeEventMass mass (sourceSpendPrimitiveGameEvent output) ≤
      outcomeEventMass mass (nullifierPrimitiveEvent (certificateOutput output)) +
      outcomeEventMass mass (singleKeyPrimitiveEvent (certificateOutput output)) +
      outcomeEventMass mass (accumulatorPrimitiveEvent (certificateOutput output)) +
      outcomeEventMass mass (mixedClawPrimitiveEvent (certificateOutput output)) := by
  classical
  let nEvent := nullifierPrimitiveEvent (certificateOutput output)
  let sEvent := singleKeyPrimitiveEvent (certificateOutput output)
  let aEvent := accumulatorPrimitiveEvent (certificateOutput output)
  let mEvent := mixedClawPrimitiveEvent (certificateOutput output)
  let allGames := fun outcome => nEvent outcome ∨ sEvent outcome ∨
    aEvent outcome ∨ mEvent outcome
  have included : ∀ outcome, sourceSpendPrimitiveGameEvent output outcome →
      allGames outcome := by
    intro outcome hit
    simpa [allGames, nEvent, sEvent, aEvent, mEvent] using
      sourceSpendPrimitiveGameEvent_implies_one_of_four output outcome hit
  have first := eventMass_mono_of_implication mass nonnegative
    (sourceSpendPrimitiveGameEvent output) allGames included
  have inner := SmzaRp05OriginalMassLossJoin.outcome_mass_union_le_add
    mass nonnegative sEvent (fun outcome => aEvent outcome ∨ mEvent outcome)
  have tail := SmzaRp05OriginalMassLossJoin.outcome_mass_union_le_add
    mass nonnegative aEvent mEvent
  have outer := SmzaRp05OriginalMassLossJoin.outcome_mass_union_le_add
    mass nonnegative nEvent (fun outcome => sEvent outcome ∨ aEvent outcome ∨
      mEvent outcome)
  unfold allGames at first
  have inner' : outcomeEventMass mass (fun outcome =>
      sEvent outcome ∨ aEvent outcome ∨ mEvent outcome) ≤
      outcomeEventMass mass sEvent +
        outcomeEventMass mass (fun outcome => aEvent outcome ∨ mEvent outcome) :=
    inner
  have tail' : outcomeEventMass mass (fun outcome => aEvent outcome ∨ mEvent outcome) ≤
      outcomeEventMass mass aEvent + outcomeEventMass mass mEvent := tail
  linarith

/-- Explicit four induced-game hypotheses give the direct charged-pair game
event bound on the same original outcome weights. -/
theorem sourceSpendPrimitiveGameEvent_mass_le_advantages
    {Outcome : Type} [Fintype Outcome]
    (output : Outcome → Option DesignatedAuthorizationComparison)
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
    outcomeEventMass mass (sourceSpendPrimitiveGameEvent output) ≤
      epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed := by
  have cover := sourceSpendPrimitiveGameEvent_mass_le_four_game_masses
    output mass nonnegative
  linarith

theorem currentHistoryChargedFailure_mass_le_path_and_games
    {Outcome : Type} [Fintype Outcome]
    (frames : Outcome → Option CurrentRunChargedFailureFrame)
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (epsilonPath epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed : ℝ)
    (pathBound : outcomeEventMass mass
      (currentHistoryPathPrimitiveGameEvent frames) ≤ epsilonPath)
    (nullifierBound : outcomeEventMass mass
      (nullifierPrimitiveEvent
        (certificateOutput (currentHistoryFailureComparisonOutput frames))) ≤
      epsilonNullifier)
    (singleBound : outcomeEventMass mass
      (singleKeyPrimitiveEvent
        (certificateOutput (currentHistoryFailureComparisonOutput frames))) ≤
      epsilonSingle)
    (accumulatorBound : outcomeEventMass mass
      (accumulatorPrimitiveEvent
        (certificateOutput (currentHistoryFailureComparisonOutput frames))) ≤
      epsilonAccumulator)
    (mixedBound : outcomeEventMass mass
      (mixedClawPrimitiveEvent
        (certificateOutput (currentHistoryFailureComparisonOutput frames))) ≤
      epsilonMixed) :
    outcomeEventMass mass (currentHistoryChargedFailureEvent frames) ≤
      epsilonPath + epsilonNullifier + epsilonSingle + epsilonAccumulator +
        epsilonMixed := by
  have included := eventMass_mono_of_implication mass nonnegative
    (currentHistoryChargedFailureEvent frames)
    (fun outcome => currentHistoryPathPrimitiveGameEvent frames outcome ∨
      sourceSpendPrimitiveGameEvent
        (currentHistoryFailureComparisonOutput frames) outcome)
    (fun outcome => currentHistoryChargedFailureEvent_included frames outcome)
  have splitMass := SmzaRp05OriginalMassLossJoin.outcome_mass_union_le_add
    mass nonnegative (currentHistoryPathPrimitiveGameEvent frames)
    (sourceSpendPrimitiveGameEvent (currentHistoryFailureComparisonOutput frames))
  have games := sourceSpendPrimitiveGameEvent_mass_le_advantages
    (currentHistoryFailureComparisonOutput frames) mass nonnegative
    epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed
    nullifierBound singleBound accumulatorBound mixedBound
  linarith

/-- Same first-failure bound with the actual finite-ledger outcome carrier.
The caller obtains `selectedOutcome` by choosing the tuple returned by the
whole-history fold theorem; no independent comparison or failure witness is
an argument. -/
theorem currentSelectedRunOutcome_mass_le_path_and_games
    {Outcome : Type} [Fintype Outcome]
    (selectedOutcome : Outcome → CurrentSelectedRunOutcome)
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (epsilonPath epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed : ℝ)
    (pathBound : outcomeEventMass mass
      (currentHistoryPathPrimitiveGameEvent
        (currentHistoryOutcomeFrames selectedOutcome)) ≤ epsilonPath)
    (nullifierBound : outcomeEventMass mass
      (nullifierPrimitiveEvent (certificateOutput
        (currentHistoryFailureComparisonOutput
          (currentHistoryOutcomeFrames selectedOutcome)))) ≤ epsilonNullifier)
    (singleBound : outcomeEventMass mass
      (singleKeyPrimitiveEvent (certificateOutput
        (currentHistoryFailureComparisonOutput
          (currentHistoryOutcomeFrames selectedOutcome)))) ≤ epsilonSingle)
    (accumulatorBound : outcomeEventMass mass
      (accumulatorPrimitiveEvent (certificateOutput
        (currentHistoryFailureComparisonOutput
          (currentHistoryOutcomeFrames selectedOutcome)))) ≤ epsilonAccumulator)
    (mixedBound : outcomeEventMass mass
      (mixedClawPrimitiveEvent (certificateOutput
        (currentHistoryFailureComparisonOutput
          (currentHistoryOutcomeFrames selectedOutcome)))) ≤ epsilonMixed) :
    outcomeEventMass mass
      (currentHistoryChargedFailureEvent
        (currentHistoryOutcomeFrames selectedOutcome)) ≤
      epsilonPath + epsilonNullifier + epsilonSingle + epsilonAccumulator +
        epsilonMixed := by
  exact currentHistoryChargedFailure_mass_le_path_and_games
    (currentHistoryOutcomeFrames selectedOutcome) mass nonnegative
    epsilonPath epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed
    pathBound nullifierBound singleBound accumulatorBound mixedBound

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- Bound the exact first charged source-input failure returned by the public
empty-genesis executor. All comparison/path outputs and game events are
projected from that same execution result on the same original outcome
measure; complete, native, and coinbase outcomes are not counted as charged
failures. -/
theorem currentHistoryGenesis_mass_le_path_and_games
    {Outcome : Type} [Fintype Outcome]
    (blocks : Outcome → List (CurrentSelectedBlock (BaseWork := BaseWork)))
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (epsilonNoteCommitment epsilonMerkle epsilonNullifier epsilonSingle
      epsilonAccumulator epsilonMixed : ℝ)
    (noteBound : outcomeEventMass mass
      (currentHistoryGenesisPathNoteCommitmentGameEvent blocks) ≤ epsilonNoteCommitment)
    (merkleBound : outcomeEventMass mass
      (currentHistoryGenesisPathMerkleCompressionGameEvent blocks) ≤ epsilonMerkle)
    (nullifierBound : outcomeEventMass mass
      (nullifierPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocks))) ≤ epsilonNullifier)
    (singleBound : outcomeEventMass mass
      (singleKeyPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocks))) ≤ epsilonSingle)
    (accumulatorBound : outcomeEventMass mass
      (accumulatorPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocks))) ≤ epsilonAccumulator)
    (mixedBound : outcomeEventMass mass
      (mixedClawPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocks))) ≤ epsilonMixed) :
    outcomeEventMass mass (currentHistoryGenesisChargedFailureEvent blocks) ≤
      epsilonNoteCommitment + epsilonMerkle + epsilonNullifier + epsilonSingle +
        epsilonAccumulator + epsilonMixed := by
  let frames := currentHistoryGenesisOutcomeFrames blocks
  have pathBound : outcomeEventMass mass
      (currentHistoryPathPrimitiveGameEvent frames) ≤
        epsilonNoteCommitment + epsilonMerkle := by
    have split := eventMass_le_note_add_merkle mass nonnegative frames
    have noteExact : currentHistoryPathNoteCommitmentGameEvent frames =
        currentHistoryGenesisPathNoteCommitmentGameEvent blocks := rfl
    have merkleExact : currentHistoryPathMerkleCompressionGameEvent frames =
        currentHistoryGenesisPathMerkleCompressionGameEvent blocks := rfl
    rw [noteExact, merkleExact] at split
    linarith
  have total := currentHistoryChargedFailure_mass_le_path_and_games
    frames mass nonnegative (epsilonNoteCommitment + epsilonMerkle)
    epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed pathBound
    nullifierBound singleBound accumulatorBound mixedBound
  exact total

end HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryCertificateMass
