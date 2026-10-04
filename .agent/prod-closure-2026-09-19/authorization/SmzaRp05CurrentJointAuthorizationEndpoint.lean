import SmzaRp05ActualAcceptedAuthorizationEndpoint
import SmzaRp05CurrentJointAcceptedExecution
import SmzaRp05CurrentJointObserverKeys
import SmzaRp05CurrentJointObserverMass
import SmzaRp05CurrentJointRetainedProofs
import SmzaRp05CurrentJointExtractionPrograms
import SmzaRp05ExecutableProgramEquality
import SmzaRp05CurrentAcceptedOrdinaryMassBound
import SmzaRp05DesignatedWitnessReadback
import SmzaRp05CurrentFullOrRoleXViewCoverage
import SmzaRp05CurrentAdaptiveExecution
import SmzaRp05ConditionedExecution
import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05CurrentJointObserverKeys
import SmzaRp05CurrentJointExtractionPrograms

/-! The current joint authorization consumer is built on one chronological
two-transaction execution and its terminal whole-prefix replay. This module
also exports small projections of the designated comparison carrier so
downstream supply adapters do not unfold the accepted relation witness. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentJointAuthorizationEndpoint

open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointAcceptedExecution
  (sequentialUnitProgram sequentialUnitBranch sequentialUnitBranch_result
    sequentialUnitBranch_split)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointObserverMass
  (bindPrefixBranch bindPrefixBranch_sequentialUnitBranch)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointExtractionPrograms
  (actualProgram_firstTarget_eq_terminalUnitPrefixReplayObserver)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointRetainedProofs
  (terminalUnitPrefixReplayObserver)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedOrdinaryMassBound
  (actualProgram)
open HegemonCrypto.SmallWood.SmzaRp05ExecutableProgramEquality
  (castProgramBranch branchResult_cast_program)
open HegemonCrypto.SmallWood.SmzaRp05CurrentFullOrRoleXViewCoverage
  (currentAcceptedXViewFullSuccessSelector)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAdaptiveExecution (Context Work)
open HegemonCrypto.SmallWood.SmzaRp05ConditionedExecution (XKey xView)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedChallengeClaims
  (nonchallengeRawKeySet)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointObserverKeys
  (terminalWholePrefixObserver terminal_observer_key_eq_joint)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointExtractionPrograms
  (actualProgram_secondTarget_eq_joint
    actualProgram_firstTarget_eq_terminalUnitPrefixReplayObserver
    firstTarget_key_eq_terminalUnitPrefixReplayObserver secondTarget_key_eq_joint)
open HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteGroupedProgram (Key)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
  (V8PublicStatement encodePublicStatement)
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
  (parseCurrentPublicStatement?)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentJointAcceptedExecution (secondProducerAfterFirst)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.FiniteOracleDatabase (Database)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05GroupedSuffix (GroupCounter)
open scoped Classical
open HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult)
open HegemonCrypto.SmallWood.SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawDigest RawInput)

set_option autoImplicit false

variable {Output : Type}
variable {decode : RawInput → Output → RawDigest}

/-- The terminal observer branch is selected deterministically from the
actual accepted joint branch: replay the first program's recorded answers.
No proof or packed witness is supplied to this constructor. -/
def expectedTerminalPrefixObserverBranch
    (first suffix : Program Unit)
    (jointBranch : Branches decode (sequentialUnitProgram first suffix)) :
    Branches decode (sequentialUnitProgram
      (sequentialUnitProgram first suffix) first) :=
  sequentialUnitBranch decode (sequentialUnitProgram first suffix) jointBranch
    first (bindPrefixBranch decode first suffix jointBranch)

/-- On a successful chronological joint branch, the deterministically replayed
first prefix is itself successful. -/
theorem expectedTerminalPrefixObserverBranch_accepted
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    (first suffix : Program Unit)
    (jointBranch : Branches decode (sequentialUnitProgram first suffix))
    (jointAccepted : branchResult decode (sequentialUnitProgram first suffix)
      jointBranch = some ()) :
    branchResult decode (sequentialUnitProgram
      (sequentialUnitProgram first suffix) first)
      (expectedTerminalPrefixObserverBranch first suffix jointBranch) =
        some () := by
  obtain ⟨firstBranch, suffixBranch, firstAccepted, _suffixAccepted, split⟩ :=
    sequentialUnitBranch_split decode first suffix jointBranch jointAccepted
  have projected : bindPrefixBranch decode first suffix jointBranch = firstBranch := by
    rw [split]
    exact bindPrefixBranch_sequentialUnitBranch decode first suffix
      firstBranch suffixBranch
  rw [expectedTerminalPrefixObserverBranch, projected,
    sequentialUnitBranch_result]
  simp [jointAccepted, firstAccepted]

open SmzaRp05CurrentJointAcceptedExecution
  (firstAcceptedVerifierProgram secondAcceptedVerifierProgram
    secondProducerAfterFirst twoAcceptedProgram_eq_sequentialUnitProgram)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)

/-- The exact left-endpoint program identity used to cast the designated
observer branch into the selector's dependent `Branches` index. -/
theorem sequentialObserver_eq_currentFirstTarget
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    sequentialUnitProgram
        (sequentialUnitProgram
          (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
          (producer₂.bind fun wire₂ => verifierProgram ns₂ currentDsl
            statement₂ pending₂ nonce₂ wire₂))
        (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁) =
      actualProgram
        ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
        ns₁ statement₁ pending₁ nonce₁ := by
  calc
    sequentialUnitProgram
        (sequentialUnitProgram
          (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
          (producer₂.bind fun wire₂ => verifierProgram ns₂ currentDsl
            statement₂ pending₂ nonce₂ wire₂))
        (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁) =
      terminalUnitPrefixReplayObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂ := by
          unfold terminalUnitPrefixReplayObserver firstAcceptedVerifierProgram
          rw [twoAcceptedProgram_eq_sequentialUnitProgram producer₁ producer₂
            ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂]
          rfl
    _ = actualProgram
        ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
        ns₁ statement₁ pending₁ nonce₁ :=
      (actualProgram_firstTarget_eq_terminalUnitPrefixReplayObserver producer₁
        producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂).symm

/-- For each accepted original joint branch, the terminal selector branch is
not chosen independently: it is the sequential branch whose appended prefix
is exactly the first prefix answers retained by that joint branch. -/
noncomputable def currentJointExpectedObserverBranch
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (jointBranch : Branches groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂)) :
    Branches groupedDecode
      (actualProgram
        ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
        ns₁ statement₁ pending₁ nonce₁) := by
  let first := firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁
  let suffix := producer₂.bind fun wire₂ => verifierProgram ns₂ currentDsl
    statement₂ pending₂ nonce₂ wire₂
  let seqJoint := sequentialUnitProgram first suffix
  have jointEq : secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ = seqJoint := by
    simpa only [seqJoint, first, suffix] using
      twoAcceptedProgram_eq_sequentialUnitProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  let seqBranch := castProgramBranch groupedDecode
    (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂) seqJoint jointEq jointBranch
  let observerBranch := expectedTerminalPrefixObserverBranch first suffix
    seqBranch
  exact castProgramBranch groupedDecode
    (sequentialUnitProgram seqJoint first)
    (actualProgram
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁)
    (sequentialObserver_eq_currentFirstTarget producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)
    observerBranch

/-- Expose the same deterministic observer branch in the syntax used by the
full-observer marginal. The equality is purely definitional/proof-irrelevant;
it introduces no branch or witness choice. -/
theorem currentJointExpectedObserverBranch_eq_massExpected
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (jointBranch : Branches groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂)) :
    let first := firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁
    let suffix := producer₂.bind fun wire₂ => verifierProgram ns₂ currentDsl
      statement₂ pending₂ nonce₂ wire₂
    let seqJoint := sequentialUnitProgram first suffix
    let joint := secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    let jointEq : joint = seqJoint := twoAcceptedProgram_eq_sequentialUnitProgram
      producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    let seqBranch := castProgramBranch groupedDecode joint seqJoint jointEq jointBranch
    let target := actualProgram (joint.bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁
    currentJointExpectedObserverBranch producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂ jointBranch =
    castProgramBranch groupedDecode (sequentialUnitProgram seqJoint first) target
      (sequentialObserver_eq_currentFirstTarget producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)
      (sequentialUnitBranch groupedDecode seqJoint seqBranch first
        (bindPrefixBranch groupedDecode first suffix seqBranch)) := by
  dsimp [currentJointExpectedObserverBranch, expectedTerminalPrefixObserverBranch]

/-- The deterministic terminal selector branch preserves success of the
actual original accepted joint execution. -/
theorem currentJointExpectedObserverBranch_accepted
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (jointBranch : Branches groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂))
    (jointAccepted : branchResult groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) jointBranch = some ()) :
    branchResult groupedDecode
      (actualProgram
        ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
        ns₁ statement₁ pending₁ nonce₁)
      (currentJointExpectedObserverBranch producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂ jointBranch) = some () := by
  unfold currentJointExpectedObserverBranch
  have jointEq := twoAcceptedProgram_eq_sequentialUnitProgram producer₁ producer₂
    ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  have acceptedSeq : branchResult groupedDecode
      (sequentialUnitProgram
        (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
        (producer₂.bind fun wire₂ => verifierProgram ns₂ currentDsl
          statement₂ pending₂ nonce₂ wire₂))
      (castProgramBranch groupedDecode
        (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂)
        (sequentialUnitProgram
          (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
          (producer₂.bind fun wire₂ => verifierProgram ns₂ currentDsl
            statement₂ pending₂ nonce₂ wire₂)) jointEq jointBranch) = some () := by
    simpa only [branchResult_cast_program] using jointAccepted
  have observerAccepted := expectedTerminalPrefixObserverBranch_accepted
    (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
    (producer₂.bind fun wire₂ => verifierProgram ns₂ currentDsl statement₂ pending₂
      nonce₂ wire₂)
    (castProgramBranch groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂)
      (sequentialUnitProgram
        (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
        (producer₂.bind fun wire₂ => verifierProgram ns₂ currentDsl
          statement₂ pending₂ nonce₂ wire₂)) jointEq jointBranch)
    acceptedSeq
  simpa only [branchResult_cast_program] using observerAccepted

/-- Same-key fact for the first target's actual extraction program and the
original joint chronology. It is derived only from the checked program and
finite-group support equalities. -/
private theorem currentFirstTarget_key_eq_joint
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    Key (actualProgram
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁) =
    Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂) := by
  calc
    Key (actualProgram
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁) =
        Key (terminalUnitPrefixReplayObserver producer₁ producer₂ ns₁ ns₂
          statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) :=
      firstTarget_key_eq_terminalUnitPrefixReplayObserver producer₁ producer₂
        ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    _ = Key (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) := rfl
    _ = Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) :=
      (terminal_observer_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).symm

/-- On one original chronological branch and one final database, the output
map exists only if both actual current full-success selectors hold: the first
selector uses the deterministic terminal replay branch, the second uses the
actual joint branch. Their views are the same database under the checked key
equality. Input slots are the caller's actual attempted active positions. -/
noncomputable def currentJointSelectorComparisonOutput
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (fallback₁ fallback₂ : RawDigest)
    (typed₁ typed₂ : V8PublicStatement)
    (parsed₁ : parseCurrentPublicStatement? statement₁ = some typed₁)
    (parsed₂ : parseCurrentPublicStatement? statement₂ = some typed₂)
    (fuel₁ fuel₂ : Nat)
    (ctx₁ : Context (Key := Key (actualProgram
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁)) (Counter := GroupCounter)
      (BaseWork := BaseWork))
    (ctx₂ : Context (Key := Key (actualProgram
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂)) (Counter := GroupCounter)
      (BaseWork := BaseWork))
    (input₁ input₂ : Fin 2)
    (active₁ : (encodePublicStatement typed₁).getD input₁.val 0 = 1)
    (active₂ : (encodePublicStatement typed₂).getD input₂.val 0 = 1) :
    (Branches groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) ×
      Basis (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
        (VectorOutput GroupCounter) (VectorOutput GroupCounter)
        (Work (Counter := GroupCounter) (BaseWork := BaseWork))) →
      Option DesignatedAuthorizationComparison := by
  classical
  intro outcome
  let joint := secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  let firstTarget := actualProgram
    (joint.bind fun _ => producer₁) ns₁ statement₁ pending₁ nonce₁
  let secondTarget := actualProgram
    (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
    ns₂ statement₂ pending₂ nonce₂
  let jointBranch := outcome.1
  let database := outcome.2.database
  let firstDatabase : Database (Key firstTarget) (VectorOutput GroupCounter) :=
    cast (congrArg (fun key => Database key (VectorOutput GroupCounter))
      (currentFirstTarget_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).symm) database
  let secondKeyEq : Key secondTarget = Key joint :=
    secondTarget_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
      pending₁ pending₂ nonce₁ nonce₂
  let secondDatabase : Database (Key secondTarget) (VectorOutput GroupCounter) :=
    cast (congrArg (fun key => Database key (VectorOutput GroupCounter))
      secondKeyEq.symm) database
  let firstView := xView (nonchallengeRawKeySet ctx₁) firstDatabase
  let secondView := xView (nonchallengeRawKeySet ctx₂) secondDatabase
  let firstBranch := currentJointExpectedObserverBranch producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ jointBranch
  let secondBranch := castProgramBranch groupedDecode joint secondTarget
    (actualProgram_secondTarget_eq_joint producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂).symm jointBranch
  exact if selected₁ : currentAcceptedXViewFullSuccessSelector
      (joint.bind fun _ => producer₁) ns₁ statement₁ pending₁ nonce₁ fallback₁
      typed₁ fuel₁ ctx₁ firstBranch firstView then
    if selected₂ : currentAcceptedXViewFullSuccessSelector
        (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
        ns₂ statement₂ pending₂ nonce₂ fallback₂ typed₂ fuel₂ ctx₂ secondBranch
        secondView then
      some (comparisonOfCurrentFullSuccessSelectors
        (joint.bind fun _ => producer₁)
        (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
        ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
        fallback₁ fallback₂ typed₁ typed₂ parsed₁ parsed₂ fuel₁ fuel₂ ctx₁ ctx₂
        firstBranch secondBranch firstView secondView selected₁ selected₂
        input₁ input₂ active₁ active₂)
    else none
  else none

/-- First-target extraction failure event on the original joint branch/basis
outcome. The observer branch is computed from that same branch, and the
predicate reads its final database from that same CMS basis. -/
def currentJointFirstSelectorFailure
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (fallback₁ : RawDigest) (typed₁ : V8PublicStatement) (fuel₁ : Nat)
    (ctx₁ : Context (Key := Key (actualProgram
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁)) (Counter := GroupCounter)
      (BaseWork := BaseWork))
    (outcome : Branches groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) ×
      Basis (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
        (VectorOutput GroupCounter) (VectorOutput GroupCounter)
        (Work (Counter := GroupCounter) (BaseWork := BaseWork))) : Prop :=
  branchResult groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) outcome.1 = some () ∧
    ¬ currentAcceptedXViewFullSuccessSelector
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁ fallback₁ typed₁ fuel₁ ctx₁
      (currentJointExpectedObserverBranch producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂ outcome.1)
      (xView (nonchallengeRawKeySet ctx₁)
        (cast (congrArg (fun key => Database key (VectorOutput GroupCounter))
          (currentFirstTarget_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
            statement₂ pending₁ pending₂ nonce₁ nonce₂).symm) outcome.2.database))

/-- Second-target extraction failure event on exactly the same original joint
branch/basis outcome used for the first-target loss. -/
def currentJointSecondSelectorFailure
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (fallback₂ : RawDigest) (typed₂ : V8PublicStatement) (fuel₂ : Nat)
    (ctx₂ : Context (Key := Key (actualProgram
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂)) (Counter := GroupCounter)
      (BaseWork := BaseWork))
    (outcome : Branches groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) ×
      Basis (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
        (VectorOutput GroupCounter) (VectorOutput GroupCounter)
        (Work (Counter := GroupCounter) (BaseWork := BaseWork))) : Prop :=
  branchResult groupedDecode
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) outcome.1 = some () ∧
    ¬ currentAcceptedXViewFullSuccessSelector
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂ fallback₂ typed₂ fuel₂ ctx₂
      (castProgramBranch groupedDecode
        (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂)
        (actualProgram
          (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
          ns₂ statement₂ pending₂ nonce₂)
        (actualProgram_secondTarget_eq_joint producer₁ producer₂ ns₁ ns₂
          statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂).symm outcome.1)
      (xView (nonchallengeRawKeySet ctx₂)
        (cast (congrArg (fun key => Database key (VectorOutput GroupCounter))
          (secondTarget_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
            statement₂ pending₁ pending₂ nonce₁ nonce₂).symm) outcome.2.database))

end HegemonCrypto.SmallWood.SmzaRp05CurrentJointAuthorizationEndpoint
