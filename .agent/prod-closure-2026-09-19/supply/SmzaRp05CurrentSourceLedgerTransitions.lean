import SmzaRp05CurrentFullOrRoleXViewCoverage
import SmzaRp05ActualAcceptedAuthorizationEndpoint
import SmzaRp05DesignatedWitnessReadback
import SmzaRp05SupplyClosureOutputHistory
import SmzaRp05CurrentAcceptedRelationWitness
import SmzaRp05CurrentPublicStatementTransport
import SmzaRp05SupplyClosureHistoricalInputs
import SmzaRp05SupplyClosureLedgerJoin
import SmzaRp05SupplyClosureCanonicalPaths
import SmzaRp05SupplyClosureInputNative
import SmzaRp05CurrentSourceLedgerPrefix
import SmzaRp05DesignatedComparisonFailureFromSourceFacts
import SmzaRp05NativeAppendReadback
import SmzaRp05CurrentAuthorizationCertificate
import SmzaRp05AcceptedPairAuthorization
import SmzaRp05AuthorizationClosureNullifier
import SmzaRp05PrimitiveCollisionGameLuna
import SmzaRp05CurrentBalanceCanonicality
import SmzaRp05SupplyClosureDistinctInputs
import SmzaRp05SupplyClosureHistoryJoin
import SmzaRp05LedgerMerkleBinding

/-! # Current designated sources for finite-history ledger transitions

This adapter starts at the actual current full-success selector.  It never
accepts a separately chosen packed witness: the packed row vector is always
`packedFromRows witness.source.data`.  The finite-ledger/history-specific
position and frame proofs are layered on this carrier by the chronological
replay consumer.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8PublicDecoder
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRelationWitness
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05CurrentTracePrefixes406
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
open HegemonCrypto.SmallWood.SmzaRp05CurrentFullOrRoleXViewCoverage
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
open HegemonCrypto.SmallWood.SmzaRp05DesignatedComparisonFailureFromSourceFacts
open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
open HegemonCrypto.SmallWood.SmzaRp05DesignatedWitnessReadback
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputHistory
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureLedgerJoin
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureCanonicalPaths
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDistinctInputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoryJoin
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
open HegemonCrypto.SmallWood.SmzaRp05NativeAppendReadback
open HegemonCrypto.SmallWood.SmzaRp05CurrentAuthorizationCertificate
open HegemonCrypto.SmallWood.SmzaRp05AcceptedPairAuthorization
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureNullifier
open HegemonCrypto.SmallWood.SmzaRp05PrimitiveCollisionGameLuna
open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
open HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open HegemonCrypto.SmallWood.PiopExtraction (FullySatisfied)
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05TracePrefixes (Payload)
open HegemonCrypto.SmallWood.V8Smz9McaDecoder (DecodedSource)
open HegemonCrypto.SmallWood.SmzaRp05CurrentResponseInputDecoder (Goldilocks)
open SmzaQ38Recovery (packedFromRows)
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)
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
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open HegemonCrypto.SmallWood.SmzaRp05PcsHashFppMiddle (gammaRows)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8SmzaOracleParser (RawDigest RawInput)
open V8Smz9CoherentMerkleGeometry (extract)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedCausalPayloads (Records)
open HegemonCrypto.SmallWood.SmzaRp04StatementRecordFilter (oneStatementFilter)
open HegemonCrypto.SmallWood.SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open HegemonCrypto.SmallWood.SmzaRp05FilteredReadback (globalLeafStatement)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false

attribute [local irreducible]
  SmzaRp05GeneratedCertificates.currentDsl
  SmzaRp05RelationRefinement.candidate
  SmzaRp05Components.program
  SmzaRp05CurrentPublicStatementTransport.rustV8SemanticPrimitives
  SmzaQ38Recovery.packedFromRows
  HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
  HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectNote
  Hegemon.Transaction.Poseidon2V8SemanticSpecification.exactV8NoteWords
  HegemonCrypto.SmallWood.SmzaRp05HistoricalTree.openingAt

noncomputable section

abbrev CurrentSourceRun :=
  HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.CurrentSourceRun

abbrev sourcePacked {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) : List Nat :=
  HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked run

abbrev CurrentNativeSnapshot :=
  HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.CurrentNativeSnapshot

abbrev CurrentSourceSpend :=
  HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.CurrentSourceSpend

def sourceSpendsOfRun {preamble : Statement} {typed : V8PublicStatement}
    (snapshot : CurrentNativeSnapshot) (run : CurrentSourceRun preamble typed)
    (admitted : publicAnchor (encodePublicStatement typed) ∈ snapshot.parent.history) :
    List CurrentSourceSpend :=
  (List.finRange 2).filterMap fun input =>
    if positive : 0 < inputSlotNative typed (sourcePacked run) input then
      some ⟨preamble, typed, run, input, positive, snapshot, admitted⟩
    else none

def sourceRunNullifiers {preamble : Statement} {typed : V8PublicStatement}
    (_run : CurrentSourceRun preamble typed) : List Digest :=
  (List.finRange 2).filterMap fun input =>
    if (encodePublicStatement typed).getD input.val 0 = 1 then
      some (publicNullifier (encodePublicStatement typed) input)
    else none

def sourceNullifiersFresh (spent : List Digest) {preamble : Statement}
    {typed : V8PublicStatement} (run : CurrentSourceRun preamble typed) : Bool :=
  (sourceRunNullifiers run).Nodup &&
    (sourceRunNullifiers run).all (fun value => spent.contains value = false)

abbrev CurrentSourceSpend.position (spend : CurrentSourceSpend) : Nat :=
  projectPosition (sourcePacked spend.run) spend.input.val

abbrev CurrentSourceSpend.nullifier (spend : CurrentSourceSpend) : Digest :=
  publicNullifier (encodePublicStatement spend.typed) spend.input

theorem CurrentSourceSpend.position_eq (spend : CurrentSourceSpend) :
    spend.position = projectPosition (sourcePacked spend.run) spend.input.val := by
  rfl

theorem source_run_accepted {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) :
    CanonicalPublicStatement rustV8SemanticPrimitives typed ∧
      SmzaRp05Components.program.AcceptsPacked (encodePublicStatement typed)
        (sourcePacked run) := by
  simpa only [sourcePacked,
    HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked] using
    current_full_rows_yield_typed_accepted_witness
    preamble typed run.parsed run.source.data run.fullySatisfied

/-- A history record is made from the very decoder output in the run carrier. -/
def sourceOutputRecord {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) : AcceptedOutputRecord :=
  (encodePublicStatement typed, sourcePacked run)

/-- Positive native input bindings are resolved against the exact snapshot
which admitted the source statement.  A mismatch is returned as a concrete
canonical path collision; nothing is silently treated as an absent note. -/
def CurrentInputPathCollision
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed)
    (snapshot : CurrentNativeSnapshot) (input : Fin 2) : Prop :=
  ∃ count, count ≤ snapshot.openings.length ∧
    ∃ path, PathAt (fromLog merkleDepth 0 (snapshot.openings.take count))
      (projectPosition (sourcePacked run) input.val)
      (openingAt (snapshot.openings.take count)
        (projectPosition (sourcePacked run) input.val)) path ∧
    Nonempty (CanonicalRp05PathCollision
      (exactV8NoteWords (projectNote (sourcePacked run) (noteCall input)))
      (exactV8NoteWords (openingAt (snapshot.openings.take count)
        (projectPosition (sourcePacked run) input.val)))
      (inputPath typed (sourcePacked run) input) path)

theorem positive_input_snapshot_binding_or_collision
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed)
    (snapshot : CurrentNativeSnapshot)
    (admitted : publicAnchor (encodePublicStatement typed) ∈ snapshot.parent.history)
    (input : Fin 2)
    (positive : 0 < inputSlotNative typed (sourcePacked run) input) :
    (projectPosition (sourcePacked run) input.val < snapshot.openings.length ∧
      exactV8NoteWords (projectNote (sourcePacked run) (noteCall input)) =
        exactV8NoteWords (openingAt snapshot.openings
          (projectPosition (sourcePacked run) input.val))) ∨
      CurrentInputPathCollision run snapshot input := by
  obtain ⟨count, countBound, anchor⟩ := replay_anchor_has_opening_prefix
    snapshot.openings snapshot.replay (publicAnchor (encodePublicStatement typed)) admitted
  have canonical := (source_run_accepted run).1
  have accepted := (source_run_accepted run).2
  have active : (encodePublicStatement typed).getD input.val 0 = 1 := by
    rw [SmzaRp05CurrentBalanceCanonicality.encoded_input_flag_for
      typed canonical input.isLt]
    exact positive_input_slot_active typed (sourcePacked run) input positive
  rcases accepted_at_history_words_or_collision accepted typed input active
      (snapshot.openings.take count)
      (fun opening member => snapshot.canonical opening (List.mem_of_mem_take member))
      anchor with equal | collision
  · have created := positive_historical_input_is_created typed (sourcePacked run)
      input snapshot.openings count positive equal
    have takeLength : (snapshot.openings.take count).length ≤ snapshot.openings.length := by
      simp only [List.length_take]
      exact Nat.min_le_right _ _
    have fullEqual : exactV8NoteWords (projectNote (sourcePacked run) (noteCall input)) =
        exactV8NoteWords (openingAt snapshot.openings
          (projectPosition (sourcePacked run) input.val)) := by
      rw [← opening_at_prefix snapshot.openings count
        (projectPosition (sourcePacked run) input.val) created.1]
      exact equal
    exact Or.inl ⟨lt_of_lt_of_le created.1 takeLength, fullEqual⟩
  · exact Or.inr ⟨count, countBound, collision⟩

/-- Active public nullifiers from one actual designated source run, in source
slot order. -/
theorem positive_source_nullifier_mem
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2)
    (positive : 0 < inputSlotNative typed (sourcePacked run) input) :
    publicNullifier (encodePublicStatement typed) input ∈ sourceRunNullifiers run := by
  have active : (encodePublicStatement typed).getD input.val 0 = 1 := by
    rw [SmzaRp05CurrentBalanceCanonicality.encoded_input_flag_for
      typed (source_run_accepted run).1 input.isLt]
    exact positive_input_slot_active typed (sourcePacked run) input positive
  unfold sourceRunNullifiers
  apply List.mem_filterMap.mpr
  refine ⟨input, by simp, ?_⟩
  have active' : (encodePublicStatement typed)[input.val]?.getD 0 = 1 := by
    simpa [List.getD_eq_getElem?_getD] using active
  simp [active']

theorem source_spend_nullifier_mem
    {preamble : Statement} {typed : V8PublicStatement}
    (snapshot : CurrentNativeSnapshot) (run : CurrentSourceRun preamble typed)
    (admitted : publicAnchor (encodePublicStatement typed) ∈ snapshot.parent.history)
    (spend : CurrentSourceSpend)
    (member : spend ∈ sourceSpendsOfRun snapshot run admitted) :
    spend.nullifier ∈ sourceRunNullifiers run := by
  simp only [sourceSpendsOfRun] at member
  rcases List.mem_filterMap.mp member with ⟨input, _inputMember, produced⟩
  by_cases positive : 0 < inputSlotNative typed (sourcePacked run) input
  · simp only [dif_pos positive, Option.some.injEq] at produced
    have producedNullifier := congrArg CurrentSourceSpend.nullifier produced
    have nullifierEq : spend.nullifier =
        publicNullifier (encodePublicStatement typed) input := by
      simpa only [CurrentSourceSpend.nullifier] using producedNullifier.symm
    rw [nullifierEq]
    exact positive_source_nullifier_mem run input positive
  · simp only [dif_neg positive] at produced
    cases produced

theorem positive_source_nullifier_absent
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (spent : List Digest)
    (fresh : sourceNullifiersFresh spent run = true)
    (input : Fin 2)
    (positive : 0 < inputSlotNative typed (sourcePacked run) input) :
    publicNullifier (encodePublicStatement typed) input ∉ spent := by
  simp only [sourceNullifiersFresh, Bool.and_eq_true] at fresh
  have absentDecide : decide
      (spent.contains (publicNullifier (encodePublicStatement typed) input) = false) = true :=
    (List.all_eq_true.mp fresh.2) _ (positive_source_nullifier_mem run input positive)
  have absent : spent.contains (publicNullifier (encodePublicStatement typed) input) = false :=
    of_decide_eq_true absentDecide
  intro member
  have contains : spent.contains (publicNullifier (encodePublicStatement typed) input) = true :=
    List.contains_iff_mem.mpr member
  rw [contains] at absent
  cases absent

private theorem source_positive_slot_active
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2)
    (positive : 0 < inputSlotNative typed (sourcePacked run) input) :
    (encodePublicStatement typed).getD input.val 0 = 1 := by
  simpa only [SmzaRp05CurrentBalanceCanonicality.encoded_input_flag_for
      typed (source_run_accepted run).1 input.isLt] using
    positive_input_slot_active typed (sourcePacked run) input positive

private def sourceComparison (left right : CurrentSourceSpend) :
    DesignatedAuthorizationComparison :=
  { leftPreamble := left.preamble
    leftTyped := left.typed
    leftWitness := left.run
    leftInput := left.input
    leftActive := source_positive_slot_active left.run left.input left.positive
    rightPreamble := right.preamble
    rightTyped := right.typed
    rightWitness := right.run
    rightInput := right.input
    rightActive := source_positive_slot_active right.run right.input right.positive }

/-- Public projection of the exact comparison already used by the source
ledger reduction. This exposes the same two designated run witnesses and
active inputs without selecting another pair. -/
noncomputable def currentSourceSpendComparison (left right : CurrentSourceSpend) :
    DesignatedAuthorizationComparison :=
  sourceComparison left right

def sourceSpendPrimitiveFailure
    (current old : CurrentSourceSpend) : Prop :=
  wins (toCollisionGameOutput
      (sourcePair (currentSourceSpendComparison current old).pair)) ∨
    (selectedAuthorizationGameOutput
      (certificateOfAcceptedPair
        (currentSourceSpendComparison current old).pair)).wins

/-- The charged source failure is exactly the collision/game disjunction for
the public comparison projection above; it is not a reverse inference from a
primitive win to an authorization-failure certificate. -/
theorem sourceSpendPrimitiveFailure_eq_currentSourceSpendComparison
    (current old : CurrentSourceSpend) :
    sourceSpendPrimitiveFailure current old =
      (wins (toCollisionGameOutput
        (sourcePair (currentSourceSpendComparison current old).pair)) ∨
      (selectedAuthorizationGameOutput
        (certificateOfAcceptedPair
          (currentSourceSpendComparison current old).pair)).wins) := by
  rfl

attribute [local irreducible] sourceSpendPrimitiveFailure

/- If a newly admitted positive-native source input reuses an earlier
positive-native position, the exact designated executions either expose a
path-binding collision or induce the actual authorization primitive game.
Public nullifier freshness supplies the distinguishing mismatch; there is no
private-position admission predicate. -/
set_option maxHeartbeats 1600000 in
theorem spent_source_position_collision_or_actual_game
    (current : CurrentSourceSpend)
    (snapshot : CurrentNativeSnapshot)
    (currentAdmitted : publicAnchor (encodePublicStatement current.typed) ∈
      snapshot.parent.history)
    (spent : List Digest)
    (fresh : sourceNullifiersFresh spent current.run = true)
    (prior : List CurrentSourceSpend)
    (priorPrefixes : ∀ spend ∈ prior,
      spend.snapshot.openings.IsPrefix snapshot.openings)
    (priorRegistered : ∀ spend ∈ prior, spend.nullifier ∈ spent)
    (positionMember : current.position ∈ (prior.map CurrentSourceSpend.position).toFinset) :
    CurrentInputPathCollision current.run snapshot current.input ∨
      (∃ old ∈ prior,
      CurrentInputPathCollision old.run old.snapshot old.input) ∨
      ∃ old ∈ prior, old.position = current.position ∧
        sourceSpendPrimitiveFailure current old := by
  classical
  rcases positive_input_snapshot_binding_or_collision current.run snapshot
      currentAdmitted current.input current.positive with currentBinding | currentCollision
  · obtain ⟨old, oldMember, positionEq⟩ :=
      List.mem_map.mp (List.mem_toFinset.mp positionMember)
    rcases positive_input_snapshot_binding_or_collision old.run old.snapshot
        old.admitted old.input old.positive with oldBinding | oldCollision
    · let comparison := currentSourceSpendComparison current old
      let pair := comparison.pair
      have priorPrefix := priorPrefixes old oldMember
      obtain ⟨suffix, suffixEq⟩ := priorPrefix
      have oldToCurrent : openingAt old.snapshot.openings old.position =
          openingAt snapshot.openings old.position := by
        rw [← suffixEq]
        exact opening_at_appended_prefix old.snapshot.openings suffix
          old.position oldBinding.1
      have currentInputEqual : exactV8NoteWords
          (projectNote (sourcePacked current.run) (noteCall current.input)) =
          exactV8NoteWords (openingAt snapshot.openings current.position) := by
        calc
          _ = exactV8NoteWords (openingAt snapshot.openings
              (projectPosition (sourcePacked current.run) current.input.val)) :=
            currentBinding.2
          _ = exactV8NoteWords (openingAt snapshot.openings current.position) := by
            rw [← current.position_eq]
      have priorInputEqual : exactV8NoteWords
          (projectNote (sourcePacked old.run) (noteCall old.input)) =
          exactV8NoteWords (openingAt old.snapshot.openings old.position) := by
        calc
          _ = exactV8NoteWords (openingAt old.snapshot.openings
              (projectPosition (sourcePacked old.run) old.input.val)) :=
            oldBinding.2
          _ = exactV8NoteWords (openingAt old.snapshot.openings old.position) := by
            rw [← old.position_eq]
      have sameWords : exactV8NoteWords
          (projectNote (sourcePacked current.run) (noteCall current.input)) =
        exactV8NoteWords (projectNote (sourcePacked old.run) (noteCall old.input)) := by
        calc
          _ = exactV8NoteWords (openingAt snapshot.openings current.position) :=
            currentInputEqual
          _ = exactV8NoteWords (openingAt snapshot.openings old.position) := by
            rw [← positionEq]
          _ = exactV8NoteWords (openingAt old.snapshot.openings old.position) := by
            rw [oldToCurrent]
          _ = _ := priorInputEqual.symm
      have pairCurrentPacked : pair.1.packed = sourcePacked current.run := by
        have raw : pair.1.packed = packedFromRows current.run.source.data := by
          change comparison.pair.1.packed = packedFromRows current.run.source.data
          rw [comparison_pair_left_packed,
            show comparison.leftWitness = current.run by rfl]
        simpa only [sourcePacked,
          HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked] using raw
      have pairOldPacked : pair.2.packed = sourcePacked old.run := by
        have raw : pair.2.packed = packedFromRows old.run.source.data := by
          change comparison.pair.2.packed = packedFromRows old.run.source.data
          rw [comparison_pair_right_packed,
            show comparison.rightWitness = old.run by rfl]
        simpa only [sourcePacked,
          HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked] using raw
      have pairCurrentInput : pair.1.input = current.input := by
        change comparison.pair.1.input = current.input
        rw [comparison_pair_left_input]
        rfl
      have pairOldInput : pair.2.input = old.input := by
        change comparison.pair.2.input = old.input
        rw [comparison_pair_right_input]
        rfl
      have samePairWords : exactV8NoteWords
          (projectNote pair.1.packed (noteCall pair.1.input)) =
          exactV8NoteWords (projectNote pair.2.packed (noteCall pair.2.input)) := by
        simpa only [pairCurrentPacked, pairOldPacked, pairCurrentInput,
          pairOldInput] using sameWords
      have samePairPosition : projectPosition pair.1.packed pair.1.input.val =
          projectPosition pair.2.packed pair.2.input.val := by
        rw [pairCurrentPacked, pairOldPacked, pairCurrentInput, pairOldInput]
        exact positionEq.symm
      have currentAbsent := positive_source_nullifier_absent
        current.run spent fresh current.input current.positive
      have oldRegistered := priorRegistered old oldMember
      have nullifierMismatch : current.nullifier ≠ old.nullifier := by
        intro equal
        have currentRegistered : current.nullifier ∈ spent := by
          rw [equal]
          exact oldRegistered
        exact currentAbsent currentRegistered
      have activeMismatch : activePublicNullifier pair.1 ≠ activePublicNullifier pair.2 := by
        intro vectorEq
        have publicEq : publicNullifier pair.1.publicWords pair.1.input =
            publicNullifier pair.2.publicWords pair.2.input := by
          apply List.ext_getElem (by simp [publicNullifier])
          intro limb leftBound rightBound
          have limbBound : limb < 7 := by simpa [publicNullifier] using leftBound
          simp only [publicNullifier, List.getElem_map, List.getElem_range]
          simpa [activePublicNullifier] using congrFun vectorEq ⟨limb, limbBound⟩
        have leftWords : pair.1.publicWords = encodePublicStatement current.typed := by
          rw [comparison_pair_left_public_words]
          rfl
        have leftInput : pair.1.input = current.input := pairCurrentInput
        have rightWords : pair.2.publicWords = encodePublicStatement old.typed := by
          rw [comparison_pair_right_public_words]
          rfl
        have rightInput : pair.2.input = old.input := pairOldInput
        have normalizedPublic :
            publicNullifier (encodePublicStatement current.typed) current.input =
              publicNullifier (encodePublicStatement old.typed) old.input := by
          rw [← leftWords, ← leftInput, ← rightWords, ← rightInput]
          exact publicEq
        have normalized : current.nullifier = old.nullifier := by
          simpa only [CurrentSourceSpend.nullifier,
            HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.CurrentSourceSpend.nullifier]
            using normalizedPublic
        exact nullifierMismatch normalized
      have failure : acceptedPairAuthorizationFailure pair :=
        designated_comparison_source_facts_imply_accepted_pair_failure
          comparison samePairWords samePairPosition activeMismatch
      have game := actual_designated_failure_has_primitive_win comparison failure
      exact Or.inr (Or.inr ⟨old, oldMember, positionEq, by
        simpa only [sourceSpendPrimitiveFailure, comparison, pair] using game⟩)
    · exact Or.inr (Or.inl ⟨old, oldMember, oldCollision⟩)
  · exact Or.inl currentCollision

/-- Full per-positive-slot history outcome for an actual designated input:
it binds to the exact chronological opening and is not in prior native
spends, or a concrete historical path/authorization game is returned. -/
theorem positive_input_unspent_or_actual_failure
    (current : CurrentSourceSpend)
    (snapshot : CurrentNativeSnapshot)
    (currentAdmitted : publicAnchor (encodePublicStatement current.typed) ∈
      snapshot.parent.history)
    (spent : List Digest)
    (fresh : sourceNullifiersFresh spent current.run = true)
    (prior : List CurrentSourceSpend)
    (priorPrefixes : ∀ spend ∈ prior,
      spend.snapshot.openings.IsPrefix snapshot.openings)
    (priorRegistered : ∀ spend ∈ prior, spend.nullifier ∈ spent) :
    (current.position < snapshot.openings.length ∧
      exactV8NoteWords (projectNote (sourcePacked current.run)
        (noteCall current.input)) =
        exactV8NoteWords (openingAt snapshot.openings current.position) ∧
      current.position ∉ (prior.map CurrentSourceSpend.position).toFinset) ∨
    CurrentInputPathCollision current.run snapshot current.input ∨
    (∃ old ∈ prior,
      CurrentInputPathCollision old.run old.snapshot old.input) ∨
    (∃ old ∈ prior, old.position = current.position ∧
      sourceSpendPrimitiveFailure current old) := by
  classical
  by_cases spentPosition : current.position ∈
      (prior.map CurrentSourceSpend.position).toFinset
  · rcases spent_source_position_collision_or_actual_game current snapshot
      currentAdmitted spent fresh prior priorPrefixes priorRegistered spentPosition with
      currentCollision | priorCollision | actualGame
    · exact Or.inr (Or.inl currentCollision)
    · exact Or.inr (Or.inr (Or.inl priorCollision))
    · exact Or.inr (Or.inr (Or.inr actualGame))
  · rcases positive_input_snapshot_binding_or_collision current.run snapshot
      currentAdmitted current.input current.positive with binding | collision
    · exact Or.inl ⟨binding.1, binding.2, spentPosition⟩
    · exact Or.inr (Or.inl collision)

/-- Exact finite-ledger input obligations induced by the actual designated
source and this replay prefix.  The positive position is in the prior opening
range, its opening is the source's projected note, and it has not been spent. -/
def CurrentInputLedgerBinding
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2) : Prop :=
  projectPosition (sourcePacked run) input.val < ledgerPrefix.snapshot.openings.length ∧
    exactV8NoteWords (projectNote (sourcePacked run) (noteCall input)) =
      exactV8NoteWords (openingAt ledgerPrefix.snapshot.openings
        (projectPosition (sourcePacked run) input.val)) ∧
    projectPosition (sourcePacked run) input.val ∉ ledgerPrefix.ledger.spent

/-- The alternative to a successful input binding is a named, concrete
source-history failure: current/prior path collision or an actual primitive
or authorization game win for equal-position source spends. -/
def CurrentInputChargedFailure (current : CurrentSourceSpend)
    (snapshot : CurrentNativeSnapshot) (prior : List CurrentSourceSpend) : Prop :=
  CurrentInputPathCollision current.run snapshot current.input ∨
    (∃ old ∈ prior, CurrentInputPathCollision old.run old.snapshot old.input) ∨
    (∃ old ∈ prior, old.position = current.position ∧
      sourceSpendPrimitiveFailure current old)

/-- Source-shaped public binding result used by the finite ledger constructor.
The current spend record is built here from the designated run and the exact
pre-block prefix; no separate membership, freshness, or no-reuse conclusion is
accepted from callers. -/
theorem positive_input_success_or_charged_failure
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    {preamble : Statement} {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2)
    (positive : 0 < inputSlotNative typed (sourcePacked run) input)
    (admitted : publicAnchor (encodePublicStatement typed) ∈
      ledgerPrefix.snapshot.parent.history)
    (fresh : sourceNullifiersFresh ledgerPrefix.spentNullifiers run = true) :
    CurrentInputLedgerBinding ledgerPrefix run input ∨
      CurrentInputChargedFailure
        ⟨preamble, typed, run, input, positive, ledgerPrefix.snapshot, admitted⟩
        ledgerPrefix.snapshot ledgerPrefix.priorSpends := by
  let current : CurrentSourceSpend :=
    ⟨preamble, typed, run, input, positive, ledgerPrefix.snapshot, admitted⟩
  rcases positive_input_unspent_or_actual_failure current ledgerPrefix.snapshot
      admitted ledgerPrefix.spentNullifiers fresh ledgerPrefix.priorSpends
      ledgerPrefix.priorPrefix ledgerPrefix.priorRegistered with bound | failure
  · rcases bound with ⟨positionBound, wordsEqual, positionFresh⟩
    have positionBound' :
        projectPosition (sourcePacked run) input.val < ledgerPrefix.snapshot.openings.length :=
      by simpa only [CurrentSourceSpend.position_eq] using positionBound
    have wordsEqual' : exactV8NoteWords (projectNote (sourcePacked run)
        (noteCall input)) = exactV8NoteWords (openingAt ledgerPrefix.snapshot.openings
          (projectPosition (sourcePacked run) input.val)) :=
      by simpa only [CurrentSourceSpend.position_eq] using wordsEqual
    have positionFresh' :
        projectPosition (sourcePacked run) input.val ∉
          (ledgerPrefix.priorSpends.map CurrentSourceSpend.position).toFinset :=
      by simpa only [CurrentSourceSpend.position_eq] using positionFresh
    refine Or.inl ⟨positionBound', wordsEqual', ?_⟩
    rw [ledgerPrefix.spentExact]
    exact positionFresh'
  · exact Or.inr failure

theorem source_records_accepted
    {runs : List (Σ preamble : Statement, Σ typed : V8PublicStatement,
      CurrentSourceRun preamble typed)} :
    ∀ record ∈ runs.map (fun item => sourceOutputRecord item.2.2),
      program.AcceptsPacked record.1 record.2 := by
  intro record member
  rcases List.mem_map.mp member with ⟨item, _member, equal⟩
  cases equal
  exact (source_run_accepted item.2.2).2

/-- Direct projection from the actual selector's designated successful arm to
the ordered output record.  The selector is retained as an argument, so this
does not invoke an existential choice over accepted witnesses. -/
theorem selected_source_record_accepted
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
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
    SmzaRp05Components.program.AcceptsPacked
      (sourceOutputRecord (designatedWitnessOfFullSuccessSelector producer ns statement
        pending nonce fallback typed parsed fuel ctx branch view selected)).1
      (sourceOutputRecord (designatedWitnessOfFullSuccessSelector producer ns statement
        pending nonce fallback typed parsed fuel ctx branch view selected)).2 := by
  let run := designatedWitnessOfFullSuccessSelector producer ns statement pending nonce
    fallback typed parsed fuel ctx branch view selected
  have accepted := (source_run_accepted run).2
  simpa only [sourceOutputRecord, sourcePacked, run] using accepted

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions
