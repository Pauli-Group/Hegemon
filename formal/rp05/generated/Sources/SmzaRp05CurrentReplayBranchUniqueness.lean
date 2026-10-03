import SmzaRp05CurrentVerifierReplay
import HegemonCrypto.CmsOracleDatabaseBridge
import HegemonCrypto.DatabaseFiber

/-! # Branch uniqueness when replaying a retained read program

If the exact answers of a prior branch are already recorded in the standard
view, replaying that program has only one nonzero answer branch: the retained
branch. Matching answers are identity projectors; the first mismatching answer
is an orthogonal coordinate projector and annihilates the state.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentReplayBranchUniqueness

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.DatabaseFiber
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05CurrentVerifierReplay
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Output Phase Work Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]

private theorem decompressAt_zero (key : Key) :
    decompressAt key (0 : State Key Output Phase Work) = 0 := by
  funext basis
  have fiberZero : databaseFiberState (0 : State Key Output Phase Work)
      basis.input basis.phase basis.workspace key
      ((databaseEquiv (Output := Output) key basis.database).1) = 0 := by
    ext coordinate
    simp [databaseFiberState]
  simp [decompressAt, fiberZero]

private theorem decompressList_zero (keys : List Key) :
    decompressList keys (0 : State Key Output Phase Work) = 0 := by
  induction keys with
  | nil => rfl
  | cons key keys ih =>
      change decompressAt key (decompressList keys
        (0 : State Key Output Phase Work)) = 0
      rw [ih]
      exact decompressAt_zero key

private theorem globalDecompress_zero :
    globalDecompress (0 : State Key Output Phase Work) = 0 := by
  unfold globalDecompress
  exact decompressList_zero (Finset.univ.toList)

private theorem coordinate_projection_zero_of_known_ne
    (key : Key) (knownOutput otherOutput : Output)
    (state : State Key Output Phase Work)
    (known : KnownAt key knownOutput state)
    (different : otherOutput ≠ knownOutput) :
    coordinateEventProjection key otherOutput state = 0 := by
  funext basis
  have knownAtBasis := congrFun known basis
  unfold KnownAt coordinateEventProjection at knownAtBasis
  unfold coordinateEventProjection
  by_cases recorded : basis.database key = some knownOutput
  · simp [recorded, Ne.symm different]
  · simp [recorded] at knownAtBasis
    rw [← knownAtBasis]
    simp

private theorem physicalReadStep_known_identity
    (key : Key) (output : Output) (state : State Key Output Phase Work)
    (known : KnownAt key output (globalDecompress state)) :
    physicalReadStep key output state = state := by
  calc
    physicalReadStep key output state =
        globalDecompress (globalDecompress
          (physicalReadStep key output state)) :=
      (global_decompress_involutive _).symm
    _ = globalDecompress
          (coordinateEventProjection key output (globalDecompress state)) :=
      congrArg globalDecompress (global_decompress_physical_read_step _ _ _)
    _ = globalDecompress (globalDecompress state) := congrArg globalDecompress known
    _ = state := global_decompress_involutive _

private theorem physicalReadStep_known_conflict_zero
    (key : Key) (knownOutput otherOutput : Output)
    (state : State Key Output Phase Work)
    (known : KnownAt key knownOutput (globalDecompress state))
    (different : otherOutput ≠ knownOutput) :
    physicalReadStep key otherOutput state = 0 := by
  calc
    physicalReadStep key otherOutput state =
        globalDecompress (globalDecompress
          (physicalReadStep key otherOutput state)) :=
      (global_decompress_involutive _).symm
    _ = globalDecompress
          (coordinateEventProjection key otherOutput (globalDecompress state)) :=
      congrArg globalDecompress (global_decompress_physical_read_step _ _ _)
    _ = 0 := by
      rw [coordinate_projection_zero_of_known_ne key knownOutput otherOutput
        (globalDecompress state) known different]
      exact globalDecompress_zero

private theorem physicalRun_zero
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (program : Program Result) (branch : Branches decode program) :
    physicalRun encode decode program branch
      (0 : State Key Output Phase Work) = 0 := by
  induction program with
  | done result => cases branch; rfl
  | read raw next ih =>
      rcases branch with ⟨answer, tail⟩
      simp only [physicalRun]
      rw [show physicalReadStep (encode raw) answer
          (0 : State Key Output Phase Work) = 0 by
        unfold physicalReadStep
        rw [globalDecompress_zero]
        have projected : coordinateEventProjection (encode raw) answer
            (0 : State Key Output Phase Work) = 0 := by
          funext basis
          simp [coordinateEventProjection]
        rw [projected]
        exact globalDecompress_zero]
      exact ih (decode raw answer) tail

/-- On a pre-replay state where all answers of `expected` are already known,
every alternative branch is either the exact retained branch (and preserves
the state) or has zero physical state. No probability/renormalization or
branch-success premise is used. -/
theorem physicalRun_eq_expected_or_zero
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (program : Program Result) (expected actual : Branches decode program)
    (state : State Key Output Phase Work)
    (expectedKnown : ∀ claim,
      claim ∈ branchClaims (branchKeys encode decode program expected)
        (branchAnswers encode decode program expected) →
      KnownAt claim.1 claim.2 (globalDecompress state)) :
    actual = expected ∨
      physicalRun encode decode program actual state = 0 := by
  induction program generalizing state with
  | done result =>
      cases expected
      cases actual
      exact Or.inl rfl
  | read raw next ih =>
      rcases expected with ⟨expectedAnswer, expectedTail⟩
      rcases actual with ⟨actualAnswer, actualTail⟩
      have headKnown : KnownAt (encode raw) expectedAnswer
          (globalDecompress state) :=
        expectedKnown (encode raw, expectedAnswer)
          (by simp [branchClaims, branchKeys, branchAnswers])
      by_cases answersAgree : actualAnswer = expectedAnswer
      · subst actualAnswer
        have tailKnown : ∀ claim,
            claim ∈ branchClaims (branchKeys encode decode
              (next (decode raw expectedAnswer)) expectedTail)
              (branchAnswers encode decode
                (next (decode raw expectedAnswer)) expectedTail) →
            KnownAt claim.1 claim.2 (globalDecompress state) := by
          intro claim member
          exact expectedKnown claim
            (by simp [branchClaims, branchKeys, branchAnswers, member])
        have tailResult := ih (decode raw expectedAnswer)
          expectedTail actualTail state tailKnown
        have headIdentity := physicalReadStep_known_identity
          (encode raw) expectedAnswer state headKnown
        simp only [physicalRun]
        rw [headIdentity]
        rcases tailResult with equal | zero
        · exact Or.inl (by cases equal; rfl)
        · exact Or.inr zero
      · have headConflict := physicalReadStep_known_conflict_zero
          (encode raw) expectedAnswer actualAnswer state headKnown
          answersAgree
        simp only [physicalRun]
        rw [headConflict]
        exact Or.inr (physicalRun_zero encode decode
          (next (decode raw actualAnswer)) actualTail)

/-- Explicit matching/alternative branch form: the retained branch preserves
the whole state, and each distinct answer branch has zero state. -/
theorem physicalRun_expected_identity_other_branches_zero
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (program : Program Result) (expected : Branches decode program)
    (state : State Key Output Phase Work)
    (expectedKnown : ∀ claim,
      claim ∈ branchClaims (branchKeys encode decode program expected)
        (branchAnswers encode decode program expected) →
      KnownAt claim.1 claim.2 (globalDecompress state)) :
    physicalRun encode decode program expected state = state ∧
    ∀ actual : Branches decode program, actual ≠ expected →
      physicalRun encode decode program actual state = 0 := by
  refine ⟨physicalRun_eq_self_on_known_branch encode decode program expected
    state expectedKnown, ?_⟩
  intro actual different
  rcases physicalRun_eq_expected_or_zero encode decode program expected actual
      state expectedKnown with equal | zero
  · exact False.elim (different equal)
  · exact zero

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentReplayBranchUniqueness
