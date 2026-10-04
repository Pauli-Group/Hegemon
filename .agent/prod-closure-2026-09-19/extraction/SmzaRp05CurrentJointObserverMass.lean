import SmzaRp05CurrentJointAcceptedExecution
import SmzaRp05PhysicalAcceptedReplayLite
import SmzaRp05CurrentVerifierReplay
import SmzaRp05CurrentReplayBranchUniqueness

/-! # Exact marginal of the terminal whole-prefix observer

The observer appends the first accepted verifier prefix to the single joint
unit chronology.  On an accepted original branch, its prefix answers are
already known after the joint suffix.  The matching replay branch is identity
and every alternative-answer branch is zero, so summing all observer answers
(including aborts) leaves the original branch mass unchanged.  No accepted
branch is normalized and no X-view selector stability is asserted.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentJointObserverMass

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05CurrentJointAcceptedExecution
  (sequentialUnitProgram sequentialUnitBranch_result sequentialUnitBranch_answerLog
    sequentialUnitBranch_split sequentialUnitBranch sequentialUnitBranch_physicalRun)
open SmzaRp05CurrentReplayBranchUniqueness
  (physicalRun_expected_identity_other_branches_zero)
open V8SmzaOracleParser (RawInput RawDigest)
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Output Phase Work : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]
variable (encode : RawInput → Key)
variable (decode : RawInput → Output → RawDigest)

/-- The branch type is finite because every read has a finite answer type. -/
@[reducible] noncomputable def branchesFintype
    (decode : RawInput → Output → RawDigest) {α : Type} :
    (program : Program α) → Fintype (Branches decode program)
  | .done _ => by
      dsimp [Branches]
      infer_instance
  | .read raw next => by
      letI (answer : Output) : Fintype (Branches decode
          (next (decode raw answer))) := branchesFintype decode
        (next (decode raw answer))
      dsimp [Branches]
      infer_instance

/-- The original-branch projection of a branch of `program.bind fun _ =>
suffix`.  A failed program has no suffix branch; a successful one is
projected to the unique completed prefix branch. -/
def bindPrefixBranch (decode : RawInput → Output → RawDigest) :
    (program : Program Unit) → (suffix : Program Unit) →
    Branches decode (program.bind fun _ => suffix) → Branches decode program
  | .done none, _, _ => PUnit.unit
  | .done (some ()), _, _ => PUnit.unit
  | .read raw next, suffix, ⟨answer, tail⟩ =>
      ⟨answer, bindPrefixBranch decode (next (decode raw answer)) suffix tail⟩

/-- The prefix projection recovers its first component on branches generated
by the accepted sequential-branch constructor. -/
theorem bindPrefixBranch_sequentialUnitBranch
    (first suffix : Program Unit)
    (firstBranch : Branches decode first)
    (suffixBranch : Branches decode suffix) :
    bindPrefixBranch decode first suffix
      (sequentialUnitBranch decode first firstBranch suffix suffixBranch) =
      firstBranch := by
  induction first with
  | done result => cases result <;> cases firstBranch <;> rfl
  | read raw next ih =>
      rcases firstBranch with ⟨answer, tail⟩
      simp only [sequentialUnitBranch, bindPrefixBranch]
      exact congrArg (fun branch => Sigma.mk answer branch)
        (ih (decode raw answer) tail)

/-- For one fixed incoming state, a replay whose exact branch claims are
already KnownAt has exactly the original event mass after summing every
answer branch.  The branch family includes successful and aborting answers. -/
theorem replay_branch_sum_eq_state_mass
    {α : Type} (program : Program α)
    (expected : Branches decode program)
    (state : State Key Output Phase Work)
    (mass : State Key Output Phase Work → ℝ)
    (massZero : mass 0 = 0)
    (expectedKnown : ∀ claim,
      claim ∈ branchClaims (branchKeys encode decode program expected)
        (branchAnswers encode decode program expected) →
      KnownAt claim.1 claim.2 (globalDecompress state)) :
    (letI := branchesFintype decode program
      ∑ actual : Branches decode program,
        mass (physicalRun encode decode program actual state)) = mass state := by
  classical
  letI := branchesFintype decode program
  have oneOrZero := physicalRun_expected_identity_other_branches_zero
    encode decode program expected state expectedKnown
  rw [Finset.sum_eq_single expected]
  · rw [oneOrZero.1]
  · intro actual _ different
    rw [oneOrZero.2 actual different]
    exact massZero
  · intro notMem
    exact False.elim (notMem (Finset.mem_univ _))

/-- Branch factorization for an actual unit bind.  The event may depend on the
original chronology branch, while the state is the terminal state on that
branch.  Only an accepted prefix has continuation branches; those continuation
answers are summed without conditioning or renormalization. -/
theorem bind_replay_branch_marginal
    (program suffix : Program Unit)
    (state : State Key Output Phase Work)
    (mass : (branch : Branches decode program) →
      State Key Output Phase Work → ℝ)
    (massZero : ∀ branch, mass branch 0 = 0)
    (expected : ∀ _branch : Branches decode program, Branches decode suffix)
    (expectedKnown : ∀ branch,
      branchResult decode program branch = some () →
      ∀ claim,
        claim ∈ branchClaims (branchKeys encode decode suffix (expected branch))
          (branchAnswers encode decode suffix (expected branch)) →
        KnownAt claim.1 claim.2
          (globalDecompress (physicalRun encode decode program branch state))) :
    (letI := branchesFintype decode (program.bind fun _ => suffix)
      ∑ observerBranch : Branches decode (program.bind fun _ => suffix),
        mass (bindPrefixBranch decode program suffix observerBranch)
          (physicalRun encode decode (program.bind fun _ => suffix)
            observerBranch state)) =
    (letI := branchesFintype decode program
      ∑ branch : Branches decode program,
        mass branch (physicalRun encode decode program branch state)) := by
  classical
  induction program generalizing state with
  | done result =>
      cases result with
      | none =>
          letI := branchesFintype decode (α := Unit) (Program.done none)
          change (∑ branch : PUnit, mass PUnit.unit state) =
            ∑ branch : PUnit, mass branch state
          simp
      | some value =>
          cases value
          letI := branchesFintype decode (α := Unit) (Program.done (some ()))
          letI := branchesFintype decode suffix
          change
            (∑ actual : Branches decode suffix,
              mass PUnit.unit (physicalRun encode decode suffix actual state)) =
              ∑ pr : PUnit, mass pr state
          rw [show (∑ pr : PUnit, mass pr state) = mass PUnit.unit state by
            simp]
          exact replay_branch_sum_eq_state_mass encode decode suffix
            (expected PUnit.unit) state (mass PUnit.unit) (massZero PUnit.unit)
            (expectedKnown PUnit.unit rfl)
  | read raw next ih =>
      letI := branchesFintype decode (Program.read raw next)
      letI (answer : Output) : Fintype (Branches decode
          (next (decode raw answer))) := branchesFintype decode
        (next (decode raw answer))
      letI (answer : Output) : Fintype
          (Branches decode ((next (decode raw answer)).bind fun _ => suffix)) :=
        branchesFintype decode ((next (decode raw answer)).bind fun _ => suffix)
      letI := branchesFintype decode
        (Program.read raw fun digest => (next digest).bind fun _ => suffix)
      change
        (∑ observerBranch : (answer : Output) ×
            Branches decode ((next (decode raw answer)).bind fun _ => suffix),
          mass (show Branches decode (Program.read raw next) from
            ⟨observerBranch.1,
              bindPrefixBranch decode (next (decode raw observerBranch.1)) suffix
                observerBranch.2⟩)
            (physicalRun encode decode
              ((next (decode raw observerBranch.1)).bind fun _ => suffix)
              observerBranch.2 (physicalReadStep (encode raw) observerBranch.1 state))) =
        (∑ branch : (answer : Output) × Branches decode
            (next (decode raw answer)),
          mass (show Branches decode (Program.read raw next) from
            ⟨branch.1, branch.2⟩)
            (physicalRun encode decode (next (decode raw branch.1)) branch.2
              (physicalReadStep (encode raw) branch.1 state)))
      rw [Fintype.sum_sigma, Fintype.sum_sigma]
      apply Finset.sum_congr rfl
      intro answer _
      have knownTail : ∀ branch,
          branchResult decode (next (decode raw answer)) branch = some () →
          ∀ claim,
            claim ∈ branchClaims (branchKeys encode decode suffix
              (expected ⟨answer, branch⟩))
                (branchAnswers encode decode suffix (expected ⟨answer, branch⟩)) →
            KnownAt claim.1 claim.2
              (globalDecompress (physicalRun encode decode
                (next (decode raw answer)) branch
                (physicalReadStep (encode raw) answer state))) := by
        intro branch accepted claim member
        exact expectedKnown ⟨answer, branch⟩
          (by simpa only [branchResult] using accepted) claim member
      simpa only [Program.bind, bindPrefixBranch, physicalRun] using
        ih (decode raw answer) (physicalReadStep (encode raw) answer state)
          (fun branch => mass ⟨answer, branch⟩)
          (fun branch => massZero ⟨answer, branch⟩)
          (fun branch => expected ⟨answer, branch⟩) knownTail

/-- Every branch of an accepted prefix followed by a suffix has a suffix
branch whose sequential constructor is that full branch. -/
theorem bindSuffixBranch_exists
    (program suffix : Program Unit)
    (observerBranch : Branches decode (program.bind fun _ => suffix))
    (accepted : branchResult decode program
      (bindPrefixBranch decode program suffix observerBranch) = some ()) :
    ∃ suffixBranch : Branches decode suffix,
      observerBranch = sequentialUnitBranch decode program
        (bindPrefixBranch decode program suffix observerBranch) suffix suffixBranch := by
  induction program with
  | done result =>
      cases result with
      | none => simp [branchResult] at accepted
      | some value =>
          cases value
          exact ⟨observerBranch, rfl⟩
  | read raw next ih =>
      rcases observerBranch with ⟨answer, tail⟩
      have tailAccepted : branchResult decode (next (decode raw answer))
          (bindPrefixBranch decode (next (decode raw answer)) suffix tail) =
            some () := by
        simpa only [Program.bind, bindPrefixBranch, branchResult] using accepted
      obtain ⟨suffixTail, tailEq⟩ := ih (decode raw answer) tail tailAccepted
      refine ⟨suffixTail, ?_⟩
      exact congrArg (fun branch => Sigma.mk answer branch) tailEq

/-- Full observer-branch marginal.  A callback may depend on the actual
terminal observer branch, not merely the original prefix branch.  Accepted
prefixes replay their supplied expected suffix branch: every different
observer suffix is zero.  An aborting original prefix contributes zero. -/
theorem bind_observer_branch_mass_eq_expected
    (program suffix : Program Unit)
    (state : State Key Output Phase Work)
    (mass : Branches decode (program.bind fun _ => suffix) →
      State Key Output Phase Work → ℝ)
    (massZero : ∀ observerBranch, mass observerBranch 0 = 0)
    (expected : ∀ _branch : Branches decode program, Branches decode suffix)
    (expectedKnown : ∀ branch,
      (accepted : branchResult decode program branch = some ()) →
      ∀ claim,
        claim ∈ branchClaims (branchKeys encode decode suffix (expected branch))
          (branchAnswers encode decode suffix (expected branch)) →
        KnownAt claim.1 claim.2
          (globalDecompress (physicalRun encode decode program branch state))) :
    (letI := branchesFintype decode (program.bind fun _ => suffix)
      ∑ observerBranch : Branches decode (program.bind fun _ => suffix),
        if branchResult decode program
            (bindPrefixBranch decode program suffix observerBranch) = some ()
        then mass observerBranch
          (physicalRun encode decode (program.bind fun _ => suffix)
            observerBranch state)
        else 0) =
    (letI := branchesFintype decode program
      ∑ branch : Branches decode program,
        if branchResult decode program branch = some () then
          mass (sequentialUnitBranch decode program branch suffix (expected branch))
            (physicalRun encode decode program branch state)
        else 0) := by
  classical
  let prefixMass : (branch : Branches decode program) →
      State Key Output Phase Work → ℝ := fun branch current =>
    if branchResult decode program branch = some () then
      mass (sequentialUnitBranch decode program branch suffix (expected branch)) current
    else 0
  have prefixMassZero : ∀ branch, prefixMass branch 0 = 0 := by
    intro branch
    by_cases accepted : branchResult decode program branch = some ()
    · simp [prefixMass, accepted, massZero]
    · simp [prefixMass, accepted]
  have marginal := bind_replay_branch_marginal encode decode program suffix
    state prefixMass prefixMassZero expected expectedKnown
  calc
    _ = (letI := branchesFintype decode (program.bind fun _ => suffix)
        ∑ observerBranch : Branches decode (program.bind fun _ => suffix),
          prefixMass (bindPrefixBranch decode program suffix observerBranch)
            (physicalRun encode decode (program.bind fun _ => suffix)
              observerBranch state)) := by
      apply Finset.sum_congr rfl
      intro observerBranch _
      let prefixBranchValue := bindPrefixBranch decode program suffix observerBranch
      by_cases prefixAccepted : branchResult decode program prefixBranchValue = some ()
      · obtain ⟨suffixBranch, observerEq⟩ :=
          bindSuffixBranch_exists decode program suffix observerBranch prefixAccepted
        have physicalEq := sequentialUnitBranch_physicalRun decode encode
          program suffix prefixBranchValue suffixBranch prefixAccepted state
        have observerEqBind : observerBranch =
            (sequentialUnitBranch decode program prefixBranchValue suffix suffixBranch :
              Branches decode (program.bind fun _ => suffix)) := by
          simpa only [sequentialUnitProgram] using observerEq
        have prefixEqBind : bindPrefixBranch decode program suffix
            (sequentialUnitBranch decode program prefixBranchValue suffix suffixBranch :
              Branches decode (program.bind fun _ => suffix)) = prefixBranchValue := by
          simpa only [sequentialUnitProgram] using
            bindPrefixBranch_sequentialUnitBranch decode program suffix
              prefixBranchValue suffixBranch
        have physicalEqBind : physicalRun encode decode
            (program.bind fun _ => suffix)
              (sequentialUnitBranch decode program prefixBranchValue suffix suffixBranch :
                Branches decode (program.bind fun _ => suffix)) state =
            physicalRun encode decode suffix suffixBranch
              (physicalRun encode decode program prefixBranchValue state) := by
          simpa only [sequentialUnitProgram] using physicalEq
        have replay := physicalRun_expected_identity_other_branches_zero
          encode decode suffix (expected prefixBranchValue)
          (physicalRun encode decode program prefixBranchValue state)
          (expectedKnown prefixBranchValue prefixAccepted)
        rcases replay with ⟨expectedIdentity, otherZero⟩
        by_cases suffixEq : suffixBranch = expected prefixBranchValue
        · subst suffixBranch
          rw [observerEqBind, prefixEqBind, physicalEqBind, expectedIdentity]
        · have suffixZero := otherZero suffixBranch suffixEq
          rw [observerEqBind, prefixEqBind, physicalEqBind, suffixZero]
          simp [prefixMass, prefixBranchValue, prefixAccepted, massZero]
      · simp [prefixMass, prefixBranchValue, prefixAccepted]
    _ = (letI := branchesFintype decode program
        ∑ branch : Branches decode program,
          prefixMass branch (physicalRun encode decode program branch state)) :=
        marginal
    _ = (letI := branchesFintype decode program
        ∑ branch : Branches decode program,
          if branchResult decode program branch = some () then
            mass (sequentialUnitBranch decode program branch suffix (expected branch))
              (physicalRun encode decode program branch state)
          else 0) := by
      apply Finset.sum_congr rfl
      intro branch _
      rfl

/-- The first stage's retained answers are known after the actual sequential
joint execution. This derives the replay premise from the same accepted
joint branch, rather than asking a consumer to provide a readback premise. -/
theorem sequential_first_prefix_expectedKnown
    (first suffix : Program Unit)
    (state : State Key Output Phase Work)
    (branch : Branches decode (sequentialUnitProgram first suffix))
    (accepted : branchResult decode (sequentialUnitProgram first suffix) branch = some ())
    (claim : Key × Output)
    (member : claim ∈ branchClaims
      (branchKeys encode decode first
        (bindPrefixBranch decode first suffix branch))
      (branchAnswers encode decode first
        (bindPrefixBranch decode first suffix branch))) :
    KnownAt claim.1 claim.2
      (globalDecompress (physicalRun encode decode
        (sequentialUnitProgram first suffix) branch state)) := by
  obtain ⟨firstBranch, suffixBranch, firstAccepted, _, branchEq⟩ :=
    sequentialUnitBranch_split decode first suffix branch accepted
  have prefixEq : bindPrefixBranch decode first suffix branch = firstBranch := by
    rw [branchEq]
    exact bindPrefixBranch_sequentialUnitBranch decode first suffix
      firstBranch suffixBranch
  rw [prefixEq] at member
  have mapped := branch_claims_eq_answer_log encode decode first firstBranch
  rw [mapped] at member
  rcases List.mem_map.mp member with ⟨call, callMember, claimEq⟩
  rcases call with ⟨raw, answer⟩
  have jointCall : (raw, answer) ∈
      answerLog decode (sequentialUnitProgram first suffix) branch := by
    rw [branchEq, sequentialUnitBranch_answerLog decode first suffix
      firstBranch suffixBranch firstAccepted]
    exact List.mem_append.mpr (Or.inl callMember)
  have jointClaim : (encode raw, answer) ∈
      branchClaims
        (branchKeys encode decode (sequentialUnitProgram first suffix) branch)
        (branchAnswers encode decode (sequentialUnitProgram first suffix) branch) := by
    rw [branch_claims_eq_answer_log]
    exact List.mem_map.mpr ⟨(raw, answer), jointCall, rfl⟩
  have known := branch_claim_known_at_repeated
    (branchKeys encode decode (sequentialUnitProgram first suffix) branch)
    (branchAnswers encode decode (sequentialUnitProgram first suffix) branch)
    (globalDecompress state) (encode raw, answer) jointClaim
  have knownFinal : KnownAt (encode raw) answer
      (globalDecompress (physicalRun encode decode
        (sequentialUnitProgram first suffix) branch state)) := by
    rw [global_decompress_physical_run_eq_retainedTrace]
    exact known
  cases claimEq
  exact knownFinal

/-- Concrete accepted-joint marginal for any full-observer branch event.
The observer's selector can depend on its actual terminal branch; replay
uniqueness transports it to the exact first-prefix branch on the original
joint terminal state. -/
theorem sequential_first_prefix_full_observer_mass_eq_joint_mass
    (first suffix : Program Unit)
    (state : State Key Output Phase Work)
    (mass : Branches decode
        ((sequentialUnitProgram first suffix).bind fun _ => first) →
      State Key Output Phase Work → ℝ)
    (massZero : ∀ observerBranch, mass observerBranch 0 = 0) :
    (letI := branchesFintype decode
      ((sequentialUnitProgram first suffix).bind fun _ => first)
      ∑ observerBranch : Branches decode
          ((sequentialUnitProgram first suffix).bind fun _ => first),
        if branchResult decode (sequentialUnitProgram first suffix)
            (bindPrefixBranch decode (sequentialUnitProgram first suffix) first
              observerBranch) = some () then
          mass observerBranch
            (physicalRun encode decode
              ((sequentialUnitProgram first suffix).bind fun _ => first)
              observerBranch state)
        else 0) =
    (letI := branchesFintype decode (sequentialUnitProgram first suffix)
      ∑ branch : Branches decode (sequentialUnitProgram first suffix),
        if branchResult decode (sequentialUnitProgram first suffix)
            branch = some () then
          mass (sequentialUnitBranch decode (sequentialUnitProgram first suffix)
            branch first (bindPrefixBranch decode first suffix branch))
            (physicalRun encode decode
              (sequentialUnitProgram first suffix) branch state)
        else 0) := by
  apply bind_observer_branch_mass_eq_expected encode decode
    (sequentialUnitProgram first suffix) first state mass massZero
    (fun branch => bindPrefixBranch decode first suffix branch)
  intro branch accepted claim member
  exact sequential_first_prefix_expectedKnown encode decode first suffix state
    branch accepted claim member

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentJointObserverMass
