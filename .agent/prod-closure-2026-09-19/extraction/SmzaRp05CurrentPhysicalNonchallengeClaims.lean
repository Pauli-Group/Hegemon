import SmzaRp05CurrentKnownClaimsFailureMass
import SmzaRp05CurrentPhysicalBranchClaimReadback
import SmzaRp05AdaptivePhysicalReadBound
import SmzaRp05RoleReadTotality

/-! An answer-branch mass bound for missing claims at literal physical keys
whose exposed bytes are not challenge frames. The per-branch failure estimate
is summed using the actual bounded read schedule and its local standard-
totality invariant; no independently supplied branch-mass bound is used. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPhysicalNonchallengeClaims

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims physicalRun physicalReadStep)
open SmzaRp05PhysicalTerminalRead (physicalReadBranch)
open SmzaRp05AdaptivePhysicalReadBound
  (ReadsAtMost ReadsWithinKeys physicalBranchesFintype)
open SmzaRp05RoleReadTotality
  (StandardOn standard_on_physical_read_branch
    sum_physical_read_branch_norm_squared_of_total_at)
open SmzaRp05PartialReadout (claimFailureProjection)
open SmzaRp05CurrentKnownClaimsFailureMass
  (global_known_claims_failure_mass_le)
open SmzaRp05CurrentPhysicalBranchClaimReadback
  (physical_branch_claim_known_at_standard)
open SmzaChallengeStageTargets (parseStageQuery)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024

variable {Key Counter Work Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype Work] [DecidableEq Work]

/-- The actual terminal answer claims restricted to physical keys whose
representative bytes fail the challenge parser. -/
def branchNonchallengeClaims
    (keyBytes : Key → RawInput)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program) :
    List (Key × VectorOutput Counter) :=
  (branchClaims (branchKeys encode decode program branch)
    (branchAnswers encode decode program branch)).filter
      (fun claim => (parseStageQuery (keyBytes claim.1)).isNone)

private theorem branch_keys_length_le
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (depth : Nat) (program : Program Result)
    (branch : Branches decode program)
    (readBound : ReadsAtMost decode depth program) :
    (branchKeys encode decode program branch).length ≤ depth := by
  induction depth generalizing program with
  | zero =>
      cases program with
      | done result => simp [branchKeys]
      | read raw next => cases readBound
  | succ depth inductionHypothesis =>
      cases program with
      | done result => simp [branchKeys]
      | read raw next =>
          rcases branch with ⟨answer, tail⟩
          have tailBound := inductionHypothesis (next (decode raw answer)) tail
            (readBound answer)
          simp only [branchKeys, List.length_cons]
          omega

private theorem branch_claims_length_eq_keys
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program) :
    (branchClaims (branchKeys encode decode program branch)
      (branchAnswers encode decode program branch)).length =
        (branchKeys encode decode program branch).length := by
  induction program with
  | done result => rfl
  | read raw next inductionHypothesis =>
      rcases branch with ⟨answer, tail⟩
      simp only [branchClaims, branchAnswers, branchKeys, List.length_cons]
      exact congrArg Nat.succ
        (inductionHypothesis (decode raw answer) tail)

private theorem nonchallenge_claim_card_le_depth
    (keyBytes : Key → RawInput)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (depth : Nat) (program : Program Result)
    (branch : Branches decode program)
    (readBound : ReadsAtMost decode depth program) :
    (branchNonchallengeClaims keyBytes encode decode program branch).toFinset.card ≤ depth := by
  calc
    (branchNonchallengeClaims keyBytes encode decode program branch).toFinset.card ≤
        (branchNonchallengeClaims keyBytes encode decode program branch).length :=
      List.toFinset_card_le _
    _ ≤ (branchClaims (branchKeys encode decode program branch)
          (branchAnswers encode decode program branch)).length :=
      List.length_filter_le _ _
    _ = (branchKeys encode decode program branch).length :=
      branch_claims_length_eq_keys encode decode program branch
    _ ≤ depth := branch_keys_length_le encode decode depth program branch readBound

/-- Exhaustive physical branch mass equals the original input mass using only
totality at the finite scheduled keys. `ReadsWithinKeys` ensures every
answer-dependent continuation stays in that same list. -/
theorem physical_branch_mass_eq_initial_of_reads_within
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (keys : List Key)
    (within : ReadsWithinKeys encode decode keys program)
    (total : StandardOn keys state) :
    letI := physicalBranchesFintype decode program
    (∑ branch : Branches decode program,
      normSquared (physicalRun encode decode program branch state)) = normSquared state := by
  classical
  induction program generalizing state keys with
  | done result =>
      letI := physicalBranchesFintype decode (Program.done result)
      simp [Branches, physicalRun]
  | read raw next inductionHypothesis =>
      letI (answer : VectorOutput Counter) :
          Fintype (Branches decode (next (decode raw answer))) :=
        physicalBranchesFintype decode (next (decode raw answer))
      letI := physicalBranchesFintype decode (Program.read raw next)
      change
        (∑ branch : (answer : VectorOutput Counter) ×
            Branches decode (next (decode raw answer)),
          normSquared (physicalRun encode decode
            (Program.read raw next) branch state)) = normSquared state
      rw [Fintype.sum_sigma]
      calc
        (∑ answer : VectorOutput Counter,
            ∑ branch : Branches decode (next (decode raw answer)),
              normSquared (physicalRun encode decode (next (decode raw answer))
                branch (physicalReadBranch (encode raw) answer state))) =
          ∑ answer : VectorOutput Counter,
            normSquared (physicalReadBranch (encode raw) answer state) := by
          apply Finset.sum_congr rfl
          intro answer _
          have tailTotal := standard_on_physical_read_branch keys
            (encode raw) answer state total
          simpa only [physicalRun, physicalReadStep, physicalReadBranch] using
            inductionHypothesis (decode raw answer)
              (physicalReadBranch (encode raw) answer state)
              keys
              (within.2 answer) tailTotal
        _ = normSquared state :=
          sum_physical_read_branch_norm_squared_of_total_at
            (encode raw) state (total (encode raw) within.1)

/-- The summed missing-claim mass on any selected subset of the actual
physical answer branches is charged once against the incoming norm. The
selected predicate can be the caller's actual accepted-branch selector. -/
theorem selected_nonchallenge_claim_failure_mass_le
    (keyBytes : Key → RawInput)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (keys : List Key)
    (within : ReadsWithinKeys encode decode keys program)
    (total : StandardOn keys state)
    (depth : Nat) (readBound : ReadsAtMost decode depth program)
    (selected : Branches decode program → Prop) :
    letI := physicalBranchesFintype decode program
    (∑ branch : Branches decode program,
      if selected branch then
        normSquared (claimFailureProjection
          (branchNonchallengeClaims keyBytes encode decode program branch)
          (physicalRun encode decode program branch state))
      else 0) ≤
      ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter) *
        normSquared state := by
  classical
  letI := physicalBranchesFintype decode program
  let loss : ℝ :=
    ((2 * depth : Nat) : ℝ) / Fintype.card (VectorOutput Counter)
  have lossNonnegative : 0 ≤ loss := by
    dsimp [loss]
    positivity
  have branchMass := physical_branch_mass_eq_initial_of_reads_within
    encode decode program state keys within total
  calc
    (∑ branch : Branches decode program,
        if selected branch then
          normSquared (claimFailureProjection
            (branchNonchallengeClaims keyBytes encode decode program branch)
            (physicalRun encode decode program branch state))
        else 0) ≤
      ∑ branch : Branches decode program,
        loss * normSquared (physicalRun encode decode program branch state) := by
      apply Finset.sum_le_sum
      intro branch _
      by_cases chosen : selected branch
      · have claimsKnown : ∀ claim ∈
            branchNonchallengeClaims keyBytes encode decode program branch,
            SmzaRp05PartialReadout.KnownAt claim.1 claim.2
              (globalDecompress (physicalRun encode decode program branch state)) := by
          intro claim member
          have original := (List.mem_filter.mp member).1
          simpa [SmzaRp05PhysicalAcceptedReplayLite.KnownAt,
            SmzaRp05PartialReadout.KnownAt] using
            physical_branch_claim_known_at_standard
              encode decode program branch state claim original
        have failureBound := global_known_claims_failure_mass_le
          (branchNonchallengeClaims keyBytes encode decode program branch)
          (physicalRun encode decode program branch state) claimsKnown
        have countBound := nonchallenge_claim_card_le_depth
          keyBytes encode decode depth program branch readBound
        have cardPositive :
            0 < (Fintype.card (VectorOutput Counter) : ℝ) := by
          exact_mod_cast Fintype.card_pos
        have coefficientBound :
            ((2 * (branchNonchallengeClaims keyBytes encode decode program branch).toFinset.card : Nat) : ℝ) /
                Fintype.card (VectorOutput Counter) ≤ loss := by
          dsimp [loss]
          apply div_le_div_of_nonneg_right
          · exact_mod_cast Nat.mul_le_mul_left 2 countBound
          · exact le_of_lt cardPositive
        have stateMassNonnegative :
            0 ≤ normSquared
              (physicalRun encode decode program branch state) := by
          unfold normSquared
          exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
        have selectedBound :
            normSquared (claimFailureProjection
              (branchNonchallengeClaims keyBytes encode decode program branch)
              (physicalRun encode decode program branch state)) ≤
            loss * normSquared (physicalRun encode decode program branch state) :=
          failureBound.trans (mul_le_mul_of_nonneg_right coefficientBound
            stateMassNonnegative)
        simpa [chosen, loss] using selectedBound
      · simp only [if_neg chosen]
        exact mul_nonneg lossNonnegative (by
          unfold normSquared
          exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _)
    _ = loss * normSquared state := by
      rw [← Finset.mul_sum, branchMass]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentPhysicalNonchallengeClaims
