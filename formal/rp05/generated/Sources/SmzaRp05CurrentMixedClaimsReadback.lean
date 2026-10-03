import SmzaRp05CurrentMixedBranchClaimReadback
import SmzaRp05AdaptiveRetainedAdviceReadback

/-! Reconstruct the full same-branch transcript from its active claims and
the actual fixed complementary table on nonzero mixed-execution support. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentMixedClaimsReadback

open scoped Classical
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaChallengeStageTargets (Role)
open SmzaRoleDomainConditioning
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05AdaptiveRetainedAdviceTransport
open SmzaRp05AdaptiveRetainedAdviceReadback
open SmzaRp05CurrentMixedBranchClaimReadback
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

theorem active_answer_log_mem_mixed_claims
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (call : RawInput × VectorOutput Counter)
    (recorded : call ∈ answerLog decode program branch)
    (live : RoleActive ctx.role blockCap ctx.keyBytes (encode call.1)) :
    (⟨encode call.1, live⟩, call.2) ∈
      mixedBranchClaims ctx blockCap encode decode program branch := by
  induction program with
  | done result => cases recorded
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      simp only [answerLog, List.mem_cons] at recorded
      rcases recorded with same | later
      · subst call
        simp [mixedBranchClaims, live]
      · have retained := ih (decode raw answer) branch later
        by_cases headLive : RoleActive ctx.role blockCap ctx.keyBytes (encode raw)
        · simp only [mixedBranchClaims, dif_pos headLive]
          exact List.mem_cons_of_mem _ retained
        · simpa only [mixedBranchClaims, dif_neg headLive] using retained

/-- The full transcript database is constructed, not independently assumed.
Active cells come from the same branch's active claims. Fixed cells are forced
by nonzero support of that branch in that very fixed-table fiber. -/
theorem nonzero_mixed_branch_active_claims_supply_full_claims
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (initial : ActiveState ctx blockCap)
    (basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput Counter) (VectorOutput Counter) (ActiveMemory ctx))
    (nonzero : mixedRun ctx blockCap fixed encode decode program branch initial basis ≠ 0)
    (active : ActiveDatabase ctx blockCap)
    (claims : ClaimsDatabaseEvent
      (mixedBranchClaims ctx blockCap encode decode program branch) active) :
    ClaimsDatabaseEvent
      (branchClaims (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch))
      (mergeFixedActive ctx blockCap fixed active) := by
  intro claim member
  rw [branch_claims_eq_answer_log] at member
  obtain ⟨call, recorded, rfl⟩ := List.mem_map.mp member
  by_cases live : RoleActive ctx.role blockCap ctx.keyBytes (encode call.1)
  · have retained := claims (⟨encode call.1, live⟩, call.2)
      (active_answer_log_mem_mixed_claims ctx blockCap encode decode
        program branch call recorded live)
    exact (merge_fixed_active_at_active ctx blockCap fixed active
      ⟨encode call.1, live⟩).trans retained
  · have retained := nonzero_mixed_branch_fixed_answers ctx blockCap fixed
      encode decode program branch initial basis nonzero call recorded live
    exact (merge_fixed_active_at_fixed ctx blockCap fixed active
      ⟨encode call.1, live⟩).trans (congrArg some retained)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentMixedClaimsReadback
