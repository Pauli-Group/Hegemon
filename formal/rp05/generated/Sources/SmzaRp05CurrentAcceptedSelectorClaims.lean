import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05CurrentMixedBranchClaimReadback

/-! # Active branch claims are claims of the same literal execution

The active mixed transcript is a sublist of the answer claims of its exact
physical branch.  This small list fact lets a same-branch full-claims witness
establish the claim-consistency clause of the X-view selector.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSelectorClaims

open scoped Classical
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaChallengeStageTargets (Role)
open SmzaRoleDomainConditioning
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05CurrentMixedBranchClaimReadback
open SmzaRp05CurrentSelectedChallengeClaims
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

private theorem mixed_claim_member_raw_branch_claim
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (claim : ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter)
    (member : claim ∈ mixedBranchClaims ctx blockCap encode decode program branch) :
    (claim.1.val, claim.2) ∈
      branchClaims (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch) := by
  induction program generalizing claim with
  | done result => simp [mixedBranchClaims] at member
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      by_cases live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw)
      · simp only [mixedBranchClaims, dif_pos live, List.mem_cons] at member
        rcases member with head | tail
        · cases head
          simp [branchKeys, branchAnswers, branchClaims]
        · change (claim.1.val, claim.2) ∈
            (encode raw, answer) :: branchClaims
              (branchKeys encode decode (next (decode raw answer)) branch)
              (branchAnswers encode decode (next (decode raw answer)) branch)
          exact List.mem_cons_of_mem _
            (ih (decode raw answer) branch _ tail)
      · simp only [mixedBranchClaims, dif_neg live] at member
        change (claim.1.val, claim.2) ∈
          (encode raw, answer) :: branchClaims
            (branchKeys encode decode (next (decode raw answer)) branch)
            (branchAnswers encode decode (next (decode raw answer)) branch)
        exact List.mem_cons_of_mem _
          (ih (decode raw answer) branch _ member)

/-- Every selected nonchallenge claim is an exact raw key/answer claim in
the same branch transcript. -/
theorem unrecognized_active_claim_mem_branch_claims
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (claim : ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter)
    (member : claim ∈ unrecognizedActiveBranchClaims ctx blockCap encode
      decode program branch) :
    (claim.1.val, claim.2) ∈
      branchClaims (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch) := by
  exact mixed_claim_member_raw_branch_claim ctx blockCap encode decode program
    branch claim (List.mem_filter.mp member).1

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSelectorClaims
